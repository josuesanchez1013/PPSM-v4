<#
    ppsm-collect.ps1 — PPSM data collection for Windows

    Runs the whole Windows side of PPSM collection and writes everything into
    one results folder that PPSM Builder reads directly. Drag the folder onto
    the tool when it finishes.

    No modules required. Works on Windows PowerShell 3.0-5.1 and PowerShell 7.
    Hosts without Get-NetTCPConnection (older builds, locked-down images) are
    read with netstat -ano instead; the shell version and method used on each
    host is recorded in the output. RSAT (ActiveDirectory) is used if present
    and skipped if it is not. Nothing is uploaded and nothing leaves the machine.

    USAGE
      .\ppsm-collect.ps1
      .\ppsm-collect.ps1 -Computers dc01,file01,sql01
      .\ppsm-collect.ps1 -ComputerListFile .\hosts.txt -ThrottleLimit 64 -ProbeTimeout 3
      .\ppsm-collect.ps1 -ComputerListFile .\hosts.txt -OutputPath D:\ppsm
      .\ppsm-collect.ps1 -SkipAD -SkipDNS
      .\ppsm-collect.ps1 -NetworkDevices fw01:asa,core01:ios -NetworkUser admin
      .\ppsm-collect.ps1 -SelfTest

    SELF-TEST
      -SelfTest collects the local machine twice — once the normal way and
      once forced through the netstat -ano fallback — and compares the two
      listener lists. Run it once on a PowerShell 5.1 host (ideally one
      where Get-NetTCPConnection is "not recognized") to confirm the
      fallback gives the same ports before trusting a fleet run. It
      writes nothing outside .\ppsm-selftest\.

    NETWORK DEVICES (optional)
      -NetworkDevices takes name[:type] entries. Type asa (default) pulls
      "show conn all" plus the access-list and object-group config; type
      ios pulls "show flow monitor <FlowMonitor> cache format csv". The
      Windows OpenSSH client (ssh.exe, built in since Windows 10 1809 /
      Server 2019) is used; you will be prompted for the password unless a
      key is set up. For a whole fleet, ppsm.yml (Ansible) does the same.

    Remote collection uses WinRM (Invoke-Command). If WinRM is not enabled,
    the script still collects the local machine and tells you which hosts it
    could not reach.

    REACH AND SPEED
      Hosts are collected IN PARALLEL (-ThrottleLimit, default 32 at once),
      not one after another. Before WinRM is tried, every host's WinRM port
      is probed at the same time and any host that does not answer within
      -ProbeTimeout seconds (default 5) is skipped and listed as unreachable;
      nothing waits on it. A host that answers the port but then stalls is
      given -ConnectTimeout seconds to open the session and -HostTimeout
      seconds to finish, then it is skipped too. The run never stops on one
      host.

    POWERSHELL VERSIONS
      Runs on Windows PowerShell 3.0-5.1 and PowerShell 7 (the control
      machine and the targets may differ). $PSVersionTable is checked on
      every host and the version-specific choices are made there:
        - ports: Get-NetTCPConnection / Get-NetUDPEndpoint when the NetTCPIP
          module exists, otherwise netstat -ano parsed
        - OS name: Get-CimInstance (3.0+), Get-WmiObject on anything older
        - CSV encoding: 5.1 writes UTF-8 with a BOM on its own; 7 is told to
          (-Encoding utf8BOM) so Excel opens both the same way
      The shell version and method used are written per host.
#>

#Requires -Version 3.0
[CmdletBinding()]
param(
    [string[]] $Computers,
    [string]   $ComputerListFile,
    [string]   $OutputPath = ".\ppsm-results",
    [switch]   $SkipAD,
    [switch]   $SkipDNS,
    [switch]   $IncludeEstablished = $true,
    [System.Management.Automation.PSCredential] $Credential,
    [string[]] $NetworkDevices,
    [string]   $NetworkUser,
    [string]   $FlowMonitor = 'FLOW-IN-IQCORE',
    [switch]   $SelfTest,
    # ---- reach and parallelism
    [int]      $ThrottleLimit  = 32,     # hosts collected at the same time
    [int]      $ProbeTimeout   = 5,      # seconds to wait for the WinRM port before a host is skipped
    [int]      $ConnectTimeout = 20,     # seconds for the WinRM session to open
    [int]      $HostTimeout    = 180,    # seconds a host may take to answer before it is given up on
    [int]      $WinRmPort      = 5985,   # 5986 with -UseSSL
    [switch]   $UseSSL,
    [switch]   $SkipProbe                # go straight to WinRM without the port check
)

$ErrorActionPreference = 'Continue'
$started = Get-Date

# ------------------------------------------------------------------ shell version
# The control machine's PowerShell decides the few cmdlet differences that
# matter here; each target host makes its own decision inside $collector.
$PSMajor   = $PSVersionTable.PSVersion.Major
$PSEditionName = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
# Export-Csv/Out-File encoding: Windows PowerShell 5.1 "UTF8" = UTF-8 with BOM;
# PowerShell 7 "UTF8" = no BOM and has utf8BOM for the 5.1 behaviour.
$CsvEncoding = if ($PSMajor -ge 6) { 'utf8BOM' } else { 'UTF8' }
function Get-OsCaption {
    if ($PSMajor -ge 3) { try { return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { } }
    try { return (Get-WmiObject Win32_OperatingSystem -ErrorAction Stop).Caption } catch { return '' }
}

# ------------------------------------------------------------------ self-test
if ($SelfTest) {
    $OutputPath = '.\ppsm-selftest'
    $Computers  = @($env:COMPUTERNAME)
}

# ------------------------------------------------------------------ folders
$dirs = @{
    root      = $OutputPath
    hosts     = Join-Path $OutputPath 'hosts'
    inventory = Join-Path $OutputPath 'inventory'
    network   = Join-Path $OutputPath 'network'
}
foreach ($d in $dirs.Values) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

function Write-Step($n, $msg) { Write-Host ("[{0}] {1}" -f $n, $msg) -ForegroundColor Cyan }
function Write-Ok($msg)       { Write-Host ("    ok   " + $msg) -ForegroundColor Green }
function Write-Skip($msg)     { Write-Host ("    skip " + $msg) -ForegroundColor DarkYellow }
function Write-Bad($msg)      { Write-Host ("    FAIL " + $msg) -ForegroundColor Red }

$manifest = New-Object System.Collections.ArrayList

# ------------------------------------------------------------------ target list
if ($ComputerListFile -and (Test-Path $ComputerListFile)) {
    $Computers = Get-Content $ComputerListFile |
        Where-Object { $_.Trim() -and -not $_.StartsWith('#') } |
        ForEach-Object { $_.Trim() }
}
# "a,b,c" arrives as one string when the script is started with -File or from
# cmd.exe; split it so both spellings work
$Computers      = @($Computers      | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$NetworkDevices = @($NetworkDevices | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $Computers -or $Computers.Count -eq 0) { $Computers = @($env:COMPUTERNAME) }

Write-Host ""
Write-Host "PPSM collection" -ForegroundColor White
Write-Host ("  shell   : PowerShell {0} ({1}) on {2} — CSV encoding {3}" -f $PSVersionTable.PSVersion, $PSEditionName, $(Get-OsCaption), $CsvEncoding)
Write-Host ("  reach   : probe TCP {0} for {1}s, then WinRM, {2} hosts at a time, {3}s to connect, {4}s per host" -f $WinRmPort, $ProbeTimeout, $ThrottleLimit, $ConnectTimeout, $HostTimeout)
if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
    Write-Host "            Get-NetTCPConnection not available here — local ports will come from netstat -ano" -ForegroundColor DarkYellow
}
Write-Host ("  targets : {0}" -f ($Computers -join ', '))
Write-Host ("  output  : {0}" -f (Resolve-Path $OutputPath -ErrorAction SilentlyContinue))
Write-Host ""

# ------------------------------------------------------------------ 1: connections
# One scriptblock covers listeners and active connections, with the owning
# process, which is what makes a port defensible as a real listening service.
$collector = {
    param([bool]$ForceNetstat = $false)
    $rows  = New-Object System.Collections.ArrayList
    $procs = @{}
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }

    # ---- which PowerShell is this, and can it list sockets natively?
    # Get-NetTCPConnection / Get-NetUDPEndpoint come from the NetTCPIP module
    # (Windows 8 / Server 2012 and later). PowerShell 5.1 on an older build,
    # a locked-down image, or PowerShell 2.0 do not have them, so the script
    # falls back to parsing netstat -ano, which every Windows has.
    $psVer   = $PSVersionTable.PSVersion
    $psText  = if ($psVer) { $psVer.ToString() } else { '2.0' }
    $edition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
    $hasNetCmd = [bool](Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    if ($ForceNetstat) { $hasNetCmd = $false }
    $method  = 'netstat'

    if ($hasNetCmd) {
        try {
            $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
            $method = 'Get-NetTCPConnection'
            foreach ($c in $tcp) {
                if ($c.State -ne 'Listen' -and $c.State -ne 'Established') { continue }
                $isListen = ($c.State -eq 'Listen')
                $null = $rows.Add([pscustomobject]@{
                    Host              = $env:COMPUTERNAME
                    Protocol          = 'TCP'
                    State             = [string]$c.State
                    'Source IP'       = if ($isListen) { '' } else { $c.LocalAddress }
                    'Source Port'     = if ($isListen) { '' } else { $c.LocalPort }
                    'Destination IP'  = if ($isListen) { $c.LocalAddress } else { $c.RemoteAddress }
                    'Destination Port'= if ($isListen) { $c.LocalPort }    else { $c.RemotePort }
                    Direction         = if ($isListen) { 'Inbound' } else { 'Outbound' }
                    'Data Service / Application' = $procs[[int]$c.OwningProcess]
                    Process           = $procs[[int]$c.OwningProcess]
                    PID               = $c.OwningProcess
                })
            }
            try {
                foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
                    $null = $rows.Add([pscustomobject]@{
                        Host              = $env:COMPUTERNAME
                        Protocol          = 'UDP'
                        State             = 'Listen'
                        'Source IP'       = ''
                        'Source Port'     = ''
                        'Destination IP'  = $u.LocalAddress
                        'Destination Port'= $u.LocalPort
                        Direction         = 'Inbound'
                        'Data Service / Application' = $procs[[int]$u.OwningProcess]
                        Process           = $procs[[int]$u.OwningProcess]
                        PID               = $u.OwningProcess
                    })
                }
            } catch { }
        } catch {
            # the cmdlet exists but refused (WMI/CIM broken, no rights) — fall back
            $rows.Clear()
            $method = 'netstat'
        }
    }

    $netstatText = (& netstat -ano 2>$null | Out-String)

    if ($method -eq 'netstat') {
        # netstat -ano lines:
        #   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       928
        #   TCP    [::1]:49669            [::1]:49670            ESTABLISHED     4
        #   UDP    0.0.0.0:123            *:*                                    1264
        $splitEp = {
            param($ep)
            $i = $ep.LastIndexOf(':')
            if ($i -lt 0) { return @($ep, '') }
            $addr = $ep.Substring(0, $i).Trim('[', ']')
            $port = $ep.Substring($i + 1)
            return @($addr, $port)
        }
        foreach ($line in ($netstatText -split "`r?`n")) {
            $m = [regex]::Match($line, '^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(?:([A-Z_]+)\s+)?(\d+)\s*$')
            if (-not $m.Success) { continue }
            $proto = $m.Groups[1].Value
            $loc   = & $splitEp $m.Groups[2].Value
            $rem   = & $splitEp $m.Groups[3].Value
            $state = $m.Groups[4].Value
            $procId= [int]$m.Groups[5].Value
            if ($proto -eq 'TCP') {
                if ($state -eq 'LISTENING')        { $st = 'Listen' }
                elseif ($state -eq 'ESTABLISHED')  { $st = 'Established' }
                else { continue }
            } else { $st = 'Listen' }
            $isListen = ($st -eq 'Listen')
            $null = $rows.Add([pscustomobject]@{
                Host              = $env:COMPUTERNAME
                Protocol          = $proto
                State             = $st
                'Source IP'       = if ($isListen) { '' } else { $loc[0] }
                'Source Port'     = if ($isListen) { '' } else { $loc[1] }
                'Destination IP'  = if ($isListen) { $loc[0] } else { $rem[0] }
                'Destination Port'= if ($isListen) { $loc[1] } else { $rem[1] }
                Direction         = if ($isListen) { 'Inbound' } else { 'Outbound' }
                'Data Service / Application' = $procs[$procId]
                Process           = $procs[$procId]
                PID               = $procId
            })
        }
    }


    # ---- face each established connection toward the service.
    # Windows reports an inbound client of a local listener as local:443 ->
    # remote:49700. That is a client of OUR service, so it is written as
    # Inbound with the listener as the destination.
    $listening = @{}
    foreach ($r in $rows) { if ($r.State -eq 'Listen') { $listening[$r.Protocol + '/' + $r.'Destination Port'] = $true } }
    foreach ($r in $rows) {
        if ($r.State -eq 'Established' -and $listening[$r.Protocol + '/' + $r.'Source Port']) {
            $sip = $r.'Source IP'; $spt = $r.'Source Port'
            $r.'Source IP' = $r.'Destination IP'; $r.'Source Port' = $r.'Destination Port'
            $r.'Destination IP' = $sip; $r.'Destination Port' = $spt
            $r.Direction = 'Inbound'
        }
    }

    $osCaption = ''
    if ($psVer -and $psVer.Major -ge 3) {
        try { $osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
    }
    if (-not $osCaption) { try { $osCaption = (Get-WmiObject Win32_OperatingSystem -ErrorAction Stop).Caption } catch { } }

    [pscustomobject]@{
        Rows      = $rows
        Netstat   = $netstatText
        Name      = $env:COMPUTERNAME
        PSVersion = $psText
        PSEdition = $edition
        Method    = $method
        OS        = $osCaption
    }
}

if ($SelfTest) {
    Write-Step 'T' "Self-test: normal collection versus the netstat fallback on this machine"
    $ver = $PSVersionTable.PSVersion
    Write-Host ("    shell      : PowerShell {0} ({1})" -f $ver, $(if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }))
    Write-Host ("    OS         : {0}" -f (Get-OsCaption))
    $hasCmd = [bool](Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)
    Write-Host ("    cmdlet     : Get-NetTCPConnection {0}" -f $(if ($hasCmd) { 'available' } else { 'NOT available — fallback is what a fleet run would use here' }))
    $a = & $collector $false
    $b = & $collector $true
    Write-Host ("    normal     : {0} rows via {1}" -f $a.Rows.Count, $a.Method)
    Write-Host ("    fallback   : {0} rows via {1}" -f $b.Rows.Count, $b.Method)
    $key = { param($r) "{0}/{1}" -f $r.Protocol, $r.'Destination Port' }
    $la = @{}; foreach ($r in $a.Rows) { if ($r.State -eq 'Listen') { $la[(& $key $r)] = $r } }
    $lb = @{}; foreach ($r in $b.Rows) { if ($r.State -eq 'Listen') { $lb[(& $key $r)] = $r } }
    $onlyA = @($la.Keys | Where-Object { -not $lb.ContainsKey($_) } | Sort-Object)
    $onlyB = @($lb.Keys | Where-Object { -not $la.ContainsKey($_) } | Sort-Object)
    $noProc = @($b.Rows | Where-Object { $_.State -eq 'Listen' -and -not $_.Process }).Count
    Write-Host ("    listeners  : {0} normal, {1} fallback, {2} in both" -f $la.Count, $lb.Count, (@($la.Keys | Where-Object { $lb.ContainsKey($_) })).Count)
    if ($a.Method -eq $b.Method) {
        Write-Skip "both runs used netstat (the cmdlet is absent here), so this checks the parser, not the two methods against each other"
    }
    if ($onlyA.Count) { Write-Bad  ("listeners only in the normal run  : {0}" -f ($onlyA -join ', ')) }
    if ($onlyB.Count) { Write-Bad  ("listeners only in the fallback run: {0}" -f ($onlyB -join ', ')) }
    if ($noProc)      { Write-Skip ("{0} fallback listener(s) have no process name (PID not in Get-Process — usually System/PID 4 or a protected process)" -f $noProc) }
    # a listener bound while the two snapshots were taken is normal churn;
    # anything beyond a handful means the parser missed something
    $verdict = if (($onlyA.Count + $onlyB.Count) -le 3) { 'PASS' } else { 'CHECK' }
    foreach ($pair in @(@('normal', $a), @('fallback', $b))) {
        $f = Join-Path $dirs.hosts ("{0}-{1}-connections.csv" -f $env:COMPUTERNAME, $pair[0])
        $pair[1].Rows | Select-Object 'Source IP','Source Port','Destination IP','Destination Port',Protocol,'Data Service / Application',Direction,Host,State,Process,PID |
            Export-Csv -NoTypeInformation -Encoding $CsvEncoding -Path $f
    }
    if ($b.Netstat) { $b.Netstat | Out-File -Encoding $CsvEncoding (Join-Path $dirs.hosts ("{0}-netstat.txt" -f $env:COMPUTERNAME)) }
    $summary = @"
PPSM collector self-test  $($started.ToString('yyyy-MM-dd HH:mm:ss'))
Shell     : PowerShell $ver
Cmdlet    : Get-NetTCPConnection $(if ($hasCmd) { 'available' } else { 'not available' })
Normal    : $($a.Rows.Count) rows via $($a.Method)
Fallback  : $($b.Rows.Count) rows via $($b.Method)
Listeners : $($la.Count) normal / $($lb.Count) fallback
Only normal   : $($onlyA -join ', ')
Only fallback : $($onlyB -join ', ')
Verdict   : $verdict
Both CSVs are in hosts\ — drop them on the builder to see that each reads the same way.
"@
    $summary | Out-File -Encoding $CsvEncoding (Join-Path $dirs.root 'SELFTEST.txt')
    Write-Host ""
    if ($verdict -eq 'PASS') { Write-Ok ("self-test PASS — results in {0}" -f (Resolve-Path $dirs.root)) }
    else { Write-Bad ("self-test needs a look — see {0}\SELFTEST.txt" -f (Resolve-Path $dirs.root)) }
    return
}

Write-Step 1 ("Collecting listening ports and active connections — {0} host(s), up to {1} at once" -f $Computers.Count, $ThrottleLimit)
$reached = 0; $failed = @()
$results = @{}   # computer -> collector result

$isLocalName = { param($c) ($c -eq $env:COMPUTERNAME -or $c -eq 'localhost' -or $c -eq '.' -or $c -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") }
$localTargets  = @($Computers | Where-Object { & $isLocalName $_ })
$remoteTargets = @($Computers | Where-Object { -not (& $isLocalName $_) })

# ---- 1a: this machine, directly
foreach ($c in $localTargets) {
    try { $results[$env:COMPUTERNAME] = & $collector $false }
    catch { Write-Bad ("{0} — {1}" -f $c, $_.Exception.Message); $failed += $c }
}

# ---- 1b: probe every remote host's WinRM port AT THE SAME TIME
# A host that is off, firewalled or not on the network is dropped here in
# at most $ProbeTimeout seconds instead of tying up a WinRM attempt.
if ($UseSSL -and $WinRmPort -eq 5985) { $WinRmPort = 5986 }
if ($remoteTargets.Count -and -not $SkipProbe) {
    $probes = @{}
    foreach ($c in $remoteTargets) {
        $tc = New-Object System.Net.Sockets.TcpClient
        try   { $probes[$c] = @{ client = $tc; task = $tc.ConnectAsync($c, $WinRmPort) } }
        catch { $probes[$c] = @{ client = $tc; task = $null; err = $_.Exception.Message } }
    }
    $deadline = (Get-Date).AddSeconds($ProbeTimeout)
    do {
        $open = @($probes.Values | Where-Object { $_.task -and -not $_.task.IsCompleted })
        if ($open.Count) { Start-Sleep -Milliseconds 150 }
    } while ($open.Count -and (Get-Date) -lt $deadline)
    $alive = @()
    foreach ($c in $remoteTargets) {
        $pr = $probes[$c]
        $ok = $pr.task -and $pr.task.IsCompleted -and -not $pr.task.IsFaulted -and $pr.client.Connected
        if ($ok) { $alive += $c }
        else {
            $why = if ($pr.err) { $pr.err }
                   elseif ($pr.task -and $pr.task.IsFaulted) { 'refused or name not resolved' }
                   else { "no answer on TCP $WinRmPort within ${ProbeTimeout}s" }
            Write-Bad ("{0} — {1} (skipped)" -f $c, $why)
            $failed += $c
        }
        try { $pr.client.Close() } catch { }
    }
    $remoteTargets = $alive
}

# ---- 1c: collect the reachable hosts in parallel
# One Invoke-Command with the whole list fans out $ThrottleLimit sessions at
# a time; each host's failure is an error record, not a stop. Timeouts bound
# a host that answers the port and then stalls.
if ($remoteTargets.Count) {
    $so = New-PSSessionOption -OpenTimeout ($ConnectTimeout * 1000) -OperationTimeout ($HostTimeout * 1000) -CancelTimeout 10000
    $p  = @{ ComputerName = $remoteTargets; ScriptBlock = $collector; ArgumentList = @($false)
             ThrottleLimit = $ThrottleLimit; SessionOption = $so
             ErrorAction = 'SilentlyContinue'; ErrorVariable = 'rcErr' }
    if ($Credential) { $p.Credential = $Credential }
    if ($UseSSL)     { $p.UseSSL = $true; $p.Port = $WinRmPort } elseif ($WinRmPort -ne 5985) { $p.Port = $WinRmPort }
    $rcErr = @()
    $out = @(Invoke-Command @p)
    foreach ($res in $out) {
        if ($null -eq $res) { continue }
        $n = if ($res.PSComputerName) { $res.PSComputerName } elseif ($res.Name) { $res.Name } else { 'unknown' }
        $results[$n] = $res
    }
    foreach ($e in $rcErr) {
        $c = if ($e.OriginInfo -and $e.OriginInfo.PSComputerName) { $e.OriginInfo.PSComputerName }
             elseif ($e.TargetObject -is [string]) { $e.TargetObject } else { '' }
        $msg = $(if ($e.Exception -and $e.Exception.Message) { $e.Exception.Message } else { "$e" }) -replace '\s+', ' '
        if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + '…' }
        if (-not $msg) { $msg = 'WinRM error (no detail given)' }
        if ($c) { Write-Bad ("{0} — {1}" -f $c, $msg); $failed += $c } else { Write-Bad ("WinRM — {0}" -f $msg) }
    }
    # a host that produced neither a result nor an error record still failed
    foreach ($c in $remoteTargets) {
        $got = $results.Keys | Where-Object { $_ -eq $c -or $_ -like "$c.*" -or $c -like "$_.*" }
        if (-not $got -and $failed -notcontains $c) { Write-Bad ("{0} — no result returned" -f $c); $failed += $c }
    }
}

# ---- 1d: write what came back
foreach ($n in ($results.Keys | Sort-Object)) {
    $res  = $results[$n]
    $name = if ($res.Name) { $res.Name } else { $n }
    try {
        $csv  = Join-Path $dirs.hosts ("{0}-connections.csv" -f $name)
        $txt  = Join-Path $dirs.hosts ("{0}-netstat.txt"     -f $name)

        $keep = @($res.Rows)
        if (-not $IncludeEstablished) { $keep = @($keep | Where-Object { $_.State -eq 'Listen' }) }
        $keep | Select-Object 'Source IP','Source Port','Destination IP','Destination Port',
                              Protocol,'Data Service / Application',Direction,Host,State,Process,PID,
                              @{n='Collector';e={ "PowerShell $($res.PSVersion) / $($res.Method)" }} |
                Export-Csv -NoTypeInformation -Encoding $CsvEncoding -Path $csv

        if ($res.Netstat) { $res.Netstat | Out-File -Encoding $CsvEncoding $txt }

        $how = "PowerShell {0} ({1}) via {2}" -f $res.PSVersion, $res.PSEdition, $res.Method
        $null = $manifest.Add(("hosts/{0}-connections.csv  {1} rows  [{2}]" -f $name, $keep.Count, $how))
        Write-Ok ("{0} — {1} ports/connections  [{2}]" -f $name, $keep.Count, $how)
        if ($res.Method -eq 'netstat') {
            Write-Skip ("{0}: Get-NetTCPConnection is not available on this host (PowerShell {1}); ports were read from netstat -ano instead" -f $name, $res.PSVersion)
        }
        $reached++
    }
    catch {
        Write-Bad ("{0} — could not write results: {1}" -f $name, $_.Exception.Message)
        $failed += $name
    }
}
Write-Host ("    {0} of {1} host(s) collected in {2:n0}s" -f $reached, $Computers.Count, ((Get-Date) - $started).TotalSeconds)

# ------------------------------------------------------------------ 2: AD names
Write-Step 2 "Exporting computer names from Active Directory"
if ($SkipAD) {
    Write-Skip "-SkipAD was set"
} else {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $out = Join-Path $dirs.inventory 'ad-computers.csv'
        Get-ADComputer -Filter * -Properties DNSHostName,IPv4Address,OperatingSystem,Description,ManagedBy -ErrorAction Stop |
            Where-Object { $_.IPv4Address } |
            Select-Object Name, DNSHostName, IPv4Address, OperatingSystem,
                          @{n='Owner';e={$_.ManagedBy}}, Description |
            Export-Csv -NoTypeInformation -Encoding $CsvEncoding -Path $out
        $n = (Import-Csv $out | Measure-Object).Count
        $null = $manifest.Add(("inventory/ad-computers.csv  {0} systems" -f $n))
        Write-Ok ("{0} systems named from AD" -f $n)
    } catch {
        Write-Skip "ActiveDirectory module not available — run on a machine with RSAT, or supply an inventory CSV yourself"
    }
}

# ------------------------------------------------------------------ 2b: DNS zones
# Forward and reverse zones are the best name source there is: a reverse zone
# is the authoritative answer to "what is this address called". RecordData
# does not survive Export-Csv on its own, so it is expanded here.
Write-Step "2b" "Exporting DNS zones (forward and reverse)"
if ($SkipDNS) {
    Write-Skip "-SkipDNS was set"
} else {
    try {
        Import-Module DnsServer -ErrorAction Stop
        $dnsOut = Join-Path $dirs.inventory 'dns-records.csv'
        $zones  = Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }
        $recs = foreach ($z in $zones) {
            Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction SilentlyContinue |
              Where-Object { $_.RecordType -in 'A','PTR','CNAME' } |
              Select-Object HostName, RecordType,
                @{n='ZoneName';      e={ $z.ZoneName }},
                @{n='IPv4Address';   e={ $_.RecordData.IPv4Address.IPAddressToString }},
                @{n='PtrDomainName'; e={ $_.RecordData.PtrDomainName }},
                @{n='HostNameAlias'; e={ $_.RecordData.HostNameAlias }}
        }
        $recs | Export-Csv -NoTypeInformation -Encoding $CsvEncoding -Path $dnsOut
        $null = $manifest.Add(("inventory/dns-records.csv  {0} records from {1} zones" -f @($recs).Count, @($zones).Count))
        Write-Ok ("{0} DNS records from {1} zones" -f @($recs).Count, @($zones).Count)
    } catch {
        Write-Skip "DnsServer module not available here — run on a DNS server, or export the zones by hand (see the SOP)"
    }
}

# ------------------------------------------------------------------ 3: hosts file
Write-Step 3 "Copying the local hosts file"
$hf = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hf) {
    Copy-Item $hf (Join-Path $dirs.inventory 'hosts-file.txt') -Force
    $null = $manifest.Add('inventory/hosts-file.txt')
    Write-Ok "hosts file copied"
} else { Write-Skip "no hosts file found" }

# ------------------------------------------------------------------ 4: firewall log
Write-Step 4 "Copying the Windows Firewall log"
$fw = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
if (Test-Path $fw) {
    try {
        Copy-Item $fw (Join-Path $dirs.hosts 'pfirewall.log') -Force -ErrorAction Stop
        $null = $manifest.Add('hosts/pfirewall.log')
        Write-Ok "firewall log copied"
    } catch { Write-Skip "firewall log is locked — copy it manually if you want it" }
} else {
    Write-Skip "firewall logging is not enabled (optional)"
}

# ------------------------------------------------------------------ 5: network devices
# Firewall connection table and switch NetFlow cache over the OpenSSH client.
# ASA and IOS do not run a command handed on the ssh command line, so the
# commands are fed on stdin with a forced tty, paging off first.
$netDone = @()
Write-Step 5 "Firewall connection table and switch NetFlow (optional)"
if (-not $NetworkDevices -or $NetworkDevices.Count -eq 0) {
    Write-Skip "no -NetworkDevices given; see READ-ME.txt for what to collect by hand, or run ppsm.yml"
} else {
    $sshExe = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if (-not $sshExe) {
        Write-Bad "ssh.exe (Windows OpenSSH client) is not installed — Settings > Apps > Optional features > OpenSSH Client, or collect by hand"
    } else {
        foreach ($spec in $NetworkDevices) {
            $parts = $spec -split ':'
            $dev = $parts[0].Trim(); $type = if ($parts.Count -gt 1 -and $parts[1]) { $parts[1].Trim().ToLower() } else { 'asa' }
            $target = if ($NetworkUser) { "$NetworkUser@$dev" } else { $dev }
            if ($type -eq 'ios' -or $type -eq 'switch' -or $type -eq 'nxos') {
                $jobs = @(@{ file = "$dev-netflow.csv"; cmds = @("terminal length 0", "show flow monitor $FlowMonitor cache format csv", "exit") })
            } else {
                $jobs = @(
                    @{ file = "$dev-showconn.txt"; cmds = @("terminal pager 0", "show conn all", "exit") },
                    @{ file = "$dev-acl.txt";      cmds = @("terminal pager 0", "show running-config access-list", "show running-config object-group", "exit") }
                )
            }
            foreach ($j in $jobs) {
                $outFile = Join-Path $dirs.network $j.file
                try {
                    $feed = ($j.cmds -join "`n") + "`n"
                    $raw = $feed | & $sshExe.Source -tt -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 $target 2>&1 | Out-String
                    # strip terminal control sequences and carriage returns
                    $clean = [regex]::Replace($raw, "\x1b\[[0-9;?]*[A-Za-z]", "") -replace "`r", ""
                    if ($clean.Trim().Length -lt 20) { throw "no output (login failed or command refused)" }
                    $clean | Out-File -Encoding $CsvEncoding $outFile
                    $null = $manifest.Add(("network/{0}" -f $j.file))
                    $netDone += $j.file
                    Write-Ok ("{0} -> network\{1}" -f $dev, $j.file)
                } catch {
                    Write-Bad ("{0} — {1}" -f $dev, $_.Exception.Message)
                }
            }
        }
    }
}

# ------------------------------------------------------------------ manifest
$readme = @"
PPSM collection results
=======================
Collected : $($started.ToString('yyyy-MM-dd HH:mm:ss'))
Shell     : PowerShell $($PSVersionTable.PSVersion) on the collecting machine (per-host shell and method are listed under FILES)
By        : $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME
Targets   : $($Computers -join ', ')
Reached   : $reached of $($Computers.Count)
$(if ($failed.Count) { "Unreachable: $($failed -join ', ')" })

WHAT TO DO WITH THIS FOLDER
  1. Open ppsm-builder.html in a browser.
  2. Set the subnet-to-enclave map under Settings.
  3. Select every file in hosts\ and inventory\ and drop them on the Ingest box.
  4. Press Finish Register.

FILES
$($manifest -join "`n")

$(if ($netDone.Count) {
"NETWORK DEVICES
  Collected over SSH: $($netDone -join ', ')
  Anything missing above failed to log in or returned nothing; see the console."
} else {
"STILL TO COLLECT (not reached by this run)
  Either re-run with -NetworkDevices fw01:asa,core01:ios -NetworkUser <user>,
  run ppsm.yml (Ansible) against the network group, or by hand:
  - Firewall connection table:  show conn all                              -> network\
  - Firewall ruleset:           show running-config access-list / object-group -> network\
  - Switch NetFlow cache:       show flow monitor <name> cache format csv  -> network\
  Save them as .txt or .csv in the network\ folder and drop the folder on the builder."
})
"@
$readme | Out-File -Encoding $CsvEncoding (Join-Path $dirs.root 'READ-ME.txt')

Write-Host ""
Write-Host ("Done in {0:n0}s. {1} of {2} hosts reached." -f `
    ((Get-Date) - $started).TotalSeconds, $reached, $Computers.Count) -ForegroundColor White
Write-Host ("Results: {0}" -f (Resolve-Path $dirs.root)) -ForegroundColor White
if ($failed.Count) { Write-Host ("Unreachable: {0}" -f ($failed -join ', ')) -ForegroundColor DarkYellow }
Write-Host ""
