param (
    [string]$Config = "config.json",
    [string]$Blacklist = "https://big.oisd.nl/domainswild",
    [string]$Log = $null,
    [switch]$Nokillswitch = $false,
    [switch]$KillswitchOff = $false,
    [switch]$Torify = $false,
    [switch]$NoFilter = $false
)

function Test-Windows {
    return ($env:OS -match 'Windows')
}
function Test-Administrator {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}
function Get-OSBitness {
    return (Get-WmiObject Win32_OperatingSystem).OSArchitecture.substring(0, 2)
}
function Get-ProcessorArchitecture {
    return $env:PROCESSOR_ARCHITECTURE.ToLower()
}
function curl {
    param (
        [string]$Url
    )
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -ErrorAction Stop
        $response.Content | Out-Host
    } catch {
        Write-Error "[-] Unable to connect to the internet or resolve the URL."
        exit 1
    }
}
function Test-FileWritable {
    param ([string]$FilePath)
    try {
        $file = [System.IO.File]::Open($FilePath, "Append", "Write")
        $file.Close()
        return $true
    } catch {
        return $false
    }
}

function Invoke-FileDownload {
    param (
        [string]$Url,
        [string]$OutputPath
    )
    if (-not $OutputPath) {
        $OutputPath = (Split-Path $Url -Leaf)
    }
    try {
        if (-not (Test-FileWritable $OutputPath)) {
            Write-Error "[-] Unable to download $Url, $OutputPath is not writable"
            exit 1
        }
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -ErrorAction Stop
    } catch {
        Write-Error "[-] Unable to connect to the internet or resolve the URL: $($_.Exception)"
        exit 1
    }
}
function Add-ToPath {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    $trimmed_path = $env:PATH.TrimEnd(';')
    if ($trimmed_path -like "*$Path*") {
        Write-Host "[!] The path '$Path' is already in the PATH."
    } else {
        $new_path = $trimmed_path + ";" + $Path
        [Environment]::SetEnvironmentVariable("PATH", $new_path, [EnvironmentVariableTarget]::Machine)
        $env:PATH = $new_path
    }
}
function Remove-FromPath {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    if ($env:PATH -notlike "*$Path*") {
        Write-Host "[!] The path '$Path' is not in the PATH."
    } else {
        $current_path = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)
        $new_path = ($current_path -split ';' | Where-Object { $_ -ne $Path }) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $new_path, [EnvironmentVariableTarget]::Machine)
        $env:PATH = $new_path
    }
}
function Test-Installed {
    param (
        [Parameter(Mandatory)]
        [string]$BinaryName
    )

    if (Get-Command $BinaryName -ErrorAction SilentlyContinue) {
        return $true
    } else {
        return $false
    }
}
function Show-Help {
    $help_text = @"
Windows CLI client for DNSCrypt + tun2socks + Xray-core by https://svoboda.land
Usage: .\svoboda-vpn-windows.ps1 [OPTIONS]

Options:
-Config PATH   Specify the configuration file (default: ./config.json)
-Blacklist URL Url to DNSCrypt-compatible DNS blacklist. Default is https://big.oisd.nl/domainswild"
-Nofilter      Turn off DNS blacklist for blocking ads & tracking
-Nokillswitch  Don't turn on killswitch. Killswitch is turned on by default."
-KillswitchOff Turn off killswitch and exit."
-Torify        Route traffic through VPN and then Tor. Assumes VPN server runs Tor on port 9050."
-Log PATH      Specify the log file (default: output log to console).
-Help          Show this help message.
"@
    Write-Host $help_text
}

if (-not (Test-Windows)) {
   Write-Error "[x] This script is only for Windows."
   exit 1
}
if (-not (Test-Administrator)) {
    Write-Host "[!] This script requires administrator privileges."
    Start-Process -FilePath "powershell" -ArgumentList "$('-File ""')$(Get-Location)$('\')$($MyInvocation.MyCommand.Name)$('""')" -Verb runAs
    exit 1
}
if ($Config -eq "config.json") {
    $Config = Join-Path $PSScriptRoot $Config
}
if (-not (Test-Path $Config)) {
    Write-Error "[x] Config file not found: $Config"
    exit 1
}
if ($Log) {
    if (-not (Test-FileWritable $Log)) {
        Write-Error "[!] Can't log to $log, check file permissions and if the file is being used by another process"
    } else {
        Start-Transcript -Path $Log
    }
}

$bitness = Get-OSBitness
$arch = Get-ProcessorArchitecture
$tmp_dir = Join-Path $env:TEMP "svoboda-vpn"
$dnscrypt_proxy_download_path = (Join-Path $env:ProgramFiles "dnscrypt-proxy")
$dnscrypt_proxy_final_path = Join-Path $dnscrypt_proxy_download_path "win$bitness"
$dnscrypt_proxy_conf = Join-Path $dnscrypt_proxy_final_path "dnscrypt-proxy.toml"
$dns_blacklist_url = $Blacklist
$dns_blacklist_path = Join-Path $dnscrypt_proxy_final_path "blacklist.txt"
$xray_path = Join-Path $env:ProgramFiles "xray-core"
$xray_binary = Join-Path $xray_path "xray.exe"
$xray_config = Join-Path $xray_path "config.json"
$tun2socks_path = Join-Path $env:ProgramFiles "tun2socks"
$tun2socks_binary = Join-Path $tun2socks_path "tun2socks.exe"

$ShowWindows = "Hidden"
$TUN_NAME = "wintun"

$script:XRAY_PID = $null 
$script:TUN2SOCKS_PID = $null
$script:default_interface = $null
$script:gateway_ip = $null
$script:xray_address = $null
$script:xray_ip = $null

function Test-FileStale {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [int]$Days
    )

    $last_modified = (Get-ItemProperty -Path $FilePath).LastWriteTime
    $days_since_last_modified = (Get-Date).Subtract($last_modified).Days
    return ($days_since_last_modified -gt $Days)
}

function Receive-DNSBlacklist {
    if (-not (Test-Path -Path $dns_blacklist_path)) {
        Write-Host "[~] DNS Blacklist file does not exist, downloading..."
        Invoke-FileDownload -Url $dns_blacklist_url -OutputPath $dns_blacklist_path 
        Write-Host "[+] DNS Blacklist downloaded"
    }
    elseif (Test-FileStale -FilePath $dns_blacklist_path -Days 7) {
        Write-Host "[~] DNS Blacklist file is stale, downloading..."
        Invoke-FileDownload -Url $dns_blacklist_url -OutputPath $dns_blacklist_path 
        Write-Host "[+] DNS Blacklist downloaded"
    } else {
        Write-Host "[+] DNS blacklist is up to date"
    }
}

function Add-DNSBlacklist {
    Write-Host  "[~] Adding DNS blacklist..."

    "[blocked_names]`nblocked_names_file = 'blacklist.txt'" | Out-File -Append -FilePath $dnscrypt_proxy_conf -Encoding UTF8

    dnscrypt-proxy -service stop
    dnscrypt-proxy -service start

    Write-Host "[+] DNS Blacklist added"
}

function Remove-DNSBlacklist {
    Write-Host "[~] Removing DNS blacklist..."

    (Get-Content $dnscrypt_proxy_conf) -replace "^\[blocked_names\]", '' -join "`n" | Set-Content -Path $dnscrypt_proxy_conf -Encoding UTF8
    (Get-Content $dnscrypt_proxy_conf) -replace "^blocked_names_file = 'blacklist.txt'", '' -join "`n" | Set-Content -Path $dnscrypt_proxy_conf -Encoding UTF8

    dnscrypt-proxy -service stop
    dnscrypt-proxy -service start

    Write-Host "[+] DNS Blacklist removed"
}

function Test-DNSBlacklistEnabled {
    if ((Select-String -Pattern '^\[blocked_names\]' -Path $dnscrypt_proxy_conf) -and 
        (Select-String -Pattern "blocked_names_file = 'blacklist.txt'" -Path $dnscrypt_proxy_conf)) {
        return $true
    } else {
        return $false
    }
}

function Install-DNSCryptProxy {
    Write-Host "[~] Installing dnscrypt-proxy..."

    try {
        $dnscrypt_proxy_version = (curl https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest | ConvertFrom-Json).tag_name
        $zip = (Join-Path $tmp_dir dnscrypt-proxy.zip)
        Invoke-FileDownload -Url "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/$dnscrypt_proxy_version/dnscrypt-proxy-win$bitness-$dnscrypt_proxy_version.zip" -OutputPath $zip
        Expand-Archive -Path $zip -DestinationPath $dnscrypt_proxy_download_path -Force
        rm $zip

        cp config/dnscrypt-proxy.toml $dnscrypt_proxy_conf

        $dnscrypt_proxy_exe = Join-Path $dnscrypt_proxy_final_path "dnscrypt-proxy.exe"
        Add-ToPath $dnscrypt_proxy_final_path

        & $dnscrypt_proxy_exe -service install
        & $dnscrypt_proxy_exe -service start

        Write-Host "[+] dnscrypt-proxy installed"
    } catch {
        Write-Error "[-] Failed to install dnscrypt-proxy: $($_.Exception)"
        exit 1
    }
}

function Get-DefaultInterfaceAlias {
    return Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object -Property RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias
}
function Get-InterfaceIP {
    param (
        [string]$InterfaceAlias
    )
    return Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
}
function Get-GatewayIP {
    param (
        [string]$InterfaceAlias
    )
    return Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty NextHop
}
function Set-SystemDNS {
    Write-Host "[~] Setting system DNS..."

    # here you can add optional backup DNS server in case DNSCrypt-proxy servers are down. Queries sent to the backup server will not be encrypted. 
    # Set-DnsClientServerAddress -InterfaceAlias $script:default_interface -ServerAddresses ("127.0.0.1", "9.9.9.9")
    Set-DnsClientServerAddress -InterfaceAlias $script:default_interface -ServerAddresses ("127.0.0.1")

    Write-Host "[+] Set system DNS"
}

function Install-Xray {
    try {
        Write-Host "[~] Downloading xray-core..."
        $xray_version = (curl https://api.github.com/repos/xtls/Xray-core/releases/latest | ConvertFrom-Json).tag_name
        $zip = (Join-Path $tmp_dir xray.zip)
        Invoke-FileDownload -Url "https://github.com/xtls/Xray-core/releases/download/$xray_version/Xray-windows-$bitness.zip" -OutputPath $zip
        Expand-Archive -Path $zip -DestinationPath $xray_path
        rm $zip

        Add-ToPath -Path $xray_path

        $user = "$env:USERNAME"

        Write-Host "[+] xray-core installed"
    } catch {
        Write-Error "[-] Failed to install xray-core: $($_.Exception)"
        exit 1
    }
}

function Receive-GeoIP() {
    $geoip_url = "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
    $geoip_file = Join-Path $xray_path "geoip.dat"
    if (-not (Test-Path -Path $geoip_file) -or (Test-FileStale -FilePath $geoip_file -Days 7)) {
        Write-Host "[~] Downloading geoip.dat..."
        Invoke-FileDownload -Url $geoip_url -OutputPath $geoip_file
        Write-Host "[+] Downloaded geoip.dat..."
    }
}
function Receive-Geosite() {
    $geosite_url = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
    $geosite_file = Join-Path $xray_path "geosite.dat"

    if (-not (Test-Path -Path $geosite_file) -or (Test-FileStale -FilePath $geosite_file -Days 7)) {
        Write-Host "[~] Downloading geosite.dat..."
        Invoke-FileDownload -Url $geosite_url -OutputPath $geosite_file
        Write-Host "[+] Downloaded geosite.dat..."
    }
}

function Install-Tun2socks {
    Write-Host "[~] Downloading tun2socks..."

    try {
        $tun2socks_version = (curl https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest | ConvertFrom-Json).tag_name
        $zip = (Join-Path $tmp_dir tun2socks.zip)
        Invoke-FileDownload -Url "https://github.com/xjasonlyu/tun2socks/releases/download/$tun2socks_version/tun2socks-windows-$arch.zip" -OutputPath $zip
        Expand-Archive -Path $zip -DestinationPath $tun2socks_path
        rm $zip
        mv (Join-Path $tun2socks_path tun2socks-*) $tun2socks_binary

        Write-Host "[~] Downloading wintun..."
        $zip_filename = "wintun-0.14.1.zip"
        Invoke-FileDownload "https://www.wintun.net/builds/$zip_filename" -O $zip_filename
        Expand-Archive -Path $zip_filename -DestinationPath $tun2socks_path
        rm $zip_filename
        mv (Join-Path $tun2socks_path "wintun\bin\$arch\wintun.dll") $tun2socks_path

        Write-Host "[+] tun2socks installed"
    } catch {
        Write-Error "[-] Failed to install tun2socks: $($_.Exception)"
        exit 1
    }
}

function Start-Tun2Socks {
    try {
        $timeout = 10
        $elapsed = 0
        $interval = 100
        $proc = Start-Process $tun2socks_binary -ArgumentList "-device $TUN_NAME -proxy socks5://127.0.0.1:1080 -interface $script:default_interface" -WindowStyle $ShowWindows -PassThru
        $script:TUN2SOCKS_PID = $proc.Id
        # Wait while tun2socks creates the net adapter
        while (-not (Get-NetAdapter -Name $TUN_NAME -ErrorAction SilentlyContinue) -and ($elapsed -lt ($timeout * 1000))) {
            Start-Sleep -Milliseconds $interval
            $elapsed += $interval
        }
        if (-not (Get-NetAdapter -Name $TUN_NAME -ErrorAction SilentlyContinue)) {
            Write-Error "[-] tun2socks is not creating $TUN_NAME interface: $($_.Exception)"
            Start-Cleanup
            exit 1
        }
    } catch {
        Write-Error "[-] Failed to start tun2socks: $($_.Exception)"
        exit 1
    }
}
function Start-Xray {
    try {
        $proc = Start-Process $xray_binary -ArgumentList "--config `"$xray_config`"" -WindowStyle $ShowWindows -PassThru
        $script:XRAY_PID = $proc.Id
    } catch {
        Write-Error "[-] Failed to start Xray-core: $($_.Exception)"
        exit 1
    }
}
function Stop-Xray {
    Write-Host "[~] Stopping Xray-core"
    try {
        Stop-Process -Id $script:XRAY_PID -Force
    } catch {
        Write-Error "[-] Failed to stop Xray-core"
    }
}
function Stop-Tun2Socks {
    Write-Host "[~] Stopping tun2socks"
    try {
        Stop-Process -Id $script:TUN2SOCKS_PID -Force
    } catch {
        Write-Error "[-] Failed to stop tun2socks"
    }
}
function Set-XrayConfig {
    cp $Config $xray_config

    if ($Torify) {
        $json_content = Get-Content -Path $xray_config -Raw
        $json_object = $json_content | ConvertFrom-Json

        $tor_outbound = @{
            "tag" = "tor"
            "protocol" = "socks"
            "settings" = @{
                "servers" = @(
                    @{
                        "address" = "127.0.0.1"
                        "port" = 9050
                    }
                )
            }
            "streamSettings" = @{
                "sockopt" = @{
                    "dialerProxy" = "proxy"
                }
            }
        }

        # Add the new outbound as the first outbound in the outbounds array
        $json_object.outbounds = @($tor_outbound) + $json_object.outbounds

        $new_json_content = $json_object | ConvertTo-Json -Depth 10

        Set-Content -Path $xray_config -Value $new_json_content
    }
}

function Find-AddressInXrayConfig {
    param (
        [string]$Config
    )
    $config_obj = Get-Content -Path $Config -Raw | ConvertFrom-Json
    $outbounds = $config_obj.outbounds
    foreach ($outbound in $outbounds) {
        $settings = $outbound.settings
        if ($settings.PSObject.Properties.Name -contains "vnext") {
            return $settings.vnext[0].address
        } else {
            return $settings.address
        }
    }
}
function Get-IPFromAddress {
    param (
        [Parameter(Mandatory)]
        [string]$Address
    )
    # Regex for IPv4
    $ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Regex for IPv6
    $ipv6_regex='^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
    # Regex for domain
    $domain_regex='^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'

    if ($Address -match $ipv4_regex) {
        return $Address
    }
    elseif ($Address -match $ipv6_regex) {
        return $Address
    }
    elseif ($Address -match $domain_regex) {
        # In case dnscrypt-proxy is just restarted, we have to wait until it comes online
        $tries = 0
        while ($true) {
            if ($tries -gt 5) {
                Write-Host "[-] Can't make DNS requests through DNSCrypt-proxy, exiting"
                exit 1
            }
        
            try {
                $dns_request = Resolve-DnsName -Name $Address -ErrorAction Stop
                $ip = $dns_request.IPAddress | Select-Object -First 1
                return $ip
            } catch {
                if ($_.Exception.Message -match "DNS name does not exist") {
                    Write-Error "[x] $Address does not exist"
                    exit 1
                }
                Start-Sleep -Seconds 1
                $tries++
                continue
            }
        }
    } 
    else {
        Write-Error "[x] $Address is an invalid address"
        exit 1
    }
}

function Get-XrayIP {
    if (-not ($script:xray_address)) {
        $script:xray_address = Find-AddressInXrayConfig $Config
    }
    if (-not ($script:xray_ip)) {
        $script:xray_ip = Get-IPFromAddress $xray_address
    }
    return $script:xray_ip
}
function Add-Routes {
    Write-Host "[~] Adding routes..."

    try {
        $xray_ip = Get-XrayIP
        netsh interface ipv4 set address name="$TUN_NAME" source=static addr=192.168.123.1 mask=255.255.255.0 1>$null
        netsh interface ipv4 add route 0.0.0.0/0 "$TUN_NAME" 192.168.123.1 metric=1 1>$null
        New-NetRoute -DestinationPrefix "$xray_ip/32" -NextHop $script:gateway_ip -InterfaceAlias $script:default_interface -ErrorAction SilentlyContinue
    } catch {
        Write-Error "[-] Failed to add routes: $($_.Exception)"
        Start-Cleanup
        exit 1
    }
    
    Write-Host "[+] Added routes"
}

function Remove-Routes {
    Write-Host "[~] Deleting routes..."

    try {
        netsh interface ipv4 delete route 0.0.0.0/0 interface="$TUN_NAME" 1>$null
    } catch {
        Write-Error "[-] Failed to delete routes: $($_.Exception)"
        exit 1
    }

    Write-Host "[+] Deleted routes"
}

function Enable-Killswitch {
    Write-Host "[~] Turning on killswitch..."

    $xray_ip = Get-XrayIP

    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
    New-NetFirewallRule -DisplayName "SvobodaVPN Kill Switch - Allow VPN Interface Traffic" `
                    -Direction Outbound `
                    -Action Allow `
                    -InterfaceAlias $TUN_NAME `
                    -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "SvobodaVPN Kill Switch - Allow VPN IP Traffic" `
                    -Direction Outbound `
                    -Action Allow `
                    -RemoteAddress $xray_ip `
                    -Profile Any | Out-Null

    Write-Host "[+] Killswitch is on"
}

function Disable-Killswitch {
    Write-Host "[~] Turning off killswitch..."

    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow
    Remove-NetFirewallRule -DisplayName "SvobodaVPN Kill Switch*"

    Write-Host "[+] Killswitch is off"
}

function Start-Cleanup {
    Write-Host "[~] Cleaning up..."

    Remove-Routes
    Stop-Xray
    Stop-Tun2Socks
    Disable-Killswitch
    Stop-Transcript -ErrorAction SilentlyContinue
}

function Start-Main {
    if ($KillswitchOff) {
        Disable-Killswitch
        exit 0
    }

    Write-Host "[~] Starting main process..."

    Write-Host "[~] Testing internet connection..."
    $ping_result = Test-Connection -ComputerName 9.9.9.9 -Count 1 -Quiet
    if (-not $ping_result) {
        Write-Error "[-] No internet connection"
        exit 1
    } 

    $script:default_interface = Get-DefaultInterfaceAlias
    $script:gateway_ip = Get-GatewayIP -InterfaceAlias $script:default_interface

    if (-not (Test-Path -Path $tmp_dir)) {
        New-Item -ItemType Directory -Path $tmp_dir | Out-Null
    } 

    if (-not (Test-Installed "dnscrypt-proxy")) {
        Install-DNSCryptProxy
    }

    if (-not ($NoFilter)) {
        Receive-DNSBlacklist
    }
    $is_dns_blacklist_enabled = Test-DNSBlacklistEnabled
    if (-not ($NoFilter) -and -not ($is_dns_blacklist_enabled)) {
        Add-DNSBlacklist
    }   
    elseif ($NoFilter -and $is_dns_blacklist_enabled) {
        Remove-DNSBlacklist
    }

    Set-SystemDNS

    if (-not (Test-Installed "xray")) {
        Install-Xray
    }

    if (Select-String -Path $Config -Pattern "geoip:") {
        Receive-GeoIP
    }

    if (Select-String -Path $Config -Pattern "geosite:") {
        Receive-Geosite
    }

    if (-not (Test-Installed $tun2socks_binary)) {
        Install-Tun2socks
    }

    Set-XrayConfig
    Start-Xray
    Start-Tun2Socks
    Add-Routes

    if (-not ($Nokillswitch)) {
        Enable-Killswitch
    }

    Write-Host "[+] Started main process, press CTRL+C to stop"

    # Loop until Ctrl+C 
    try {
        while ($true) {
            Start-Sleep 1
        }
    } finally {
        Write-Host "[~] Exiting main process"
        Start-Cleanup
        exit
    }
}

Start-Main

# TODO: Make detaching work on Windows (main process should be killed gracefully).
#
#
# function Send-CtrlC {
#     [Parameter(Mandatory)]
#     [int]$ProcessID
    
#     $MemberDefinition = @'
#         [DllImport("kernel32.dll")]public static extern bool FreeConsole();
#         [DllImport("kernel32.dll")]public static extern bool AttachConsole(uint p);
#         [DllImport("kernel32.dll")]public static extern bool GenerateConsoleCtrlEvent(uint e, uint p);
#         [DllImport("kernel32.dll")]public static extern bool SetConsoleCtrlHandler(uint routine, uint Add);

#         public static void SendCtrlC(uint p) {
#             AttachConsole(p);
#             GenerateConsoleCtrlEvent(0, p);
#         }
# '@
#     Add-Type -Name 'SomeName' -Namespace 'SomeNamespace' -MemberDefinition $MemberDefinition
#     [SomeNamespace.SomeName]::SendCtrlC($ProcessID)
# }
# function Stop-DetachedGracefully {
#     $target_pid = Get-Content -Path $PID_FILE -ErrorAction SilentlyContinue
#     if (!$target_pid) {
#         Write-Host "[x] No detached process running to stop."
#         exit 1
#     }
#     $target_proc = Get-Process -Id $target_pid -ErrorAction SilentlyContinue
#     if (!$target_proc) {
#         Write-Host "[x] Process with PID $target_pid is not running."
#         Remove-Item "$PID_FILE" -Force
#         exit 1
#     }
#     Write-Host "[~] Stopping process with PID $target_pid..."

#     Remove-Item "$PID_FILE" -Force
#     Send-CtrlC $target_pid

#     Write-Host "[+] Background process is stopped"
# }

# if ($Stop) {
#     Stop-DetachedGracefully
#     exit 0
# }

# if ($Detach) {
#     Write-Host "[~] Running in background..."
#     $old_pid = Get-Content -Path $PID_FILE -ErrorAction SilentlyContinue
#     if ($old_pid) {
#         Write-Host "[~] A detached process is already running. Restarting..."
#         Stop-DetachedGracefully
#         Start-Sleep 5
#     }
#     $argumentList = @()
#     if ($Config -ne ".\config.json") { $argumentList += "-Config", "`"$Config`"" }
#     if ($Log) { $argumentList += "-Log", "`"$Log`"" }
#     if ($NoFilter) { $argumentList += "-NoFilter" }
#     $detached_proc = Start-Process powershell -ArgumentList "-Command", "& { $PSCommandPath $argumentList }" -PassThru
#     $detached_proc_id = $detached_proc.Id
#     $detached_proc_id | Out-File -FilePath $PID_FILE
#     Write-Host "[+] Background process started with PID $detached_proc_id"
# } else {
#     Start-Main
# }