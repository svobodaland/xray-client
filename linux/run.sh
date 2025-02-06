#!/bin/bash

if [ "$(uname -s)" != "Linux" ]; then
    echo "[x] This script is only for Linux"
    exit 1
fi

required_dependencies="tar unzip wget curl python"
arch=$(uname -m)
tun_name="svo-tun0"
dnscrypt_proxy_conf="/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
dns_blacklist_path="/etc/dnscrypt-proxy/blacklist.txt"
xray_address=""
xray_ip=""

ARGS=$(getopt -o dsc:l:h --long detach,stop,config:,blacklist:,nofilter,nokillswitch,killswitch-off,torify,log:,help -- "$@")
if [ $? -ne 0 ]; then
    echo "[x] Invalid arguments"
    exit 1
fi

SCRIPT_NAME=$(basename "$0")
PID_FILE="/tmp/$SCRIPT_NAME.pid"


eval set -- "$ARGS"

detach=false
stop=false
nofilter=false
nokillswitch=false
killswitch_off=false
torify=false
config_path="./config.json"
dns_blacklist_url="https://big.oisd.nl/domainswild"
log_path=""

show_help() {
    echo "Linux CLI client for DNSCrypt + tun2socks + Xray-core by https://svoboda.land"
    echo "Usage: [sudo] $0 [options]"
    echo "  -d, --detach        Run the process in the background."
    echo "  -s, --stop          Stop the detached process."
    echo "  -c, --config PATH   Specify the configuration file (default: ./config.json)."
    echo "  --blacklist URL     Url to DNSCrypt-compatible DNS blacklist. Default is https://big.oisd.nl/domainswild."
    echo "  --nofilter          Turn off DNS blacklist for blocking ads & tracking. DNS blacklist is turned on by default."
    echo "  --nokillswitch      Don't turn on killswitch. Killswitch is turned on by default."
    echo "  --killswitch-off    Turn off killswitch and exit."
    echo "  --torify            Route traffic through VPN and then Tor. Works only if the VPN server runs Tor on port 9050."
    echo "  -l, --log PATH      Specify the log file (default: output log to console)."
    echo "  -h, --help          Show this help message."
}

while true; do
    case "$1" in
        -d|--detach) 
            detach=true 
            shift ;;
        -s|--stop)
            stop=true
            shift ;;
        -c|--config)
            config_path="$2"
            shift 2 ;;
        --blacklist)
            dns_blacklist_url="$2"
            shift 2 ;;
        --nofilter)
            nofilter=true
            shift ;;
        --nokillswitch)
            nokillswitch=true
            shift ;;
        --killswitch-off)
            killswitch_off=true
            shift ;;
        --torify)
            torify=true
            shift ;;
        -l|--log)
            log_path="$2"
            shift 2 ;;
        -h|--help)
            show_help
            exit 0
            ;;
        --) 
            shift
            break ;;
        *) 
            echo "[x] Invalid arguments" 
            show_help
            exit 1 ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    echo "[x] Run as root"
    exit 1
fi

if [[ -n "$log_path" ]]; then
    exec >> "$log_path" 2>&1
fi

if [ ! -e "$config_path" ]; then
    echo "[x] Config file not found: $config_path"
    exit 1
fi

install_package() {
    local package="$1"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y "$package"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$package"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "$package"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm "$package"
    elif command -v zypper >/dev/null 2>&1; then
        zypper install -y "$package"
    else
        echo "[-] Unsupported package manager. Install $package manually."
        return 1
    fi
}

install_dnsutils() {
    if command -v apt-get >/dev/null 2>&1; then
        install_package "dnsutils"
    elif command -v dnf >/dev/null 2>&1; then
        install_package "bind-utils"
    elif command -v yum >/dev/null 2>&1; then
        install_package  bind-utils
    elif command -v pacman >/dev/null 2>&1; then
        install_package "bind"
    elif command -v zypper >/dev/null 2>&1; then
        install_package "bind-utils"
    else
        echo "No package manager found, install dig manually."
        exit 1
    fi
}

curl() {
    $(type -P curl) -L -q --retry 5 --retry-delay 10 --retry-max-time 60 "$@" || {
        echo "[-] Unable to connect to the internet or resolve the URL." >&2
        exit 1
    }
}

wget() {
    $(type -P wget) --quiet --show-progress --tries=5 --waitretry=10 --timeout=60 "$@" || {
        echo "[-] Unable to connect to the internet or resolve the URL." >&2
        exit 1
    }
}

is_binary_installed() {
    local binary="$1"
    if command -v "$binary" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

install_dependencies() {
    for pkg in $required_dependencies; do
        if ! is_binary_installed "$pkg"; then
            echo "[~] Installing $pkg..."
            install_package "$pkg" || {
                echo "[-] Failed to install $pkg. Please install it manually."
                exit 1
            }
            echo "[+] $pkg is installed."
        fi
    done
    if ! is_binary_installed "dig"; then
        install_dnsutils
    fi
}

is_file_stale() {
    file=$1
    days=$2
    if find "$file" -mtime +"$days" -print | grep -q "$file"; then
        return 0 #true
    else
        return 1 #false
    fi
}

receive_dns_blacklist() {
    if [[ ! -e $dns_blacklist_path ]]; then
        echo "[~] DNS Blacklist file does not exist, downloading..."
        wget "$dns_blacklist_url" -O $dns_blacklist_path --no-use-server-timestamps
    elif is_file_stale $dns_blacklist_path "7"; then
        echo "[~] DNS Blacklist file is stale, downloading..."
        wget "$dns_blacklist_url" -O $dns_blacklist_path --no-use-server-timestamps
    else
        echo "[+] DNS blacklist is up to date"
    fi
}

add_dns_blacklist() {
    echo "[~] Adding DNS blacklist..."
 
    echo -e '[blocked_names]\nblocked_names_file = '\''blacklist.txt'\''' | tee -a $dnscrypt_proxy_conf &>/dev/null

    systemctl restart dnscrypt-proxy  

    echo "[+] DNS Blacklist added"
}

remove_dns_blacklist() {
    echo "[~] Removing DNS blacklist..."

    sed -i '/^\[blocked_names\]/,/^$/d' $dnscrypt_proxy_conf

    systemctl restart dnscrypt-proxy  

    echo "[+] DNS Blacklist removed"
}

is_dns_blacklist_enabled() {
    if grep -q '^\[blocked_names\]' $dnscrypt_proxy_conf && grep -q "blocked_names_file = 'blacklist.txt'" $dnscrypt_proxy_conf; then
        return 0
    else
        return 1
    fi
}


install_dnscrypt_proxy() {
    echo "[~] Installing dnscrypt-proxy..."

    dnscrypt_proxy_version=$(curl -s https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest|grep tag_name|cut -d '"' -f 4)
    wget https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/"$dnscrypt_proxy_version"/dnscrypt-proxy-linux_"$arch"-"$dnscrypt_proxy_version".tar.gz -O /tmp/dnscrypt-proxy.tar.gz
    tar -xzvf /tmp/dnscrypt-proxy.tar.gz -C /tmp
    mv /tmp/linux-x86_64/dnscrypt-proxy /usr/sbin/dnscrypt-proxy
    rm /tmp/linux-x86_64 -r

    useradd -r -s /usr/sbin/nologin _dnscrypt-proxy
    groupadd _dnscrypt-proxy -U _dnscrypt-proxy
    mkdir -p /etc/dnscrypt-proxy/
    cp ../config/dnscrypt-proxy.toml $dnscrypt_proxy_conf
    cp ../config/dnscrypt-proxy.service /etc/systemd/system/
    # chmod -R 755 /etc/dnscrypt-proxy/

    systemctl daemon-reload
    systemctl enable dnscrypt-proxy  
    systemctl start dnscrypt-proxy  

    echo "[+] dnscrypt-proxy installed"
}

set_resolvconf() {
    if [ -L /etc/resolv.conf ]; then # is /etc/resolv.conf a symlink
        target=$(readlink -f /etc/resolv.conf)
        if [[ $target == *resolvconf* ]]; then # is managed by resolvconf
            echo "nameserver 127.0.0.1" | tee /etc/resolvconf/resolv.conf.d/head
            sudo resolvconf -u
        elif [[ $target == *systemd* ]]; then # is managed by systemd-resolved
            sudo mkdir -p /etc/systemd/resolved.conf.d
            echo -e "[Resolve]\nDNS=127.0.0.1\n" | tee /etc/systemd/resolved.conf.d/dnscrypt.conf
            sudo systemctl restart systemd-resolved
        else
            echo "Unsupported /etc/resolv.conf manager: $target. Change /etc/resolv.conf content to 'nameserver 127.0.0.1' (without quotes) if you want DNSCrypt-proxy to work."
        fi
    else
        # Set /etc/resolv.conf manually
        if ! grep -Fxq "nameserver 127.0.0.1" /etc/resolv.conf; then
            if lsattr "/etc/resolv.conf" 2>/dev/null | grep -q "i"; then
                echo "[-] File /etc/resolv.conf is immutable"
            else
                echo "nameserver 127.0.0.1" | tee /etc/resolv.conf
                chattr +i /etc/resolv.conf
            fi
        fi
    fi
}

get_xray_address() {
    grep 'address' "$config_path" | sed ':a;N;$!ba;s/\n//g' | sed 's/"//g'| sed 's/,//g' | awk '{print$2}'
}
get_ip_from_address() {
    address=$1

    # Regex for IPv4
    ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    # Regex for IPv6
    ipv6_regex='^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$'
    # Regex for domain
    domain_regex='^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'

    if [[ "$address" =~ $ipv4_regex ]]; then
        echo $address
        return 0
    elif [[ "$address" =~ $ipv6_regex ]]; then
        echo $address
        return 0
    elif [[ "$address" =~ $domain_regex ]]; then
        # In case dnscrypt-proxy is just restarted, we have to wait until it comes online
        tries=0
        while true; do
            if [ $tries -gt 5 ]; then
                echo "[-] Can't make DNS requests through DNSCrypt-proxy, exiting"
                exit 1
            fi
            ip=$(dig +short "$address" | head -n1)
            if echo "$ip" | grep -q "communications error"; then
                sleep 1
                tries=$(($tries+1))
                continue
            else
                echo $ip
                return 0
            fi
        done
    else
        echo "[x] $address is an invalid address"
        exit 1
    fi
}
get_xray_ip() {
    if [ -z "$xray_address" ]; then
        xray_address=$(get_xray_address)
    fi
    if [ -z "$xray_ip" ]; then
        xray_ip=$(get_ip_from_address "$xray_address")
    fi
    echo "$xray_ip"
}
get_default_gateway_ip() {
    ip route | grep 'default' | awk '{print$3}' | head -n1
}
get_default_interface() {
    ip route | awk '/default/ {print $5}' | head -n1
}
get_default_interface_ip() {
    default_interface=$(get_default_interface)
    ip addr show "$default_interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1
}

download_tun2socks() {
    echo "[~] Downloading tun2socks..."

    tun2socks_version=$(curl -s https://api.github.com/repos/xjasonlyu/tun2socks/releases/latest|grep tag_name|cut -d '"' -f 4)
    zip_filename=""
    if [ "$arch" = "x86_64" ]; then
        zip_filename="tun2socks-linux-amd64.zip"
    else
        zip_filename="tun2socks-linux-$arch.zip"
    fi
    wget https://github.com/xjasonlyu/tun2socks/releases/download/"$tun2socks_version"/"$zip_filename"
    unzip "$zip_filename"
    rm "$zip_filename"
    mv tun2socks-* tun2socks
    chmod +x ./tun2socks

    echo "[+] Downloaded tun2socks"
}

install_xray() {
    echo "[~] Installing xray..."

    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    echo "[+] xray installed"
}

download_geoip() {
    geoip_url="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
    geoip_file="/usr/local/share/xray/geoip.dat"
    if [[ ! -e $geoip_file ]] || is_file_stale $geoip_file "7"; then
        echo "[~] Downloading geoip.dat..."
        wget $geoip_url -O $geoip_file --no-use-server-timestamps
        echo "[+] Downloaded geoip.dat..."
    fi
}
download_geosite() {
    geosite_url="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
    geosite_file="/usr/local/share/xray/geosite.dat"

    if [[ ! -e $geosite_file ]] || is_file_stale $geosite_file "7"; then
        echo "[~] Downloading geosite.dat..."
        wget $geosite_url -O  $geosite_file --no-use-server-timestamps
        echo "[+] Downloaded geosite.dat..."
    fi
}

handle_xray_config() {
    prod_path="/usr/local/etc/xray/config.json"
    cp "$config_path" $prod_path

    # this prevents loops on linux
    default_interface=$(get_default_interface)
    pythoncode+="$(cat <<EOF
import json

with open("$prod_path", "r") as f:
    config = json.load(f)

for outbound in config.get("outbounds", []):
    if "streamSettings" not in outbound:
        outbound["streamSettings"] = {}
    streamSettings = outbound.get("streamSettings")
    if "sockopt" not in streamSettings:
        streamSettings["sockopt"] = {}
    outbound["streamSettings"]["sockopt"]["interface"] = "$default_interface"
EOF
)"

    if [ $torify = true ]; then
    # add tor outbound as default
    # assumes that default outbound has a "tag": "proxy"
    pythoncode+="

$(cat <<EOF
config.get("outbounds").insert(0, json.loads('''{
  "tag": "tor",
  "protocol": "socks",
  "settings": {
    "servers": [
      {
        "address": "127.0.0.1",
        "port": 9050
      }
    ]
  },
  "streamSettings": {
    "sockopt": {
    	"dialerProxy": "proxy" 
    }
  }
}
'''))
EOF
)"
    fi


    # add routing for DNSCrypt requests (assumes DNSCrypt-proxy runs at 127.0.0.1)
    dnscrypt_server_ports="4443"
    pythoncode+="
    
$(cat <<EOF
config.setdefault("routing", {}).setdefault("rules", [])
config["routing"]["rules"].append({
    "type": "field",
    "source": ["127.0.0.1"],
    "port": "$dnscrypt_server_ports",
    "network": "udp",
    "outboundTag": "direct"
})
EOF
)"

    pythoncode+="
    
$(cat <<EOF
with open("$prod_path", "w") as f:
    json.dump(config, f, indent=2)
EOF
)"

    if is_binary_installed "python3"; then
        python3 -c "$pythoncode"
    elif is_binary_installed "python"; then
        python -c "$pythoncode"
    fi

    sleep 3
}

add_tun() {
    echo "[~] Creating tunnel interface $tun_name..."

    # https://github.com/xjasonlyu/tun2socks/wiki/Load-TUN-Module
    # Create the necessary file structure for /dev/net/tun if it doesn't exist
    if [ ! -c /dev/net/tun ]; then
        if [ ! -d /dev/net ]; then
            mkdir -m 755 /dev/net
        fi
        mknod /dev/net/tun c 10 200
        chmod 0755 /dev/net/tun
    fi

    # Load the tun module if not already loaded
    if ( ! (lsmod | grep -q "^tun\s")); then
        insmod /lib/modules/tun.ko
    fi

    # Prevent DNS query loop
    # gateway_ip=$(get_default_gateway_ip)
    # xray_ip=$(get_xray_ip)
    # default_interface=$(get_default_interface)
    # ip route add $xray_ip via $gateway_ip dev $default_interface

    ip tuntap add dev $tun_name mode tun user tun2socks

    ip addr add 10.0.0.1/24 dev $tun_name
    ip addr add fdfe:dcba:9876::1/125 dev $tun_name

    ip link set $tun_name up
    ip -6 link set $tun_name up 2>/dev/null
    ip route add default dev $tun_name
    ip -6 route add default dev $tun_name 2>/dev/null

    echo "[+] Created tunnel interface $tun_name"
}

del_tun() {
    echo "[~] Deleting $tun_name interface..."

    ip tuntap del dev $tun_name mode tun
    if [ $? -ne 0 ]; then
        echo "[-] Failed to delete tunnel interface $tun_name"
    else
        echo "[+] Deleted $tun_name interface"
    fi
}

find_iptables() {
    if is_binary_installed "iptables"; then
        echo "iptables"
    elif is_binary_installed "iptables-nft"; then
        echo "iptables-nft"
    elif is_binary_installed "nft"; then
        echo "nft"
    else
        return 1
    fi
}

killswitch_enable() {
    echo "[~] Turning on killswitch..."

    ipt=$(find_iptables)
    if [ $? -eq 1 ]; then
        echo "[-] Failed to set up killswitch: iptables is not found"
        return 1
    fi

    xray_ip=$(get_xray_ip)

    # allow local and tunnel traffic
    $ipt -F
    $ipt -F -t nat
    $ipt -A INPUT -j ACCEPT -i lo
    $ipt -A OUTPUT -j ACCEPT -o lo
    $ipt -A INPUT -j ACCEPT -i $tun_name
    $ipt -A OUTPUT -j ACCEPT -o $tun_name

    # allow LAN
    for LAN in $(ip -o -f inet addr show | awk '/scope global/ {print $4}'|grep -E "^192\.168\.|^10\."); do
        $ipt -A INPUT -s $LAN -j ACCEPT
        $ipt -A OUTPUT -d $LAN -j ACCEPT
    done

    # allow VPN traffic
    $ipt -A OUTPUT -j ACCEPT -d $xray_ip
    $ipt -A INPUT -j ACCEPT -s $xray_ip

    # block everything else
    $ipt -P OUTPUT DROP
    $ipt -P INPUT DROP

    # turn off ipv6
    sysctl -qw net.ipv6.conf.all.disable_ipv6=1
    sysctl -qw net.ipv6.conf.default.disable_ipv6=1
    sysctl -qw net.ipv6.conf.lo.disable_ipv6=1

    echo "[+] Killswitch is on"
    echo "[?] The killswitch should turn off on script exit. To do it manually, run $0 --killswitch-off"
}

killswitch_disable() {
    echo "[~] Turning off killswitch..."

    ipt=$(find_iptables)
    if [ $? -eq 1 ]; then
        echo "[-] Failed to set up killswitch: iptables is not found"
        return 1
    fi

    # remove iptables rules
    $ipt -F
    $ipt -F -t nat
    $ipt -P OUTPUT ACCEPT
    $ipt -P INPUT ACCEPT

    # turn on ipv6
    sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    sysctl -qw net.ipv6.conf.default.disable_ipv6=0
    sysctl -qw net.ipv6.conf.lo.disable_ipv6=0

    echo "[+] Killswitch is off"

    return 0
}

cleanup() {
    systemctl stop xray
    del_tun
    killswitch_disable
}

start() {
    if $killswitch_off; then
        killswitch_disable
        exit $? 
    fi

    echo "[~] Starting main process..."

    echo "[~] Testing internet connection..."
    if ! ping -c 1 9.9.9.9 &> /dev/null; then
        echo "[-] No internet connection"
        exit 1
    fi

    install_dependencies

    if ! is_binary_installed "dnscrypt-proxy"; then
        install_dnscrypt_proxy
    fi

    if [ $nofilter = false ]; then
        receive_dns_blacklist
    fi
    if [ $nofilter = false ] && ! is_dns_blacklist_enabled; then
        add_dns_blacklist
    elif [ $nofilter = true ] && is_dns_blacklist_enabled; then
        remove_dns_blacklist
    fi

    set_resolvconf

    if ! is_binary_installed "xray"; then
        install_xray
    fi

    if grep -q "geoip:" "$config_path"; then
        download_geoip
    fi
    if grep -q "geosite:" "$config_path"; then
        download_geosite
    fi

    if [ ! -e "./tun2socks" ]; then
        download_tun2socks
    fi

    if ! id tun2socks &>/dev/null; then
        useradd -m tun2socks 
    fi

    # If tunnel interface already exists, delete it
    ip link show $tun_name &>/dev/null && del_tun

    handle_xray_config

    # Add tunnel interface
    add_tun

    systemctl enable xray
    systemctl restart xray

    ./tun2socks -device tun://$tun_name -proxy socks5://127.0.0.1:1080 &
    tun2socks_pid=$!
    trap 'echo "[~] Stopping tun2socks..."; kill "$tun2socks_pid" 2>/dev/null; wait "$tun2socks_pid"; echo "[+] Stopped tun2socks"' SIGTERM SIGINT EXIT

    if ! $nokillswitch; then
        killswitch_enable
    fi

    echo "[+] Started main process, press CTRL+C to stop"
    wait "$tun2socks_pid"

    cleanup

    echo "[+] Exiting main process"
}

stop() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE") # Get ID of the running process 
        if kill -0 "$pid" &>/dev/null; then # If process with $pid exist
            echo "[~] Stopping process with PID $pid..."

            kill -TERM "$pid"
            rm -f "$PID_FILE"

            echo "[+] Background process is stopped"

        else
            echo "[x] Process with PID $pid is not running."
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo "[x] No detached process running to stop."
        exit 1
    fi
}

if [ "$stop" = true ]; then
    stop
    exit 0
fi

if [ "$detach" = true ]; then
    echo "[~] Running in background..."
    if [ -f "$PID_FILE" ]; then
        echo "[~] A detached process is already running. Restarting..."
        stop
        sleep 5
    fi
    (
        trap 'exit' SIGTERM
        start
    ) &
    pid=$!
    echo "$pid" > "$PID_FILE"
    echo "[+] Background process started with PID $pid"
else
    start
fi
