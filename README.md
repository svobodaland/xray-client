# svoboda.land xray-core client

Privacy focused [xray-core](https://github.com/XTLS/Xray-core) client by https://svoboda.land

## Features

- DNS resolving via [DNSCrypt](https://dnscrypt.info), protecting user from DNS-based surveillance
- Automatically updated **DNS blacklist** for blocking ads/tracking/malware
- Robust **killswitch** prevents IP leaks
- **VPN > Tor chain** for enhanced privacy without the need to install Tor on client's machine
- Automatically updated **geosite.dat and geoip.dat** for xray routing

## Usage

### Linux

Requirements: 
- systemd
- git
- sudo
- root privileges

```bash
# Clone the repository
git clone https://github.com/svobodaland/xray-client

# Navigate to the client's directory
cd xray-client/linux

# Run (root priveleges are required)
sudo ./run.sh --config path/to/config.json
# OR just put config.json into this directory and run sudo ./run.sh
```

### Windows

Requirements: 
- powershell 5.1 (installed by default on windows 10/11)
- Administrative privileges

Start powershell.exe **as Administrator** and run code below

```powershell
# Clone the repository (if you have git installed)
git clone https://github.com/svobodaland/xray-client
cd xray-client/windows
# OR if you don't have git installed:
# Invoke-WebRequest -Uri https://github.com/svobodaland/xray-client/archive/refs/heads/main.zip -OutFile main.zip -ErrorAction Stop 
# Expand-Archive main.zip -DestinationPath .
# cd xray-client-main/windows

# Run
.\run.ps1 --config "path\to\config.json"
# OR just put config.json into this directory and run .\run.ps1
```

### Examples

- Route traffic through VPN and then Tor
    ```bash
    sudo ./run.sh --torify
    ```
- Detach (linux-only)
    ```bash
    sudo ./run.sh --detach
    ## stop detached process
    sudo ./run.sh --stop
    ```
- No killswitch
    ```bash
    sudo ./run.sh --nokillswitch
    ```
- Show help
    ```bash
    sudo ./run.sh --help
    ```
For Windows, add flags with one hyphen and capitalize (e.g. `.\run.ps1 -Torify`)

If, for some reason, the client is killed and killswitch is still enabled, to disable it run: `sudo ./run.sh --killswitch-off`

## Questions

If you have any questions, feel free to reach out:

- **Website:** https://svoboda.land
- **GitHub:** https://github.com/svobodaland
- **Email:** svoboda@mailum.com

## License

This project is licensed under the Mozilla Public License Version 2.0. See the [LICENSE](LICENSE) file for more details.

## Credits

- [XTLS](https://github.com/XTLS)
- [DNSCrypt](https://github.com/DNSCrypt)
- [xjasonlyu](https://github.com/xjasonlyu)
- [wintun](https://www.wintun.net)