#!/bin/bash

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

is_binary_installed() {
    local binary="$1"
    if command -v "$binary" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Clone the repository
if ! is_binary_installed "git"; then
    echo "[~] git is required, installing"
    install_package "git"
fi
git clone https://github.com/svobodaland/xray-client

# Copy config into client's directory
if [ ! -e "config.json" ]; then
    echo "[!] There is no config.json in the current directory"
else
    cp config.json xray-client/linux
fi

# Navigate to the client's directory
cd xray-client/linux

if [ ! -e "config.json" ]; then
    echo "[?] Put config.json in the current directory and run 'sudo ./run.sh'"
    exit 0
fi

# Run (root priveleges are required)
if ! is_binary_installed "git"; then
    echo "[-] sudo is required, installing"
    install_package "sudo"
fi
sudo ./run.sh