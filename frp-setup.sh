#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script installation path
INSTALL_PATH="/usr/local/bin/frp-manager"
SCRIPT_PATH="$(readlink -f "$0")"

# Helper functions
print_header() {
    echo -e "${BLUE}=================================${NC}"
    echo -e "${BLUE}       FRP Management Tool       ${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

# Cron for Garbage Collection / doesnt terminate process just triggers Garbage Collection and Ensuring BBR and FQ are Enabled
optimize() {
    local -r cron_job="0 */3 * * * pkill -10 -x frpc; pkill -10 -x frps"
    local -r sysctl_conf="/etc/sysctl.conf"
    local -r bbr_module="/etc/modules-load.d/bbr.conf"

    # Ensure cron job exists (idempotent)
    sudo crontab -l 2>/dev/null | grep -Fq "${cron_job}" || {
        (sudo crontab -l 2>/dev/null; echo "${cron_job}") | sudo crontab -
    }

    # Configure BBR if not already optimal
    [[ "$(sysctl -n net.core.default_qdisc)" == "fq" &&
       "$(sysctl -n net.ipv4.tcp_congestion_control)" == "bbr" ]] && return

    # Apply BBR configuration atomically
    {
        echo "net.core.default_qdisc=fq"
        echo "net.ipv4.tcp_congestion_control=bbr"
    } | sudo tee -a "${sysctl_conf}" >/dev/null

    echo "tcp_bbr" | sudo tee "${bbr_module}" >/dev/null

    sudo modprobe tcp_bbr 2>/dev/null || true
    sudo sysctl -p >/dev/null
}

# Reduce I/O by disabling rsyslog and making journald volatile
reduce_io() {
    print_info "Reducing I/O by logging only to memory..."
    sudo systemctl disable --now rsyslog && sudo sed -i 's/^#Storage=.*/Storage=volatile/' /etc/systemd/journald.conf && sudo sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=50M/' /etc/systemd/journald.conf && sudo sed -i 's/^#SystemKeepFree=.*/SystemKeepFree=5M/' /etc/systemd/journald.conf && sudo systemctl restart systemd-journald
    print_success "I/O reduced - logs are now stored in volatile memory."
}

# Remove all system logs
remove_logs() {
    print_warning "This will permanently delete all system logs!"
    read -p "Are you sure you want to continue? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_info "Log removal cancelled."
        return
    fi

    print_info "Removing all system logs..."

    # Clear journal logs
    sudo journalctl --vacuum-time=1s

    # Remove log files in /var/log
    sudo find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null
    sudo find /var/log -type f -name "*.log.*" -delete 2>/dev/null

    # Remove other common log locations
    sudo find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.2" -o -name "*.3" -o -name "*.4" -o -name "*.5" -o -name "*.6" -o -name "*.7" -o -name "*.8" -o -name "*.9" \) -delete 2>/dev/null

    # Clear wtmp and btmp logs
    sudo truncate -s 0 /var/log/wtmp 2>/dev/null
    sudo truncate -s 0 /var/log/btmp 2>/dev/null

    print_success "All system logs have been removed."
}

# Utilities menu
utilities_menu() {
    while true; do
        clear
        print_header
        echo "FRP Manager Utilities"
        echo "---------------------"
        echo
        echo "1) Optimize System (BBR, FQ)"
        echo "2) OS logs Only In Memory (Reduce disk I/O)"
        echo "3) Remove All System logs (Clears Storage)"
        echo "4) Back to Main Menu"
        echo

        read -p "Choose an option [1-4]: " util_choice
        echo

        case $util_choice in
            1)
                optimize
                print_success "System optimization completed."
                read -p "Press Enter to continue..."
                ;;
            2)
                reduce_io
                read -p "Press Enter to continue..."
                ;;
            3)
                remove_logs
                read -p "Press Enter to continue..."
                ;;
            4)
                return
                ;;
            *)
                print_error "Invalid option. Please choose 1-4."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Self-install the script as a command
install_script() {
    if [[ "$SCRIPT_PATH" == "$INSTALL_PATH" ]]; then
        print_info "Script is already installed as frp-manager command."
        return
    fi

    print_info "Installing script as frp-manager command..."
    curl -L https://raw.githubusercontent.com/mikeesierrah/frp-script/main/frp-setup.sh -o "$INSTALL_PATH"
    sudo chmod +x "$INSTALL_PATH"

    # Comment out the call to install_script in the installed version
    sed -i 's/^install_script$/# install_script/' "$INSTALL_PATH"

    # Comment out the call to optimize in the installed version
    sed -i 's/^optimize$/# optimize/' "$INSTALL_PATH"

    print_success "Script installed as frp-manager. You can now run it by typing 'frp-manager' in terminal."
}

# Force installation as frp-manager command
install_script

# Install FRP
install_frp() {
    print_info "Starting FRP installation..."

    # Detect platform
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l|armv6l) arch="arm" ;;
        *) print_error "Unsupported arch: $arch"; exit 1 ;;
    esac

    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    platform="${os}_${arch}"

    # Get latest version
    print_info "Fetching latest FRP version..."
    version=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
    url="https://github.com/fatedier/frp/releases/download/v${version}/frp_${version}_${platform}.tar.gz"

    print_info "Downloading $url"
    curl -L "$url" -o "/tmp/frp.tar.gz"

    print_info "Extracting..."
    tar -xzf /tmp/frp.tar.gz -C /tmp

    print_info "Installing frpc and frps..."
    cp /tmp/frp_${version}_${platform}/frpc /usr/local/bin/
    cp /tmp/frp_${version}_${platform}/frps /usr/local/bin/
    chmod +x /usr/local/bin/frpc /usr/local/bin/frps

    print_info "Creating config folders..."
    mkdir -p /root/frp/server
    mkdir -p /root/frp/client

    print_info "Writing frps@.service..."
    cat > /etc/systemd/system/frps@.service <<EOF
[Unit]
Description=FRP Server Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frps -c /root/frp/server/%i.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    print_info "Writing frpc@.service..."
    cat > /etc/systemd/system/frpc@.service <<EOF
[Unit]
Description=FRP Client Service (%i)
Documentation=https://gofrp.org/en/docs/overview/
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/frpc -c /root/frp/client/%i.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    print_info "Reloading systemd..."
    systemctl daemon-reload

    print_success "FRP $version installed and services created."
}

# Setup FRP Server
setup_server() {
    print_info "FRP Server Setup"

    read -p "Enter bindPort [7000]: " bindPort
    bindPort=${bindPort:-7000}

    echo "Enable Quic or KCP ? (default = 2):"
    echo "  1) none"
    echo "  2) quic"
    echo "  3) kcp"
    read -p "Protocol [2]: " proto_choice
    proto_choice=${proto_choice:-2}

    read -p "Enable TCP Mux (y/n) [n]: " use_mux
    use_mux=${use_mux:-n}

    read -p "Enter auth token [mikeesierrah]: " token
    token=${token:-mikeesierrah}

    mkdir -p /root/frp/server/
    config="/root/frp/server/server-$bindPort.toml"

    print_info "Writing config to $config"

    {
        echo "# Auto-generated frps config"
        echo 'bindAddr = "::"'
        echo "bindPort = $bindPort"

        if [[ $proto_choice == 2 ]]; then
            echo "quicBindPort = $bindPort"
        elif [[ $proto_choice == 3 ]]; then
            echo "kcpBindPort = $bindPort"
        fi
        echo

        if [[ $proto_choice == 2 ]]; then
            echo "transport.quic.keepalivePeriod = 10"
            echo "transport.quic.maxIdleTimeout = 30"
            echo "transport.quic.maxIncomingStreams = 100000"
        else
            echo "# transport.quic.keepalivePeriod = 10"
            echo "# transport.quic.maxIdleTimeout = 30"
            echo "# transport.quic.maxIncomingStreams = 100000"
        fi
        echo

        echo "transport.heartbeatTimeout = 90"
        echo "transport.maxPoolCount = 65535"
        echo "transport.tcpMux = $( [[ $use_mux =~ ^[Yy]$ ]] && echo true || echo false )"
        echo "transport.tcpMuxKeepaliveInterval = 10"
        echo "transport.tcpKeepalive = 120"
        echo
        echo 'auth.method = "token"'
        echo "auth.token = \"$token\""
    } > "$config"

    print_info "Enabling and starting frps@server-$bindPort..."
    systemctl enable --now frps@server-$bindPort

    print_success "Server setup complete."
}

# Setup FRP Client
setup_client() {
    print_info "FRP Client Setup"

    read -p "Server IP (v4 or v6): " server_ip

    read -p "Server port [7000]: " server_port
    server_port=${server_port:-7000}

    read -p "Auth token [mikeesierrah]: " auth_token
    auth_token=${auth_token:-mikeesierrah}

    echo "Choose transport protocol:"
    echo "1) tcp"
    echo "2) websocket"
    echo "3) quic"
    echo "4) kcp"
    read -p "Option [1]: " transport_option
    case $transport_option in
        2) transport="websocket" ;;
        3) transport="quic" ;;
        4) transport="kcp" ;;
        1|"") transport="tcp" ;;
        *) transport="tcp" ;;
    esac

    read -p "Enable TCP Mux (y/n) [n]: " use_mux
    use_mux=${use_mux:-n}

    read -p "Local ports to expose (e.g. 22,6000-6006,6007): " port_input

    config_name="client-$server_port.toml"
    mkdir -p /root/frp/client/

    cat > "/root/frp/client/$config_name" <<EOF
serverAddr = "$server_ip"
serverPort = $server_port

loginFailExit = false

auth.method = "token"
auth.token = "$auth_token"

transport.protocol = "$transport"
transport.tcpMux = $( [[ $use_mux =~ ^[Yy]$ ]] && echo true || echo false )
transport.tcpMuxKeepaliveInterval = 10
transport.dialServerTimeout = 10
transport.dialServerKeepalive = 120
transport.poolCount = 20
transport.heartbeatInterval = 30
transport.heartbeatTimeout = 90
transport.tls.enable = false
transport.quic.keepalivePeriod = 10
transport.quic.maxIdleTimeout = 30
transport.quic.maxIncomingStreams = 100000

{{- range \$_, \$v := parseNumberRangePair "$port_input" "$port_input" }}
[[proxies]]
name = "tcp-{{ \$v.First }}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {{ \$v.First }}
remotePort = {{ \$v.Second }}
transport.useEncryption = false
transport.useCompression = true
{{- end }}
EOF

    service_name="${config_name%.toml}"
    systemctl enable --now "frpc@$service_name"

    print_success "Client setup complete."
}

# Advanced config management
advanced_config() {
    print_info "Advanced Configuration Management"
    echo
    echo "1) Server Configuration"
    echo "2) Client Configuration"
    echo "3) Back to main menu"
    echo
    read -p "Choose option [1-3]: " config_choice

    case $config_choice in
        1)
            if [[ ! -d "/root/frp/server" ]] || [[ -z "$(ls -A /root/frp/server/ 2>/dev/null)" ]]; then
                print_warning "No server configurations found in /root/frp/server/"
                return
            fi

            print_info "Available server configurations:"
            echo
            configs=($(ls /root/frp/server/*.toml 2>/dev/null | xargs -n1 basename))
            for i in "${!configs[@]}"; do
                echo "$((i+1))) ${configs[$i]}"
            done
            echo "$((${#configs[@]}+1))) Back"
            echo

            read -p "Select configuration to edit [1-$((${#configs[@]}+1))]: " server_choice

            if [[ $server_choice -eq $((${#configs[@]}+1)) ]]; then
                return
            elif [[ $server_choice -ge 1 && $server_choice -le ${#configs[@]} ]]; then
                selected_config="${configs[$((server_choice-1))]}"
                config_path="/root/frp/server/$selected_config"

                print_info "Current configuration ($selected_config):"
                echo "----------------------------------------"
                cat "$config_path"
                echo "----------------------------------------"
                echo

                read -p "Edit this file? (y/n) [n]: " edit_choice
                if [[ "$edit_choice" =~ ^[Yy]$ ]]; then
                    ${EDITOR:-nano} "$config_path"

                    # Restart service if it's running
                    service_name="${selected_config%.toml}"
                    if systemctl is-active --quiet "frps@$service_name"; then
                        print_info "Restarting service frps@$service_name..."
                        systemctl restart "frps@$service_name"
                        print_success "Service restarted."
                    fi
                fi
            fi
            ;;
        2)
            if [[ ! -d "/root/frp/client" ]] || [[ -z "$(ls -A /root/frp/client/ 2>/dev/null)" ]]; then
                print_warning "No client configurations found in /root/frp/client/"
                return
            fi

            print_info "Available client configurations:"
            echo
            configs=($(ls /root/frp/client/*.toml 2>/dev/null | xargs -n1 basename))
            for i in "${!configs[@]}"; do
                echo "$((i+1))) ${configs[$i]}"
            done
            echo "$((${#configs[@]}+1))) Back"
            echo

            read -p "Select configuration to edit [1-$((${#configs[@]}+1))]: " client_choice

            if [[ $client_choice -eq $((${#configs[@]}+1)) ]]; then
                return
            elif [[ $client_choice -ge 1 && $client_choice -le ${#configs[@]} ]]; then
                selected_config="${configs[$((client_choice-1))]}"
                config_path="/root/frp/client/$selected_config"

                print_info "Current configuration ($selected_config):"
                echo "----------------------------------------"
                cat "$config_path"
                echo "----------------------------------------"
                echo

                read -p "Edit this file? (y/n) [n]: " edit_choice
                if [[ "$edit_choice" =~ ^[Yy]$ ]]; then
                    ${EDITOR:-nano} "$config_path"

                    # Restart service if it's running
                    service_name="${selected_config%.toml}"
                    if systemctl is-active --quiet "frpc@$service_name"; then
                        print_info "Restarting service frpc@$service_name..."
                        systemctl restart "frpc@$service_name"
                        print_success "Service restarted."
                    fi
                fi
            fi
            ;;
        3)
            return
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}

# Stop services
stop_services() {
    print_info "Stopping FRP services..."

    # Stop all running frps services
    running_servers=$(systemctl list-units --type=service --state=running | grep "frps@" | awk '{print $1}' || true)
    if [[ -n "$running_servers" ]]; then
        print_info "Stopping server services..."
        for service in $running_servers; do
            print_info "Stopping $service..."
            systemctl stop "$service"
        done
    fi

    # Stop all running frpc services
    running_clients=$(systemctl list-units --type=service --state=running | grep "frpc@" | awk '{print $1}' || true)
    if [[ -n "$running_clients" ]]; then
        print_info "Stopping client services..."
        for service in $running_clients; do
            print_info "Stopping $service..."
            systemctl stop "$service"
        done
    fi

    print_success "All FRP services stopped."
}

# Remove FRP completely
remove_frp() {
    print_warning "This will completely remove FRP and all configurations!"
    read -p "Are you sure? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_info "Removal cancelled."
        return
    fi

    print_info "Stopping all FRP services..."
    stop_services

    print_info "Disabling and removing services..."
    # Disable and remove all frp services
    enabled_servers=$(systemctl list-unit-files | grep "frps@" | awk '{print $1}' || true)
    for service in $enabled_servers; do
        systemctl disable "$service" 2>/dev/null || true
    done

    enabled_clients=$(systemctl list-unit-files | grep "frpc@" | awk '{print $1}' || true)
    for service in $enabled_clients; do
        systemctl disable "$service" 2>/dev/null || true
    done

    print_info "Removing service files..."
    rm -f /etc/systemd/system/frps@.service
    rm -f /etc/systemd/system/frpc@.service

    print_info "Removing binaries..."
    rm -f /usr/local/bin/frpc
    rm -f /usr/local/bin/frps

    print_info "Removing configuration directories..."
    rm -rf /root/frp/

    print_info "Reloading systemd..."
    systemctl daemon-reload

    print_success "FRP completely removed from system."
}

# Show service status
show_status() {
    print_info "FRP Service Status"
    echo

    # Check if binaries exist
    if [[ ! -f "/usr/local/bin/frpc" ]] || [[ ! -f "/usr/local/bin/frps" ]]; then
        print_warning "FRP is not installed."
        return
    fi

    print_info "Installed FRP version:"
    /usr/local/bin/frps --version 2>/dev/null || echo "Unable to determine version"
    echo

    print_info "Running services:"
    systemctl list-units --type=service --state=running | grep -E "frp[sc]@" || echo "No FRP services running"
    echo

    print_info "Enabled services:"
    systemctl list-unit-files | grep -E "frp[sc]@.*enabled" || echo "No FRP services enabled"
    echo

    print_info "Configuration files:"
    echo "Server configs:"
    ls -la /root/frp/server/ 2>/dev/null || echo "  No server configs found"
    echo "Client configs:"
    ls -la /root/frp/client/ 2>/dev/null || echo "  No client configs found"
}

# Main menu
main_menu() {
    while true; do
        clear
        print_header

        echo "1) Install FRP"
        echo "2) Setup FRP Server"
        echo "3) Setup FRP Client"
        echo "4) Advanced Configuration"
        echo "5) Show Status"
        echo "6) Stop All Services"
        echo "7) Optimization Utilities"
        echo "8) Remove FRP"
        echo "9) Exit"
        echo

        read -p "Choose an option [1-9]: " choice
        echo

        case $choice in
            1)
                install_frp
                read -p "Press Enter to continue..."
                ;;
            2)
                setup_server
                read -p "Press Enter to continue..."
                ;;
            3)
                setup_client
                read -p "Press Enter to continue..."
                ;;
            4)
                advanced_config
                read -p "Press Enter to continue..."
                ;;
            5)
                show_status
                read -p "Press Enter to continue..."
                ;;
            6)
                stop_services
                read -p "Press Enter to continue..."
                ;;
            7)
                utilities_menu
                ;;
            8)
                remove_frp
                read -p "Press Enter to continue..."
                ;;
            9)
                print_success "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose 1-9."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Ensure optimization
optimize
# Start the main menu
main_menu
