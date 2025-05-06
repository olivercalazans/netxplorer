#!/bin/bash

# Ensure the script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please use 'sudo' to execute it."
  exec sudo "$0" "$@"
fi



# Variables
SOURCE_DIR=$(dirname "$(realpath "$0")")
ROOT_DIR=${SOURCE_DIR%/*/*}
DESTINY_DIR="/opt/netxplorer"
WRAPPER_FILE="xplorer"
DIRECTORIES=("config" "core" "models" "sniffing" "utils")
FILES=(
    # CONFIG ===================
    "config/__init__.py"              
    "config/arg_parser.py"
    # CORE=======================
    "core/__init__.py"
    "core/banner_grabber.py"
    "core/network_mapper.py"
    "core/port_scanner.py"
    # DISSECTOR =================
    "dissector/__init__.py"
    "dissector/dissector.py"
    "dissector/ip_dissector.py"
    "dissector/tcp_dissector.py"
    # MODEL =====================
    "models/__init__.py"
    "models/data.py"
    # PACKET BUILD ==============
    "pkt_build/__init__.py"
    "pkt_build/header_icmp.py"
    "pkt_build/header_ip.py"
    "pkt_build/header_tcp.py"
    "pkt_build/header_udp.py"
    "pkt_build/layer_4_utils.py"
    "pkt_build/packet_builder.py"
    "pkt_build/packet_sender.py"
    # SNIFFING ==================
    "sniffing/__init__.py"
    "sniffing/bpf_filter.py"
    "sniffing/sniffer.py"
    # UTILS =====================
    "utils/__init__.py"
    "utils/network_info.py"
    "utils/port_set.py"
    "utils/type_hints.py"
    # ROOT ======================
    "__init__.py"
    "main.py"
)



# Verify if all required files exist
FILES_NOT_FOUND=""
for file in "${FILES[@]}"; do
    if [ ! -e "$SOURCE_DIR/$file" ]; then
        FILES_NOT_FOUND="$FILES_NOT_FOUND $file"
    fi
done



# Stop execution if any file is missing
if [ -n "$FILES_NOT_FOUND" ]; then
    echo "[ ERROR ] File(s) not found: $FILES_NOT_FOUND"
    exit 1
fi



# Create directories
sudo mkdir -p "$DESTINY_DIR"

for dict in "${DIRECTORIES[@]}"; do
    sudo mkdir -p "$DESTINY_DIR/$dict"
done
echo "[  OK  ] Directory created ($DESTINY_DIR)"



# Copie files to destiny directory
for file in "${FILES[@]}"; do
    cp "$SOURCE_DIR/$file" "$DESTINY_DIR/$file"
done



# Copy the LICENSE file if it exists
if [ -e "$ROOT_DIR/LICENSE" ]; then
    cp "$ROOT_DIR/LICENSE" "$DESTINY_DIR" 2> /dev/null
else
    echo "[WARNING] LICENSE not found"
fi



# Create a wrapper script to execute the application
cat <<'EOF' > "/usr/bin/$WRAPPER_FILE"
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

python3 /opt/netxplorer/main.py "$@"
EOF
echo "[  OK  ] Wrapper script created"



# Protect files and directories
sudo chmod -R 710 "$DESTINY_DIR"
sudo chmod 710 "/usr/bin/$WRAPPER_FILE"


# Display installation completion message
echo "INSTALLATION COMPLETED"
echo "A copy has been kept here" 