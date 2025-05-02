#!/bin/bash

# Ensure the script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please use 'sudo' to execute it."
  exec sudo "$0" "$@"
fi



# Variables
SOURCE_DIR=$(dirname "$(realpath "$0")")
ROOT_DIR=${SOURCE_DIR%/*}
DESTINY_DIR="/opt/netxplorer"
WRAPPER_FILE="xplorer"
DIRECTORIES=("$DESTINY_DIR" "config" "core" "models" "sniffing" "utils")
FILES=(
    # CONFIG ===================
    "config/__init__.py"              
    "config/arg_parser.py"
    # CORE=======================
    "core/__init__.py"
    "core/banner_grabber.py"
    "core/network_mapper.py"
    "core/port_scanner.py"
    # MODEL =====================
    "models/__init__.py"
    "models/data.py"
    # SNIFFING ==================
    "sniffing/__init__.py"
    "sniffing/packet_builder.py"
    "sniffing/packet_dissector.py"
    "sniffing/packet_sender.py"
    "sniffing/sniffer.py"
    # UTILS =====================
    "utils/__init__.py"
    "utils/network_info.py"
    "utils/type_hints.py"
    # ROOT ======================
    "__init__.py"
    "main.py"
)




# Verify if all required files exist and copy them to the destination directory
FILES_NOT_FOUND=""
for file in "${FILES[@]}"; do
    if [ ! -e "$SOURCE_DIR/$file" ]; then
        FILES_NOT_FOUND="$FILES_NOT_FOUND $file"
    fi
done




# If no files are missing, copy them to the destination
if [ -z "$FILES_NOT_FOUND" ]; then
    for dict in "${DIRECTORIES[@]}"; do
        sudo mkdir -p "$dict"
    done
    for file in "${FILES[@]}"; do
        cp "$SOURCE_DIR/$file" "$DESTINY_DIR"
    done
else
    printf "\n[ ERROR ] File(s) not found: $FILES_NOT_FOUND\n"
    exit 1
fi
printf "[  OK  ] Directory created ($DESTINY_DIR)\n"




# Create a wrapper script to execute the application
printf "Creating wrapper script..."
cat <<'EOF' > "/usr/bin/$WRAPPER_FILE"
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

python3 /opt/netxplorer/main.py "$@"
EOF
sudo chmod 710 "/usr/bin/$WRAPPER_FILE"
printf "\r[  OK  ] Wrapper script created\n"



# Copy the LICENSE file if it exists
if [ -e "$ROOT_DIR/LICENSE" ]; then
    cp "$ROOT_DIR/LICENSE" "$DESTINY_DIR" 2> /dev/null
else
    printf "[WARNING] LICENSE not found\n"
fi



# Display installation completion message
echo "INSTALLATION COMPLETED"
echo "A copy has been kept here" 
