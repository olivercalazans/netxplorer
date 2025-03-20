#!/bin/bash

# Ensure the script is executed with root privileges
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please use 'sudo' to execute it."
  exec sudo "$0" "$@"
fi



# Define variables for directories and visual indicators
HOME_DIR=$(eval echo "~$SUDO_USER")              # Home directory of the user running the script
DESTINY_DIR="$HOME_DIR/.netxplorer"              # Destination directory for the application
OK='[  \033[0;32mOK\033[0m  ] '                  # Visual indicator for successful operations
ERROR='[ \033[0;31mERROR\033[0m ]'               # Visual indicator for errors
WARNING='[\033[38;5;214mWARNING\033[0m]'         # Visual indicator for warnings



# Create a wrapper script to execute the application
printf "Creating wrapper script..."
WRAPPER_FILE="xplorer"
cat <<'EOF' > "/usr/bin/$WRAPPER_FILE"
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  exec sudo "$0" "$@"
fi
HOME_DIR=$(eval echo "~$SUDO_USER")
python3 $HOME_DIR/.netxplorer/main.py "$@"
EOF
sudo chmod +x "/usr/bin/$WRAPPER_FILE"
printf "\r${OK} Wrapper script created\n"



# Define script source and target directories
SCRIPTS_DIR=$(dirname "$(realpath "$0")")        # Directory containing the current script
SOURCE_DIR=${SCRIPTS_DIR%/*}                     # Parent directory of the script's directory
FILES=("arg_parser.py"                           # List of required Python scripts
       "bgrab.py"
       "display.py"
       "main.py"
       "netmap.py"
       "net_info.py"
       "pkt_builder.py"
       "pkt_dissector.py"
       "pkt_sender.py"
       "port_scan.py"
       "sniffer.py"
       "type_hints.py"
       )



# Create the destination directory for the application
printf "Creating directory..."
mkdir -p "$DESTINY_DIR"



# Verify if all required files exist and copy them to the destination directory
FILES_NOT_FOUND=""
for file in "${FILES[@]}"; do
    if [ ! -e "$SCRIPTS_DIR/$file" ]; then
        FILES_NOT_FOUND="$FILES_NOT_FOUND $file"
    fi
done



# If no files are missing, copy them to the destination
if [ -z "$FILES_NOT_FOUND" ]; then
    for file in "${FILES[@]}"; do
        cp "$SCRIPTS_DIR/$file" "$DESTINY_DIR"
    done
else
    printf "\n${ERROR} Files not found: $FILES_NOT_FOUND\n"
    exit 1
fi
printf "\r${OK} Directory created\n"



# Copy the LICENSE file if it exists
if [ -e "$SOURCE_DIR/LICENSE" ]; then
    cp "$SOURCE_DIR/LICENSE" "$DESTINY_DIR" 2> /dev/null
else
    printf "${WARNING} LICENSE not found\n"
fi



# Display installation completion message
echo -e "\033[0;32mINSTALLATION COMPLETED\033[0m"
