# LearnPEAS

A comprehensive Linux privilege escalation enumeration script designed for learning and understanding, not just finding vulnerabilities. Every finding includes educational context explaining WHAT it is, WHY it matters, and HOW to exploit it.

## ⚠️ Important Notice

This project is not affiliated with or endorsed by the [PEASS-ng project](https://github.com/carlospolop/PEASS-ng). LearnPEAS is an independent educational tool inspired by LinPEAS. All credit for the original PEAS enumeration framework and the exceptional work on LinPEAS goes to the PEASS-ng team. I deeply respect their contributions to the security community.

LearnPEAS is currently in active development and should be considered beta software. While functional and useful for educational purposes, features are being actively refined and expanded. The tool will continue to improve with enhanced detection capabilities, additional educational content, and performance optimizations. Feedback and contributions are welcome as I work to make this the most comprehensive educational privilege escalation tool available.

## ⚠️ Legal Disclaimer

This tool is provided for educational and authorized testing purposes only.

**LearnPEAS is designed exclusively for:**
- Capture The Flag (CTF) competitions - HackTheBox, TryHackMe, and similar platforms
- Authorized penetration testing - With explicit written permission from system owners
- Educational environments - Academic courses, training labs, and personal learning
- Personal systems - Systems you own or have legal authority to test

**You must not use this tool for:**
- Unauthorized access to computer systems
- Testing systems without explicit written permission
- Any illegal activities or malicious purposes
- Circumventing security measures on systems you do not own or have permission to test

**By using LearnPEAS, you agree that:**
- You have authorization to test the target system
- You understand applicable laws in your jurisdiction
- You accept full responsibility for your actions
- The author and contributors are not liable for any misuse

Unauthorized access to computer systems is illegal in most jurisdictions and may result in criminal prosecution.

## 🎯 Who Is This For?

LearnPEAS is built for penetration testing students, CTF players, and red teamers who want to:
- Learn privilege escalation concepts deeply, not just run commands
- Understand the "why" behind each vulnerability
- Recognize patterns across different systems
- Build mental models for privilege escalation, not just checklists

Perfect for HackTheBox, TryHackMe, and OSCP preparation.

## 🔥 What Makes LearnPEAS Different?

Unlike other enumeration tools, LearnPEAS doesn't just list vulnerabilities—it teaches you about them:

```
[INFO] Sudo version: 1.9.13p3
[INFO] Checking against known sudo CVEs...

[!!! CRITICAL !!!] Sudo vulnerable to CVE-2025-32463 - Privilege escalation
[VULNERABLE] sudo < 1.9.16p1 vulnerable

[INFO] Performing quick verification check...

[LEARN] ╔════════════════════════════════════════════════════════════╗
[LEARN] ║  CVE-2025-32463 - Recent Sudo Vulnerability
[LEARN] ╚════════════════════════════════════════════════════════════╝
[LEARN] 
[LEARN] WHAT IT IS:
[LEARN]   A vulnerability in sudo versions before 1.9.16p1 that allows
[LEARN]   privilege escalation to root.
[LEARN] 
[LEARN] WHY IT EXISTS:
[LEARN]   Sudo contains a flaw in how it processes certain commands or
[LEARN]   environment variables, allowing attackers to bypass security
[LEARN]   checks and execute commands as root.
[LEARN] 
[LEARN] HOW TO EXPLOIT:
[LEARN]   1. Check exploit availability:
[LEARN]      searchsploit sudo 2025
[LEARN]   2. Download exploit:
[LEARN]      https://www.exploit-db.com/exploits/52352
[LEARN]   3. Compile and run (follow exploit instructions)
[LEARN] 
[LEARN] IMPACT: Instant root access from any user account

[OK] Sudo version checked against known CVEs

[LEARN] ═══════════════════════════════════════════════════════════════
[LEARN] GENERAL SUDO SECURITY TIPS:
[LEARN] ═══════════════════════════════════════════════════════════════
[LEARN] 
[LEARN] Why sudo is a common target:
[LEARN]   • Runs with root privileges by design
[LEARN]   • Complex codebase (150,000+ lines of C)
[LEARN]   • Handles authentication, parsing, environment variables
[LEARN]   • Backward compatibility = old code paths still exist
[LEARN]   • Written in C = memory safety issues possible
[LEARN] 
[LEARN] How to find sudo exploits:
[LEARN]   1. Check version: sudo -V | head -1
[LEARN]   2. Search exploit-db: searchsploit sudo [version]
[LEARN]   3. GitHub: Search 'sudo CVE-[year]'
[LEARN]   4. Check sudo permissions: sudo -l
[LEARN] 
[LEARN] Defense (as admin):
[LEARN]   • Keep sudo updated (sudo --version)
[LEARN]   • Principle of least privilege (specific commands, not ALL)
[LEARN]   • Avoid NOPASSWD where possible
[LEARN]   • Monitor sudo logs: /var/log/auth.log
```

**Every vulnerability type includes:**
- **WHAT:** Clear definition of the vulnerability
- **WHY:** Why it exists and why it matters
- **HOW:** Step-by-step exploitation guidance
- **Real Examples:** Actual commands you can run immediately

## 🚨 Alert System

- **[!!! CRITICAL !!!]** (Red background) - Instant privilege escalation paths
- **[🚩 CTF FLAG 🚩]** (Purple background) - CTF flag locations discovered (opt-in only)
- **[REQUIRES WORK]** (Blue background) - Exploitable but requires additional steps (e.g., password cracking)
- **[VULNERABLE]** - Exploitable misconfigurations
- **[WARNING]** - Potential security issues
- **[INFO]** - General system information
- **[LEARN]** - Educational explanations (can be disabled with `--no-explain`)
- **[OK]** - Confirmations that security controls are working

## ⚡ Core Privilege Escalation Vectors

### Instant Root Access
- **NOPASSWD sudo entries** with GTFOBins exploitation guides
- **Writable /etc/passwd, /etc/shadow, or /etc/sudoers**
- **SUID interpreters** (Python, Perl, Ruby with SUID bit)
- **Docker/LXD/Disk group membership** with container escape techniques
- **Writable systemd service files** or directories
- **Writable cron jobs** and systemd timers
- **Dangerous Linux capabilities** (CAP_SETUID, CAP_DAC_OVERRIDE, CAP_SYS_ADMIN)
- **Writable ExecStart scripts** in systemd services
- **Privileged containers** with escape paths
- **Known exploitable SUID/SGID binaries** with GTFOBins integration
- **Wildcard injection** opportunities in scripts
- **PATH hijacking** opportunities

### Requires Compilation/Download
- **Sudo version CVEs** (Baron Samedit, sudoedit bypass, runas bypass) with verification checks
- **Kernel vulnerabilities** (DirtyCOW, Dirty Pipe, PwnKit, nf_tables) with backport detection
- **Custom SUID binaries** requiring analysis and exploitation

## 📋 Comprehensive Enumeration Modules

### Core Checks
- **System fingerprinting** with exploitation context
- **Enhanced network configuration** with localhost service identification
  - Identifies MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached, RabbitMQ
  - Detects internal networks for pivot opportunities
  - Firewall detection (iptables, nftables, ufw, firewalld) with bypass techniques
  - ARP cache analysis for lateral movement targets
- **User enumeration** with anomaly detection
  - Non-root UID 0 accounts
  - Empty passwords
  - System accounts with shells
- **Running processes** with credential detection
  - Passwords in command-line arguments
  - Session hijacking (tmux/screen)
- **Comprehensive SUDO analysis** with version-specific CVE detection
  - CVE-2025-32463, CVE-2023-22809, CVE-2021-3156 (Baron Samedit)
  - CVE-2019-14287 (Runas bypass), CVE-2019-18634 (pwfeedback overflow)
  - Quick verification checks for each CVE
  - Backport detection warnings
- **SUID/SGID binaries** with GTFOBins integration and custom binary analysis
- **Linux capabilities** with detailed exploitation guides
  - Whitelisted safe capabilities (reduced false positives)
  - Binary-specific exploitation for each capability type
- **Cron jobs and systemd timers** with wildcard injection detection
- **Systemd service analysis** with comprehensive attack vectors
  - Writable service directories and files
  - Writable ExecStart scripts
  - Writable EnvironmentFile detection
  - Writable timer files
  - Services with Restart=always (persistence)
  - Relative path detection with safe binary filtering
- **Kernel exploit detection** with verification checks and backport warnings
- **Container detection & escape techniques**
  - Intelligent internet detection for LXD/LXC (online vs offline methods)
  - Complete offline exploitation with Alpine image building
  - Multiple transfer methods (wget, base64, SCP)
- **Special group membership** (docker, lxd, disk, video, sudo)
- **Writable sensitive files** (/etc/passwd, /etc/shadow, /etc/sudoers)
- **PATH hijacking opportunities**
- **Wildcard injection** in scripts (NEW - tar, rsync, chown, chmod with exploitation)

- **Cloud metadata services** (AWS EC2, Azure, GCP) with IAM role detection
- **Language-specific credential discovery**
  - .env files (Laravel, Node.js, Rails)
  - package.json, composer.json, Gemfile
  - Python virtual environments
  - ASP.NET configurations
- **Enhanced database enumeration**
  - MySQL, PostgreSQL, MongoDB, Redis with authentication testing
  - Database configuration files with credential extraction
  - Database dump file discovery
- **Web application analysis**
  - Writable web roots and upload directories
  - Configuration files with credentials (.env, wp-config.php, database.yml)
  - WordPress extended enumeration (plugins, themes, xmlrpc.php, REST API)
  - Framework detection (Laravel, Django, Node.js, Rails, Spring Boot)
  - Exposed .git directories with commit history analysis
  - Apache Tomcat manager detection
  - Spring Boot actuators
  - Web server logs with credentials
  - Existing web shell detection
- **CI/CD secret exposure**
  - Git configuration with embedded tokens
  - GitLab CI, GitHub Actions workflows
  - Jenkins credentials
  - Docker registry credentials
- **API keys and token discovery** (skippable, AWS, GitHub, Slack, Google, Stripe, JWT)
- **SMB/Samba shares** with null session testing
- **Software version checking** (exploitation-focused)
  - SUID interpreters (Python, Perl, Ruby, PHP, Node)
  - Version-specific CVEs (screen, exim, ansible)
  - Interpreters used by root (tarfile, pickle vulnerabilities)
- **Post-exploitation opportunities** (persistence, credential harvesting, lateral movement)
- **Network pivoting setup** (SSH tunneling, internal network discovery)
- **Password and credential hunting**
  - Command history for all users
  - SSH private keys
  - Configuration files
  - Mail spools
  - Backup files
- **Interesting file discovery** (skippable)
  - SUID/SGID in unusual locations
  - Recently modified sensitive files (48 hours)
  - Credential files with content validation
  - Readable sensitive configurations
- **Hidden files and directories**
- **Process monitoring** (skippable, 60-second watch for hidden cron jobs)
- **Polkit/pkexec analysis** (PwnKit CVE-2021-4034)
- **Snap package security** (devmode, classic confinement, Dirty_sock)
- **Python library path hijacking**
- **LD.SO.PRELOAD analysis**
- **AppArmor/SELinux writable profiles**
- **Tool availability** categorized by exploitation value
  - Compilers (gcc, make)
  - Exploit languages (Python, Perl, Ruby)
  - Download tools (wget, curl)
  - Pivot tools (nmap, socat, SSH)
  - Container tools (docker, kubectl) with group membership verification
  - Shell upgrade techniques (Python PTY, full interactive TTY)

## 🎮 Interactive Features

LearnPEAS respects your time with **skippable long-running checks**. Simply press **ENTER** to skip:

- **API key and token discovery** - Searches through /home, /var/www, /opt, /etc, /tmp for AWS keys, GitHub tokens, API keys
- **Process monitoring** - 60-second watch for hidden cron jobs
- **SUID binary search** - Comprehensive filesystem scan
- **Recent file search** - Modified files in last 48 hours
- **Credential file search** - SSH keys, secrets, password files

This gives you control over scan duration while maintaining thoroughness.

## 🚀 Usage

### Basic Usage
```bash
./learnpeas.sh
```

### Enable CTF Flag Hunting
```bash
./learnpeas.sh --flags
```

**Important:** Flag hunting is opt-in only. Without the `--flags` flag, the script will NOT search for or reveal CTF flags. This prevents accidental spoilers in learning environments.

### Quick Scan (Skip Slow Checks)
```bash
./learnpeas.sh --quick
```

### Command-Line Options
```
Usage: ./learnpeas.sh [OPTIONS]

Options:
  -q, --quick       Quick scan (skip some slow checks)
  -f, --flags       Enable CTF flag hunting (searches for and reveals flags)
  -v, --verbose     Verbose output
  --no-explain      Skip educational explanations
  -h, --help        Show help message
```

## 💡 How LearnPEAS Teaches You

LearnPEAS teaches you to think like a privilege escalation expert:

### Understand the "Why"
Don't just memorize commands - understand why vulnerabilities exist:
- **Sudo misconfigurations:** Why admins grant NOPASSWD and how that breaks security
- **SUID binaries:** Why programs need elevated privileges and how that creates attack surface
- **Container escapes:** Why privileged containers defeat isolation

### Pattern Recognition
Learn to recognize similar issues across different systems:
- Identify dangerous sudo entries at a glance
- Spot suspicious SUID binaries in unusual locations
- Recognize credential patterns in configuration files

### Mental Models
Build frameworks for approaching privilege escalation systematically:
- How to analyze sudo permissions methodically
- When to check for kernel exploits vs misconfigurations
- How to prioritize findings (instant root vs requires work)

### Manual Verification
Always test findings manually - don't just trust automated tools:
- Understand what each command does before running it
- Verify vulnerabilities are actually exploitable
- Learn from false positives

## 📊 Example Output

### Critical Findings Summary
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ CRITICAL FINDINGS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Found instant privilege escalation opportunities:

[!!! CRITICAL !!!] NOPASSWD vim - Instant root: sudo vim -c ':!/bin/sh'
[!!! CRITICAL !!!] Sudo vulnerable to CVE-2021-3156 (Baron Samedit)
[!!! CRITICAL !!!] DOCKER GROUP - Instant root: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
[!!! CRITICAL !!!] AWS METADATA ACCESSIBLE - Steal IAM credentials
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 📚 Typical CTF/HTB Workflow

```bash
# 1. Initial foothold - understand what you have
./learnpeas.sh

# 2. Enable flag hunting to find objectives
./learnpeas.sh --flags

# 3. Review the log file to understand each finding
cat /tmp/learnpeas_*.log

# 4. Quick enumeration without explanations (less noisy)
./learnpeas.sh --quick --no-explain
```

## ⚙️ Design Philosophy

This tool is designed for:
- **Authorized penetration testing** - With explicit written permission
- **CTF competitions** - HackTheBox, TryHackMe, similar platforms
- **Educational environments** - Academic courses, training labs
- **Personal lab systems** - Systems you own or control

**Never run on systems you don't own or have explicit permission to test.**

## ⚠️ Important Notes

### Performance Considerations
- Full enumeration provides comprehensive coverage but takes time
- API key scanning can take several minutes on systems with large filesystems
- Process monitoring runs for 60 seconds but can be skipped by pressing ENTER
- Long-running checks (API keys, process monitoring, password hunting, SUID search, recent files) can be skipped by pressing ENTER
- Use `--quick` mode if time is critical

### Stealth Considerations
This script is **not stealthy**. On monitored systems:
- Multiple `find` commands will be logged
- Process enumeration is visible in logs
- File access attempts are auditable
- Extended searches trigger IDS/HIDS alerts

For real red team engagements, use targeted manual checks instead.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional privilege escalation vectors
- Better GTFOBins integration
- More CTF-specific checks
- Performance optimizations
- Additional educational content
- More CVE coverage
- Enhanced container escape techniques

## 🙏 Acknowledgments

Inspired by:
- **[LinPEAS](https://github.com/peass-ng/PEASS-ng)** by PEASS-ng team - The gold standard for Linux enumeration
- **[GTFOBins](https://gtfobins.github.io/)** - Invaluable resource for exploitation techniques
- The HackTheBox and TryHackMe communities

### Additional Resources
- **[GTFOBins](https://gtfobins.github.io/)** - Unix binaries exploitation
- **[HackTricks](https://book.hacktricks.xyz/)** - Pentesting methodology
- **[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** - Exploit collection
- **[Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)** - Kernel exploit detection

## 📝 Final Thoughts

**Remember:** The goal is to learn and understand, not just to root boxes. Take time to read the explanations and understand why each vulnerability exists. Building deep knowledge will make you a better penetration tester.

Happy learning! 🎓🔓
