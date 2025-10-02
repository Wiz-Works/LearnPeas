# LearnPEAS - Educational Linux Privilege Escalation Enumeration

**LearnPEAS: The Red Team's Privilege Escalation Bible**

A comprehensive Linux privilege escalation enumeration script designed for **learning** and **understanding**, not just finding vulnerabilities. Every finding includes educational context explaining WHAT it is, WHY it matters, and HOW to exploit it.

## ⚠️ Disclaimer

This project is **not affiliated with or endorsed by** the [PEASS-ng project](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS). LearnPEAS is an independent tool inspired by LinPEAS, designed specifically for educational purposes. All credit for the original PEAS enumeration framework goes to the PEASS-ng team.

## 🎯 Purpose

LearnPEAS is built for penetration testing students, CTF players, and red teamers who want to:
- **Learn** privilege escalation concepts deeply, not just run commands
- **Understand** the "why" behind each vulnerability
- **Recognize** patterns across different systems
- **Build mental models** for privilege escalation, not just checklists

Perfect for **HackTheBox**, **TryHackMe**, and **OSCP** preparation.

## ⚡ Key Features

### Educational Framework
- **Concept Explanations**: Every vulnerability type includes a detailed breakdown
- **WHAT**: Clear definition of the vulnerability
- **WHY**: Why it exists and why it matters
- **HOW**: Step-by-step exploitation guidance
- **Real Examples**: Actual commands you can run immediately

### Alert System
High-priority findings with color-coded alerts:
- **[!!! CRITICAL !!!]** (Red background) - Instant privilege escalation paths
- **[🚩 CTF FLAG 🚩]** (Purple background) - CTF flag locations discovered
- **[VULNERABLE]** - Exploitable misconfigurations
- **[WARNING]** - Potential security issues

Critical findings include:
- NOPASSWD sudo entries
- Writable /etc/passwd or /etc/shadow
- Docker/LXD/Disk group membership
- Privileged containers
- Dangerous Linux capabilities
- Writable cron directories
- Kernel vulnerabilities (DirtyCOW, Dirty Pipe)
- Sudo version CVEs (Baron Samedit, sudoedit bypass, etc.)
- Polkit/pkexec vulnerabilities (PwnKit)
- Active SMB services with guest access
- Exposed .git directories with source code
- Tomcat manager with default credentials
- Cloud metadata service access (AWS/Azure/GCP)
- Writable systemd services and timers
- Python library path hijacking opportunities

### Comprehensive Coverage

**Core Enumeration:**
- System fingerprinting
- Network configuration
- User enumeration
- Running processes
- SUDO permissions analysis
- **Sudo version CVE detection** (Baron Samedit, sudoedit bypass, Runas bypass, and more)
- SUID/SGID binaries
- Linux capabilities
- Cron jobs
- Systemd services and timers
- Kernel exploit detection
- Container detection & escape
- PATH hijacking
- Special group membership
- Writable sensitive files
- Password & credential hunting
- Polkit/pkexec analysis (including PwnKit)
- Snap package security
- LD.SO.PRELOAD analysis

**Application Service Enumeration:**
- **SMB/Samba shares** (null sessions, guest access, writable shares with service validation)
- **Exposed .git directories** (source code disclosure, credential extraction, commit history)
- **Apache Tomcat manager** (default credentials, WAR upload, tomcat-users.xml)
- **Spring Boot actuators** (exposed endpoints, environment variables, heap dumps)
- **WordPress vulnerabilities** (plugins, themes, xmlrpc.php, wp-json API, config backups)

**Extended Enumeration** (Enabled by default):
- **Cloud metadata services** (AWS EC2, Azure managed identity, GCP service accounts)
- **Language-specific credential discovery** (.env, package.json, composer.json, Python venvs, Gemfiles, ASP.NET configs)
- **Enhanced database enumeration** (MySQL history, PostgreSQL, MongoDB unauthenticated access, Redis, MSSQL, database dumps)
- **Web application analysis** (config files, writable web roots, framework-specific vulnerabilities)
- **CI/CD secret exposure** (Git config tokens, GitLab CI, GitHub Actions, Jenkins credentials, Docker registry auth)
- **Post-exploitation techniques** (persistence mechanisms, lateral movement prep)
- **CTF flag hunting** (opt-in with --flags)
- **Network pivoting setup** (SSH tunneling, internal network detection)
- **Python library path hijacking** (writable sys.path directories)
- **MAC profile writability** (AppArmor/SELinux policy modification)

## 🚀 Usage

### Full Scan (Extended Mode - Default)
```bash
./learnpeas.sh
```
**Note:** Extended mode is enabled by default for comprehensive enumeration including cloud metadata, databases, web applications, CI/CD secrets, and application services.

### Enable CTF Flag Hunting
```bash
./learnpeas.sh --flags
```
**Note:** Flag hunting is opt-in. Without `--flags`, the script will not search for or reveal CTF flags.

### Quick Scan (Skip slow checks)
```bash
./learnpeas.sh --quick
```

### Without Educational Explanations
```bash
./learnpeas.sh --no-explain
```

### Combined Options
```bash
# Quick scan with flags and no explanations
./learnpeas.sh --quick --flags --no-explain
```

### Piped Execution
```bash
# Run directly from URL
curl -sL http://your-server/learnpeas.sh | bash

# With flag hunting enabled
curl -sL http://your-server/learnpeas.sh | bash -s -- --flags

# Quick scan from URL
curl -sL http://your-server/learnpeas.sh | bash -s -- --quick
```

### All Options
```bash
Usage: ./learnpeas.sh [OPTIONS]

Options:
  -q, --quick      Quick scan (skip some slow checks)
  -f, --flags      Enable CTF flag hunting (searches for and reveals flags)
  -v, --verbose    Verbose output
  --no-explain     Skip educational explanations
  -h, --help       Show help message

Note: Extended mode is ALWAYS enabled by default (cloud metadata, databases, 
web apps, CI/CD, application services, etc.)
```

## 📊 Output Examples

### Critical Finding
```
[!!! CRITICAL !!!] DOCKER GROUP - Instant root: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash

[VULNERABLE] You are in the DOCKER group!

╔═══════════════════════════════════════╗
║  UNDERSTANDING: Docker Group Exploitation
╚═══════════════════════════════════════

WHAT: Docker daemon runs as root. Docker group members can execute commands 
inside containers that run as root and can mount the host filesystem.

WHY IT MATTERS: This is by design - Docker needs root to manage containers. 
The security issue is that Docker group = root equivalent, but admins don't 
realize this when adding users.

HOW TO EXPLOIT:
  docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
  This:
    1. Mounts entire host filesystem to /mnt in container
    2. chroot into /mnt (now you're in host filesystem)
    3. Running as root inside container = root on host
```

### Sudo CVE Detection
```
[!!! CRITICAL !!!] Sudo vulnerable to Baron Samedit (CVE-2021-3156) - Heap overflow

[VULNERABLE] sudo < 1.9.5p2 vulnerable

[LEARN] Heap overflow exploit. Works on most distros.
[LEARN] GitHub: https://github.com/blasty/CVE-2021-3156
```

### Application Service Finding
```
[!!! CRITICAL !!!] SMB shares accessible with null session

[VULNERABLE] Share backup is READABLE without authentication

[LEARN] Access with: smbclient -N //127.0.0.1/backup
```

### Regular Finding
```
[VULNERABLE] Non-standard SUID binary: /usr/local/bin/custom_tool
    Owner: root | Permissions: 4755
  → Analysis steps:
      strings /usr/local/bin/custom_tool | grep -E 'system|exec|popen'
      ltrace /usr/local/bin/custom_tool 2>&1 | grep -E 'system|exec'
      Check GTFOBins for: custom_tool
```

### End of Scan Summary
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  CRITICAL FINDINGS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Found instant privilege escalation opportunities:

[!!! CRITICAL !!!] NOPASSWD vim - Instant root: sudo vim -c ':!/bin/sh'
[!!! CRITICAL !!!] Sudo vulnerable to CVE-2021-3156 (Baron Samedit)
[!!! CRITICAL !!!] DOCKER GROUP - Instant root: docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
[!!! CRITICAL !!!] AWS METADATA ACCESSIBLE - Steal IAM credentials

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚩 CTF FLAGS DISCOVERED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Flag locations found:

[🚩 CTF FLAG 🚩] USER FLAG READABLE: /home/user/user.txt
[🚩 CTF FLAG 🚩] ROOT FLAG READABLE: /root/root.txt

[INFO] Rerun with --flags to reveal the flags
```

## 🎓 Learning Philosophy

LearnPEAS teaches you to **think** like a privilege escalation expert:

1. **Understand the "Why"**: Don't just memorize commands - understand why vulnerabilities exist
2. **Pattern Recognition**: Learn to recognize similar issues across different systems
3. **Mental Models**: Build frameworks for approaching privilege escalation systematically
4. **Manual Verification**: Always test findings manually, don't just trust automated tools

LearnPEAS complements other enumeration tools like LinPEAS by focusing on education rather than speed. Use it when you want to learn and understand privilege escalation deeply, not just find quick wins.

## 🎯 Use Cases

### HTB/THM Boxes
```bash
# Initial foothold - understand what you have
./learnpeas.sh

# Enable flag hunting to find objectives
./learnpeas.sh --flags

# Review the log file to understand each finding
cat /tmp/learnpeas_*.log
```

### Red Team Engagements
```bash
# Targeted enumeration (quieter, less noisy)
./learnpeas.sh --quick --no-explain

# Note: For real engagements, consider more targeted manual checks
```

## 📝 Understanding the Output

The script produces findings in priority order:

1. **[!!! CRITICAL !!!]** - Instant root or near-instant privilege escalation
2. **[🚩 CTF FLAG 🚩]** - CTF flag locations (only with --flags)
3. **[VULNERABLE]** - Exploitable findings requiring some work
4. **[WARNING]** - Potential issues worth investigating
5. **[INFO]** - General information about the system
6. **[LEARN]** - Educational explanations (can be disabled with `--no-explain`)
7. **[OK]** - Confirmations that security controls are working

## ⚠️ Important Notes

### Intended Use
This tool is designed for:
- Authorized penetration testing
- CTF competitions
- Educational environments
- Personal lab systems

**Never run on systems you don't own or have explicit permission to test.**

### Performance Considerations
- Some checks can be slow on large filesystems (multiple `find /` commands)
- Extended mode adds significant runtime but provides comprehensive coverage
- Use `--quick` mode if time is critical

### Detection Risk
This script is **not stealthy**. On monitored systems:
- Multiple find commands will be logged
- Process enumeration is visible
- File access attempts are auditable

For real red team engagements, use targeted manual checks instead.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional privilege escalation vectors
- Better GTFOBins integration
- More CTF-specific checks
- Performance optimizations
- Additional educational content
- More CVE coverage

## 📄 License

This tool is provided for educational purposes. Use responsibly and legally.

## 🙏 Acknowledgments

Inspired by:
- **LinPEAS** by PEASS-ng team - The gold standard for Linux enumeration
- **GTFOBins** - Invaluable resource for exploitation techniques
- The **HackTheBox** and **TryHackMe** communities

## 📚 Additional Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation
- [HackTricks](https://book.hacktricks.xyz/) - Pentesting methodology
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Exploit collection
- [Linux Privilege Escalation Guide](https://github.com/mzet-/linux-exploit-suggester)

---

**Remember**: The goal is to learn and understand, not just to root boxes. Take time to read the explanations and understand why each vulnerability exists. Building deep knowledge will make you a better penetration tester.

Happy learning! 🎓🔓
