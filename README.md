# LearnPEAS - Educational Linux Privilege Escalation Enumeration

**TeachPEAS: The Red Team's Privilege Escalation Bible**

A comprehensive Linux privilege escalation enumeration script designed for **learning** and **understanding**, not just finding vulnerabilities. Every finding includes educational context explaining WHAT it is, WHY it matters, and HOW to exploit it.

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

### Critical Finding Alerts
High-priority findings marked with bright `[!!! CRITICAL !!!]` alerts:
- NOPASSWD sudo entries
- Writable /etc/passwd or /etc/shadow
- Docker/LXD/Disk group membership
- Privileged containers
- Dangerous Linux capabilities
- Writable cron directories
- Kernel vulnerabilities (DirtyCOW, Dirty Pipe)
- And more...

### Comprehensive Coverage

**Core Enumeration:**
- System fingerprinting
- Network configuration
- User enumeration
- Running processes
- SUDO permissions analysis
- SUID/SGID binaries
- Linux capabilities
- Cron jobs
- Systemd services
- Kernel exploit detection
- Container detection & escape
- PATH hijacking
- Special group membership
- Writable sensitive files
- Password & credential hunting

**Extended Enumeration** (`--extended` flag):
- Cloud metadata services (AWS/Azure/GCP)
- Language-specific credential discovery (.env, package.json, composer.json)
- Enhanced database enumeration (MySQL, PostgreSQL, MongoDB, Redis)
- Web application analysis
- CI/CD secret exposure (Git, Jenkins, GitLab)
- Post-exploitation techniques
- CTF flag hunting
- Network pivoting setup

### Smart Design
- Avoids false positives with whitelist filtering
- Distinguishes legitimate vs. dangerous findings
- GTFOBins integration for exploitation guidance
- Logs everything to `/tmp/teachpeas_*.log` for reference


## 🚀 Usage

### Full Scan (Default - Extended Mode Enabled)
```bash
./learnpeas.sh
```
**Note:** Extended mode is ON by default for comprehensive enumeration.

### Quick Scan (Skip slow checks)
```bash
./learnpeas.sh --quick
```

### Without Educational Explanations
```bash
./learnpeas.sh --no-explain
```

### Piped Execution
```bash
# Run directly from URL (extended mode by default)
curl -sL http://your-server/learnpeas.sh | bash

# Quick scan from URL
curl -sL http://your-server/learnpeas.sh | bash -s -- --quick
```

### All Options
```bash
Options:
  -q, --quick      Quick scan (skip some slow checks)
  -v, --verbose    Verbose output
  --no-explain     Skip educational explanations
  -h, --help       Show help message

Note: Extended mode is ALWAYS enabled by default (cloud metadata, databases, 
web apps, CI/CD, CTF flags, etc.)
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

### Regular Finding
```
[VULNERABLE] Non-standard SUID binary: /usr/local/bin/custom_tool
    Owner: root | Permissions: 4755
  → Analysis steps:
      strings /usr/local/bin/custom_tool | grep -E 'system|exec|popen'
      ltrace /usr/local/bin/custom_tool 2>&1 | grep -E 'system|exec'
      Check GTFOBins for: custom_tool
```

## 🎓 Learning Philosophy

LearnPEAS teaches you to **think** like a privilege escalation expert:

1. **Understand the "Why"**: Don't just memorize commands - understand why vulnerabilities exist
2. **Pattern Recognition**: Learn to recognize similar issues across different systems
3. **Mental Models**: Build frameworks for approaching privilege escalation systematically
4. **Manual Verification**: Always test findings manually, don't just trust automated tools

## 🔍 What Makes This Different?

| Feature | LinPEAS | LearnPEAS |
|---------|---------|-----------|
| Output Volume | High | Low but structured & explained |
| Learning Focus | Low | **Very High** |
| Exploitation Guidance | Minimal | **Detailed step-by-step** |
| CTF-Specific Features | Limited | **Flag hunting, cloud metadata, etc.** |
| Educational Concepts | None | **Full WHAT/WHY/HOW framework** |

LearnPEAS is **not a replacement** for LinPEAS - it's a **learning companion**. Use LinPEAS for speed, use LearnPEAS to understand what you found and why it matters.

## 🎯 Use Cases

### HTB/THM Boxes
```bash
# Initial foothold - understand what you have
./learnpeas.sh

# Review the log file to understand each finding
cat /tmp/teachpeas_*.log
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
2. **[VULNERABLE]** - Exploitable findings requiring some work
3. **[WARNING]** - Potential issues worth investigating
4. **[INFO]** - General information about the system
5. **[LEARN]** - Educational explanations (can be disabled with `--no-explain`)
6. **[OK]** - Confirmations that security controls are working


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
