# LearnPEAS: Privilege Escalation In-Field Educational Tool

A comprehensive Linux privilege escalation enumeration script designed for **learning and understanding**, not just finding vulnerabilities. Every finding includes educational context explaining WHAT it is, WHY it matters, and HOW to exploit it.

> **⚠️ Important Notice**
>
> This project is **not affiliated with or endorsed by** the [PEASS-ng project](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS). LearnPEAS is an independent educational tool inspired by LinPEAS. All credit for the original PEAS enumeration framework and the exceptional work on LinPEAS goes to the PEASS-ng team. I deeply respect their contributions to the security community.

## 🚧 Development Status

LearnPEAS is currently in **active development** and should be considered beta software. While functional and useful for educational purposes, features are being actively refined and expanded. The tool will continue to improve with enhanced detection capabilities, additional educational content, and performance optimizations. Feedback and contributions are welcome as we work to make this the most comprehensive educational privilege escalation tool available.

## ⚖️ Legal Disclaimer & Intended Use

**This tool is provided for educational and authorized testing purposes only.**

LearnPEAS is designed exclusively for:
- **Capture The Flag (CTF) competitions** - HackTheBox, TryHackMe, and similar platforms
- **Authorized penetration testing** - With explicit written permission from system owners
- **Educational environments** - Academic courses, training labs, and personal learning
- **Personal systems** - Systems you own or have legal authority to test

### Prohibited Uses

You **must not** use this tool for:
- Unauthorized access to computer systems
- Testing systems without explicit written permission
- Any illegal activities or malicious purposes
- Circumventing security measures on systems you do not own or have permission to test

### Your Responsibility

By using LearnPEAS, you agree that:
- You have authorization to test the target system
- You understand applicable laws in your jurisdiction
- You accept full responsibility for your actions
- The authors and contributors are not liable for any misuse

**Unauthorized access to computer systems is illegal in most jurisdictions and may result in criminal prosecution.**

## Why LearnPEAS?

LearnPEAS is built for penetration testing students, CTF players, and red teamers who want to:
- **Learn privilege escalation concepts deeply**, not just run commands
- **Understand the "why"** behind each vulnerability
- **Recognize patterns** across different systems
- **Build mental models** for privilege escalation, not just checklists

Perfect for **HackTheBox, TryHackMe, and OSCP preparation**.

## Educational Framework

Unlike other enumeration tools, LearnPEAS doesn't just list vulnerabilities—it teaches you about them:

### Example: Sudo Version Vulnerability (Baron Samedit)

```
[!!! CRITICAL !!!] Sudo vulnerable to Baron Samedit (CVE-2021-3156) - Heap overflow
[VULNERABLE] sudo < 1.9.5p2 vulnerable

╔════════════════════════════════════════════════════════════╗
║  CVE-2021-3156 - Baron Samedit (Heap Buffer Overflow)
╚════════════════════════════════════════════════════════════╝

WHAT IT IS:
  A heap-based buffer overflow in sudo that allows any local
  user to gain root WITHOUT needing a password or sudo access.
  One of the most critical sudo vulnerabilities ever found.

WHY IT EXISTS:
  When sudo processes command-line arguments, it needs to handle
  backslashes (\) specially. There's a bug in how it counts
  backslashes when a command runs in 'shell mode' (with -s or -i).

THE TECHNICAL FLAW:
  1. Sudo allocates a buffer (memory) to store the command
  2. When processing backslashes, it miscounts the length needed
  3. This causes sudo to write PAST the end of the buffer (overflow)
  4. By carefully crafting the overflow, attacker controls memory
  5. Attacker overwrites function pointers to execute their code
  6. Since sudo runs as root, the attacker's code runs as root

WHY IT'S CALLED BARON SAMEDIT:
  Play on words: 'Sudo edit' → 'Baron Samedit'
  The vulnerability is in sudoedit, a symlink to sudo

HOW TO EXPLOIT:
  1. Check if vulnerable:
     sudoedit -s / (if you get usage error = vulnerable)
  2. Download exploit:
     https://github.com/blasty/CVE-2021-3156
     https://github.com/worawit/CVE-2021-3156
  3. Compile the exploit (usually a C program):
     gcc exploit.c -o exploit
  4. Run it:
     ./exploit
  5. Get root shell

WHY IT WORKS:
  • No sudo privileges needed (any user can exploit)
  • No password required
  • Works on most Linux distributions
  • Vulnerability existed for 10+ years (since 2011)

IMPACT: Any user → Root, no credentials needed
```

### Example: Container Escape Detection

```
[WARNING] Running inside a DOCKER container

[INFO] Checking if container is privileged...
[!!! CRITICAL !!!] PRIVILEGED CONTAINER - Full host access possible
[VULNERABLE] Container is PRIVILEGED!

╔════════════════════════════════════════════════════════════╗
║  Privileged Container Escape
╚════════════════════════════════════════════════════════════╝

WHAT: Privileged containers have almost all capabilities and can 
      access host devices.

WHY IT MATTERS: The --privileged flag disables most security features.
                It's used for nested Docker, device access, etc. But it 
                allows mounting host filesystem and accessing host resources.

HOW TO EXPLOIT:
  1. List host disks: fdisk -l
  2. Mount host root: mkdir /mnt/host && mount /dev/sda1 /mnt/host
  3. Chroot to host: chroot /mnt/host /bin/bash
  4. Alternative: Access /dev/mem or /dev/kmem for direct memory access

[LEARN] Privileged escape steps:
[LEARN]   fdisk -l  # Find host disk (usually /dev/sda1 or /dev/vda1)
[LEARN]   mkdir /mnt/host
[LEARN]   mount /dev/sda1 /mnt/host
[LEARN]   chroot /mnt/host /bin/bash
[LEARN]   # You're now on the host as root
```

## Key Features

### Concept Explanations
Every vulnerability type includes a detailed breakdown:
- **WHAT**: Clear definition of the vulnerability
- **WHY**: Why it exists and why it matters
- **HOW**: Step-by-step exploitation guidance
- **Real Examples**: Actual commands you can run immediately

### High-Priority Findings with Color-Coded Alerts
- **[!!! CRITICAL !!!]** (Red background) - Instant privilege escalation paths
- **[🚩 CTF FLAG 🚩]** (Purple background) - CTF flag locations discovered
- **[VULNERABLE]** - Exploitable misconfigurations
- **[WARNING]** - Potential security issues

### Critical Finding Types
- NOPASSWD sudo entries with GTFOBins exploitation
- Writable /etc/passwd, /etc/shadow, or /etc/sudoers
- Docker/LXD/Disk group membership
- Privileged containers with escape techniques
- Dangerous Linux capabilities (CAP_SETUID, CAP_DAC_OVERRIDE)
- Writable cron directories and systemd services
- Kernel vulnerabilities (DirtyCOW, Dirty Pipe, PwnKit)
- Sudo version CVEs (Baron Samedit, sudoedit bypass, etc.)
- Container detection and escape paths

### Comprehensive Enumeration

**Core Checks:**
- System fingerprinting
- Network configuration with localhost service identification
- User enumeration
- Running processes
- SUDO permissions with version-specific CVE detection
- SUID/SGID binaries with GTFOBins integration
- Linux capabilities with detailed exploitation
- Cron jobs and systemd timers
- Kernel exploit detection
- Container detection & escape techniques
- PATH hijacking opportunities
- Special group membership (docker, lxd, disk, sudo)
- Writable sensitive files
- Password & credential hunting
- Polkit/pkexec analysis (PwnKit)

**Extended Enumeration (Enabled by default):**
- Cloud metadata services (AWS EC2, Azure, GCP)
- Language-specific credential discovery (.env, package.json, etc.)
- Enhanced database enumeration (MySQL, PostgreSQL, MongoDB, Redis)
- Web application analysis (config files, writable web roots, frameworks)
- CI/CD secret exposure (Git config, GitLab CI, GitHub Actions, Jenkins)
- SMB/Samba shares with null session detection
- Exposed .git directories with source code disclosure
- Apache Tomcat manager detection
- Spring Boot actuators
- WordPress extended enumeration
- CTF flag hunting (opt-in with --flags)

## Usage

```bash
./learnpeas.sh
```

**Note:** Extended mode is enabled by default for comprehensive enumeration including cloud metadata, databases, web applications, CI/CD secrets, and application services.

### Enable CTF Flag Hunting
```bash
./learnpeas.sh --flags
```

**Note:** Flag hunting is opt-in. Without `--flags`, the script will not search for or reveal CTF flags.

### Quick Scan
```bash
./learnpeas.sh --quick
```

### Options

```
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

## Interactive Features

### Skippable Long-Running Checks
LearnPEAS allows you to skip time-consuming checks by pressing **ENTER**:
- API key and token discovery (searches through /home, /var/www, /opt, /etc, /tmp)
- Process monitoring for hidden cron jobs (60-second watch)
- Password and credential hunting (extensive file searches)

Simply press ENTER during these checks to continue to the next enumeration section.

## Educational Philosophy

LearnPEAS teaches you to think like a privilege escalation expert:

- **Understand the "Why"**: Don't just memorize commands - understand why vulnerabilities exist
- **Pattern Recognition**: Learn to recognize similar issues across different systems
- **Mental Models**: Build frameworks for approaching privilege escalation systematically
- **Manual Verification**: Always test findings manually, don't just trust automated tools

## Example Output

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
```

## Typical CTF/HTB Workflow

```bash
# Initial foothold - understand what you have
./learnpeas.sh

# Enable flag hunting to find objectives
./learnpeas.sh --flags

# Review the log file to understand each finding
cat /tmp/learnpeas_*.log

# Targeted enumeration (quieter, less noisy)
./learnpeas.sh --quick --no-explain
```

## Output Priority

The script produces findings in priority order:
- **[!!! CRITICAL !!!]** - Instant root or near-instant privilege escalation
- **[🚩 CTF FLAG 🚩]** - CTF flag locations (only with --flags)
- **[VULNERABLE]** - Exploitable findings requiring some work
- **[WARNING]** - Potential issues worth investigating
- **[INFO]** - General information about the system
- **[LEARN]** - Educational explanations (can be disabled with `--no-explain`)
- **[OK]** - Confirmations that security controls are working

## Legal Disclaimer

This tool is designed for:
- Authorized penetration testing
- CTF competitions
- Educational environments
- Personal lab systems

**Never run on systems you don't own or have explicit permission to test.**

## Performance Notes

- Some checks can be slow on large filesystems (multiple `find /` commands)
- Extended mode adds significant runtime but provides comprehensive coverage
- Use `--quick` mode if time is critical
- Long-running checks (API keys, process monitoring) can be skipped by pressing ENTER

## Operational Security

This script is **not stealthy**. On monitored systems:
- Multiple find commands will be logged
- Process enumeration is visible
- File access attempts are auditable

For real red team engagements, use targeted manual checks instead.

## Contributing

Contributions welcome! Areas for improvement:
- Additional privilege escalation vectors
- Better GTFOBins integration
- More CTF-specific checks
- Performance optimizations
- Additional educational content
- More CVE coverage

## Credits

Inspired by:
- [LinPEAS](https://github.com/peass-ng/PEASS-ng) by PEASS-ng team - The gold standard for Linux enumeration
- [GTFOBins](https://gtfobins.github.io/) - Invaluable resource for exploitation techniques
- The HackTheBox and TryHackMe communities

## Additional Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation
- [HackTricks](https://book.hacktricks.xyz/) - Pentesting methodology
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Exploit collection
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)

---

**Remember:** The goal is to learn and understand, not just to root boxes. Take time to read the explanations and understand why each vulnerability exists. Building deep knowledge will make you a better penetration tester.

Happy learning! 🎓🔓
