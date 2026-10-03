# SENTIO — Perceive. Learn. Protect.

A 4-phase purple-team learning platform that integrates vulnerability scanning, behavioral monitoring, fuzzing, and threat intelligence correlation.

**⚠️ NOT a replacement for enterprise tools.** A lightweight, integrated environment for learning the full kill chain.

## 🚀 Quick Start (Demo Mode)

```bash
pip install -r requirements.txt

# Terminal 1: demo victim app
python demo/target_app.py

# Terminal 2: normal traffic generator
python demo/traffic_generator.py

# Terminal 3: SENTIO
python app.py

# Terminal 4: automated red team simulator
python redteam.py

# Open browser
http://localhost:5000
```

## 🔑 Configuration (Optional — Phase 1 Only)

Phase 1 (CVE scanning) works without a key but is rate-limited. For faster scans, get a free NVD API key:

1. Request one at: https://nvd.nist.gov/developers/request-an-api-key
2. Create a file named `.env` in the SENTIO folder:
   ```
   NVD_API_KEY=your_key_here
   ```
3. Restart `python app.py`

Phases 2–4 need no configuration.

## 📊 The 4 Phases

| Phase | Name | What It Does |
|-------|------|--------------|
| 1 | Scanner | Known CVE lookup via NVD, EPSS, CISA KEV |
| 2 | Monitor | Learns normal behavior, detects statistical anomalies |
| 3 | Fuzzer | Proactively finds crashes, hangs, input validation bugs |
| 4 | Nexus | One button: Detect anomalies → Correlate with fuzz findings → Generate report |

## ⚠️ Legal Disclaimer

Only test systems you own or have explicit permission to test. Unauthorized scanning or fuzzing may violate laws.

&gt; **Note:** Database files (`*.db`) are auto-created on first run and are excluded from Git via `.gitignore`.