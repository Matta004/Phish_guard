# Phish Guard 🛡️  
_Real‑time phishing‑email defence for security analysts, SOC teams and curious tinkerers._

![Python](https://img.shields.io/badge/python-3.11%2B-blue) ![Status](https://img.shields.io/badge/status-active-brightgreen) ![License](https://img.shields.io/github/license/Matta004/Phish_guard)

---

## 1. Why Phish Guard?

Most e‑mail security suites are black boxes, expensive, and often miss attacks that mix social‑engineering tricks with zero‑day URLs or file types.  
I built **Phish Guard** as an open, offline‑friendly alternative that:

* Cross‑checks **every** incoming mail with outside reputation engines (**VirusTotal** & **MXToolbox**).  
* Feeds raw headers + body through a lightweight ML model (XGBoost / Random‑Forest).  
* Shows the verdict instantly in a clean Tkinter dashboard or CLI log.

The goal is simple: give defenders a single, trusted pane of glass **before** the user ever clicks _“Open attachment”_.

---

## 2. Feature Highlights

| Layer | What it does | Why it matters |
|-------|--------------|----------------|
| **IMAP Live‑Pull** | Streams messages as they arrive. | Works behind the scenes; no mail‑server plug‑ins required. |
| **URL / File Reputation** | VirusTotal hash / URL look‑ups. | Cuts false negatives on brand‑new campaigns. |
| **Domain Hygiene** | MXToolbox checks (SPF, DKIM, DMARC, rDNS, blacklist). | Exposes spoofed or shadow‑IT domains. |
| **ML Classifier** | TF‑IDF + XGBoost (96 % test accuracy) with ONNX export for portability. | Catches text‑only lures & obfuscated payloads. |
| **Threaded Scanner** | 30× faster than sequential fetch. | Keeps pace with busy mailboxes. |
| **SOC‑Style PDF Report** | One‑click export of all findings. | Evidence you can hand straight to IR / compliance. |

---

## 3. Quick Start

### 3.1 Prerequisites

* Python **3.11+**  
* A Gmail (or any IMAP) account with an **app password**  
* API key for **VirusTotal**

### 3.2 Installation

```bash
git clone https://github.com/Matta004/Phish_guard.git
cd Phish_guard

# grab every dependency in one go
pip install -r requirements.txt
```

### 3.3 Configuration

Create a `.env` (or edit `config.ini`) with:

```
IMAP_SERVER = imap.gmail.com
EMAIL_USER  = you@example.com
EMAIL_PASS  = your‑app‑password

VT_API_KEY  = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### 3.4 Run

```bash
python main.py          # GUI mode
python main.py --cli    # headless / server mode
```

### 3.5 (Optional) Download pre‑trained assets

Grab the trained model, large datasets, and sample reports from this Drive folder:  
<https://drive.google.com/drive/folders/1ye_58in6luhG33mB04-26klxRa7l6-D9?usp=sharing>

Place the contents as follows to use out‑of‑the‑box:

```
model/          → pre‑trained .joblib / .onnx files
reports/demo/   → example SOC PDFs
datasets/       → large cleaned CSVs (if you want to retrain)
```

---

## 4. Anatomy of the Project

```
Phish_guard/
├── gui/                # Tkinter front‑end
├── core/               # mail fetcher, VT & MXToolbox clients
├── model/              # saved .joblib + ONNX weights
├── reports/            # auto‑generated PDFs
├── datasets/           # cleaned & labelled e‑mails (not pushed to keep repo light)
├── scanner.log         # rotating log file
└── requirements.txt
```

---

## 5. How It Works (Under the Hood)

```
               ┌────────────┐         VT / MX requests
IMAP INBOX ───▶│  FETCHER   │─────────────────┐
               └────────────┘                 │
                     │ RAW mail               │  reputation JSON
                     ▼                        ▼
               ┌────────────┐         ┌─────────────┐
               │  PARSER    │──meta──▶│ INTEL MERGE │──▶ unified feature‑dict
               └────────────┘         └─────────────┘
                     │                                   
                     ▼ text/vector                      ▲
               ┌────────────┐  scores   ┌─────────────┐  │ one‑hot rules
               │  ML MODEL  │──────────▶│  DECISION   │──┤
               └────────────┘           └─────────────┘  │
                     │ verdict                            │
                     ▼                                   │
               ┌────────────┐                            │
               │   GUI /    │────────▶ Human             │
               │   LOG      │                            ▼
               └────────────┘                    PDF / JSON report
```

---

## 6. Training the Classifier (optional)

1. Drop new CSVs into `datasets/raw/` (columns: **text**, **label**).  
2. Run:

   ```bash
   python tools/train.py --algo xgb --out model/phish_guard.onnx
   ```

3. Check `model/metrics.json` for F1 / recall graphs.

---

## 7. Roadmap

* Outlook / Office 365 add‑in  
* Web dashboard (FastAPI + React)  
* Multilingual corpus (Arabic, French)  
* SIEM push (Elastic / Splunk HEC)

_Contributions & PRs welcome — see **CONTRIBUTING.md**._

---

## 8. Acknowledgements

Built as part of my Coventry University graduation project.  
Special thanks to **Dr Mohamed Omar** and **Mariam Abdelaati** for guidance.

---

## 9. License

MIT — see `LICENSE` for details.

---

> **Disclaimer:** Phish Guard is provided for educational and defensive purposes.  
> Use it responsibly and comply with all applicable laws and corporate policies.
