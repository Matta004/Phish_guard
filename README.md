# Phish_Guard 🛡️

An AI-powered phishing email detection tool designed for SOC teams, system admins, and cybersecurity enthusiasts. This project integrates external threat intelligence services with machine learning to detect and classify phishing attempts in real-time.

## 📌 Overview

Phish_Guard is a comprehensive solution that:
- Analyzes incoming emails for phishing indicators.
- Cross-checks URLs and attachments using **VirusTotal**.
- Verifies domain and email security configurations using **MXToolbox**.
- Uses an AI classifier (XGBoost or Random Forest) to evaluate the email’s content, sender, and structure.
- Provides a user-friendly **Tkinter GUI** to monitor results.
- Generates **SOC-style reports** to support threat analysts and incident responders.

## 🚀 Features

- ✅ Real-time email analysis using IMAP
- 🔍 Domain and certificate checks via MXToolbox
- 🧠 AI classification model with high accuracy (96%+)
- 🧪 External file/link scanning with VirusTotal API
- 🧾 Report generation for flagged emails
- 📊 GUI-based visualization of results and logs
- 🔁 Periodic scanning and multi-threaded email checks

## 🧠 Machine Learning Pipeline

1. **Preprocessing**: Cleaned text, removed stopwords, lemmatization.
2. **Feature Extraction**: TF-IDF vectorization.
3. **Model**: XGBoost or Random Forest classifier trained on 24K+ email samples.
4. **Accuracy**: Achieved up to **96% accuracy** on test data.
5. **ONNX Conversion**: Model exported to ONNX for integration and portability.

## 🧰 Tech Stack

- **Language**: Python 3.11+
- **Libraries**: 
  - `scikit-learn`, `xgboost`, `joblib`, `tkinter`
  - `imapclient`, `email`, `requests`, `tqdm`, `threading`
- **Threat Intelligence**:
  - VirusTotal API
  - MXToolbox (SMTP, DMARC, SPF, DKIM checks)

## 📦 Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/Matta004/Phish_guard.git
   cd Phish_guard
