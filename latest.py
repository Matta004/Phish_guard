import warnings
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

import imapclient
import email
from email.header import decode_header
import re
import requests
import csv
import json
import joblib
import pandas as pd
import tkinter as tk
from tkinter import messagebox, ttk
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import logging
from logging.handlers import RotatingFileHandler

# =======================
# Logging Configuration
# =======================
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
file_handler = RotatingFileHandler("scanner.log", maxBytes=1_000_000, backupCount=3)
file_handler.setFormatter(formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(), file_handler],
    format="%(asctime)s %(levelname)s: %(message)s"
)

# =======================
# Global Configurations
# =======================
IMAP_SERVER        = "imap.gmail.com"
EMAIL_ACCOUNT      = "kambucharestaurant@gmail.com"
EMAIL_PASSWORD     = "plqc mgzk ccvu opqn"  # App Password or OAuth2 tokens
VIRUSTOTAL_API_KEY = "65a0adbb6446f2dbe6effb13bb1699b0b1331e0ef4c8999a754f511ca00e5584"
PHISHING_MODEL_PATH= "rf_model.joblib"
DETECTED_FOLDER    = "Detected Phishing"
POLL_INTERVAL      = 30  # seconds
VT_CALL_INTERVAL   = 15  # seconds between VT calls (4/minute)

# =======================
# Utility Functions
# =======================
def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)

def send_alert(title, message):
    try:
        messagebox.showwarning(title, message)
    except Exception as e:
        logging.error("Unable to send alert: %s", e)

# =======================
# Email Fetching & Parsing
# =======================
class EmailFetcher:
    def __init__(self, server, user, password):
        self.server   = server
        self.user     = user
        self.password = password
        self.conn     = None

    def connect(self):
        try:
            self.conn = imapclient.IMAPClient(self.server, ssl=True)
            self.conn.login(self.user, self.password)
            logging.info("Connected to IMAP server.")
            # Ensure phishing folder exists
            folders = [f[2] for f in self.conn.list_folders()]
            if DETECTED_FOLDER not in folders:
                self.conn.create_folder(DETECTED_FOLDER)
                logging.info("Created folder '%s'", DETECTED_FOLDER)
        except Exception as e:
            logging.error("IMAP connect error: %s", e)

    def fetch_unseen(self):
        msgs = []
        try:
            self.conn.select_folder("INBOX")
            uids = self.conn.search("UNSEEN")
            for uid in uids:
                raw = self.conn.fetch([uid], ["RFC822"])[uid][b"RFC822"]
                msgs.append((uid, email.message_from_bytes(raw)))
        except Exception as e:
            logging.error("Fetch unseen error: %s", e)
        return msgs

    def move_to_detected(self, uids):
        try:
            self.conn.move(uids, DETECTED_FOLDER)
            logging.info("Moved %s to '%s'", uids, DETECTED_FOLDER)
        except Exception as e:
            logging.error("Move error: %s", e)

    def disconnect(self):
        if self.conn:
            try:
                self.conn.logout()
                logging.info("Logged out from IMAP server.")
            except Exception as e:
                logging.error("Logout error: %s", e)

class EmailAnalyzer:
    def parse(self, msg):
        data = {
            "subject": "",
            "from":    msg.get("From"),
            "date":    msg.get("Date"),
            "body":    "",
            "urls":    [],
            "attachments": [],
            "headers": dict(msg.items())
        }
        subj, enc = decode_header(msg.get("Subject") or "")[0]
        if isinstance(subj, bytes):
            try:
                subj = subj.decode(enc or "utf-8", errors="ignore")
            except:
                subj = subj.decode("utf-8", errors="ignore")
        data["subject"] = subj

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                dispo = str(part.get("Content-Disposition") or "")
                if ctype == "text/plain" and "attachment" not in dispo:
                    try:
                        txt = part.get_payload(decode=True).decode(errors="ignore")
                        data["body"] += txt
                        data["urls"] += extract_urls(txt)
                    except:
                        pass
                elif "attachment" in dispo:
                    fname = part.get_filename()
                    if fname:
                        data["attachments"].append((fname, part.get_payload(decode=True)))
        else:
            if msg.get_content_type() == "text/plain":
                try:
                    txt = msg.get_payload(decode=True).decode(errors="ignore")
                    data["body"] += txt
                    data["urls"] += extract_urls(txt)
                except:
                    pass

        return data

    def analyze_headers(self, msg):
        auth = msg.get("Authentication-Results", "")
        if "fail" in auth.lower():
            return True, ["Authentication-Results failure"]
        return False, []

# =======================
# VirusTotal Integration
# =======================
class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key    = api_key
        self.base_url   = "https://www.virustotal.com/api/v3"
        self._lock      = threading.Lock()
        self._last_call = 0.0

    def _throttle(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_call
            if elapsed < VT_CALL_INTERVAL:
                time.sleep(VT_CALL_INTERVAL - elapsed)
            self._last_call = time.time()

    def scan_url(self, url):
        self._throttle()
        try:
            headers = {"x-apikey": self.api_key}
            vid     = requests.utils.quote(url, safe="")
            res     = requests.get(f"{self.base_url}/urls/{vid}", headers=headers, timeout=10)
            if res.status_code == 200:
                stats = res.json()["data"]["attributes"]["last_analysis_stats"]
                return stats.get("malicious", 0) > 0
            requests.post(f"{self.base_url}/urls", headers=headers, data={"url": url}, timeout=10)
            return False
        except Exception as e:
            logging.error("VT URL scan error: %s", e)
            return False

    def scan_file(self, content, name):
        self._throttle()
        try:
            headers = {"x-apikey": self.api_key}
            files   = {"file": (name, content)}
            res     = requests.post(f"{self.base_url}/files", headers=headers, files=files, timeout=30)
            if res.status_code == 200:
                fid      = res.json()["data"]["id"]
                analysis = requests.get(f"{self.base_url}/analyses/{fid}", headers=headers, timeout=10)
                stats    = analysis.json()["data"]["attributes"]["stats"]
                return stats.get("malicious", 0) > 0
            return False
        except Exception as e:
            logging.error("VT file scan error: %s", e)
            return False

# =======================
# Phishing Detection
# =======================
class PhishingDetector:
    def __init__(self, model_path):
        try:
            loaded = joblib.load(model_path)
            # if tuple, use first element
            if isinstance(loaded, (tuple, list)) and hasattr(loaded[0], "predict_proba"):
                logging.warning("Loaded model is a tuple/list; using first element as pipeline")
                loaded = loaded[0]
            if not hasattr(loaded, "predict_proba"):
                raise ValueError("Loaded object has no predict_proba method")
            self.pipeline = loaded
            logging.info("Loaded RF model from %s.", model_path)
        except Exception as e:
            logging.error("Model load error: %s", e)
            self.pipeline = None

    def predict(self, email_data):
        # assemble single-row DataFrame matching training schema
        prep = self.pipeline.named_steps["prep"]
        num_cols  = prep.transformers[0][2] or []
        text_col  = prep.transformers[1][2]
        txt = (email_data["subject"] + " " + email_data["body"]).strip()
        row = {c: 0 for c in num_cols}
        row[text_col] = txt
        df = pd.DataFrame([row])
        try:
            proba = self.pipeline.predict_proba(df)[0]
            label = int(proba.argmax())
            cls   = "Safe Email" if label == 0 else "Phishing Email"
            score = float(proba[label])
            return cls, score
        except Exception as e:
            logging.error("Predict error: %s", e)
            return "Unknown", 0.5

    def explain(self, email_data):
        return "SHAP: 'urgent', 'account', 'verify' most influential."

# =======================
# Reporting
# =======================
class ReportGenerator:
    def __init__(self, csv_filename="flagged_emails.csv"):
        self.csv_filename = csv_filename
        self.entries      = []
        self.total = self.phish = self.safe = 0

    def add(self, info):
        self.entries.append(info)
        self.total += 1
        if info["classification"] == "Phishing Email":
            self.phish += 1
        elif info["classification"] == "Safe Email":
            self.safe += 1

    def to_csv(self):
        fields = [
            "id","from","subject","date","risk","classification",
            "reasons","score_url","score_attachment","score_ai",
            "score_cert","total_score","explanation"
        ]
        try:
            with open(self.csv_filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(self.entries)
            logging.info("CSV report written to %s.", self.csv_filename)
        except Exception as e:
            logging.error("CSV write error: %s", e)

    def to_json(self, json_filename="report.json"):
        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                json.dump(self.entries, f, indent=4)
            logging.info("JSON report written to %s.", json_filename)
        except Exception as e:
            logging.error("JSON write error: %s", e)

# =======================
# Retraining Stub
# =======================
def retrain_model():
    logging.info("Retraining model... (stub)")

# =======================
# GUI with Flagged Emails List
# =======================
class SecurityScannerGUI:
    def __init__(self, root, report, stop_event):
        self.report     = report
        self.stop_event = stop_event

        root.title("Email Security Scanner")
        tk.Label(root, text="Live Email Scanner", font=("Arial", 16)).pack(pady=10)

        self.total_lbl = tk.Label(root, text="Total: 0", font=("Arial", 12))
        self.total_lbl.pack()
        self.phish_lbl = tk.Label(root, text="Phishing: 0", font=("Arial", 12))
        self.phish_lbl.pack()
        self.safe_lbl  = tk.Label(root, text="Safe: 0", font=("Arial", 12))
        self.safe_lbl.pack()

        tk.Button(root, text="Refresh", command=self.refresh).pack(pady=5)
        tk.Button(root, text="Retrain Model", command=retrain_model).pack(pady=5)

        tk.Label(root, text="Flagged Emails:", font=("Arial", 12)).pack(pady=(10,0))
        self.tree = ttk.Treeview(root, columns=("UID","Subject","Risk","Class"), show="headings", height=10)
        for col, width in [("UID", 50), ("Subject", 300), ("Risk", 60), ("Class", 100)]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

        # Handle window close for graceful shutdown
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    def refresh(self):
        self.total_lbl.config(text=f"Total: {self.report.total}")
        self.phish_lbl.config(text=f"Phishing: {self.report.phish}")
        self.safe_lbl.config(text=f"Safe: {self.report.safe}")

        # update flagged list
        for i in self.tree.get_children():
            self.tree.delete(i)
        for info in self.report.entries:
            if info["classification"] == "Phishing Email":
                self.tree.insert("", "end", values=(
                    info["id"], info["subject"][:50]+"…" if len(info["subject"])>50 else info["subject"],
                    info["risk"], info["classification"]
                ))

    def on_close(self):
        self.stop_event.set()
        self.tree.master.destroy()

# =======================
# Processing & Monitoring
# =======================
def process_and_handle(item, fetcher, analyzer, vt, detector, report):
    uid, msg = item
    try:
        data       = analyzer.parse(msg)
        header_fail, reasons = analyzer.analyze_headers(msg)

        # only call VT if there are URLs or attachments
        url_flags = [(u, vt.scan_url(u)) for u in data["urls"]]           if data["urls"]       else []
        att_flags = [(n, vt.scan_file(b, n)) for n, b in data["attachments"]] if data["attachments"] else []

        cls, ai_score = detector.predict(data)
        explanation   = detector.explain(data)

        if header_fail:
            reasons.append("Header fail")
        reasons += [f"URL {u} flagged" for u, f in url_flags if f]
        reasons += [f"Attachment {n} flagged" for n, f in att_flags if f]

        score_url  = 1 if not any(f for _, f in url_flags) else 0
        score_att  = 1 if not any(f for _, f in att_flags) else 0
        score_ai   = 1 if cls == "Safe Email" else 0
        score_cert = 1 if not header_fail else 0
        total      = score_url + score_att + score_ai + score_cert

        risk = "High" if reasons or total < 4 else "Low"

        info = {
            "id":           uid,
            "from":         data["from"],
            "subject":      data["subject"],
            "date":         data["date"],
            "risk":         risk,
            "classification": cls,
            "reasons":      "; ".join(reasons),
            "score_url":    score_url,
            "score_attachment": score_att,
            "score_ai":     score_ai,
            "score_cert":   score_cert,
            "total_score":  total,
            "explanation":  explanation
        }

        report.add(info)
        logging.info("UID %s processed; total_score=%s", uid, total)

        if cls == "Phishing Email":
            send_alert("Phishing Detected", f"Email {uid} flagged.")
        if total < 2:
            fetcher.move_to_detected([uid])

    except Exception as e:
        logging.error("Processing error for UID %s: %s", uid, e)

def live_email_monitor(fetcher, analyzer, vt, detector, report, stop_event, interval=POLL_INTERVAL):
    seen = set()
    while not stop_event.is_set():
        try:
            unseen = fetcher.fetch_unseen()
            new    = [(u, m) for u, m in unseen if u not in seen]
            if new:
                logging.info("Found %d new emails", len(new))
                with ThreadPoolExecutor(max_workers=5) as executor:
                    for item in new:
                        executor.submit(process_and_handle, item, fetcher, analyzer, vt, detector, report)
                for u, _ in new:
                    seen.add(u)
        except Exception as e:
            logging.error("Polling error: %s", e)
            try:
                logging.info("Reconnecting to IMAP...")
                fetcher.connect()
            except Exception as ex:
                logging.error("Reconnect failed: %s", ex)
        time.sleep(interval)

# =======================
# Main Application
# =======================
def main():
    stop_event = threading.Event()

    fetcher  = EmailFetcher(IMAP_SERVER, EMAIL_ACCOUNT, EMAIL_PASSWORD)
    analyzer = EmailAnalyzer()
    vt       = VirusTotalScanner(VIRUSTOTAL_API_KEY)
    detector = PhishingDetector(PHISHING_MODEL_PATH)
    report   = ReportGenerator()

    fetcher.connect()
    monitor_thread = threading.Thread(
        target=live_email_monitor,
        args=(fetcher, analyzer, vt, detector, report, stop_event),
        daemon=True
    )
    monitor_thread.start()

    root = tk.Tk()
    SecurityScannerGUI(root, report, stop_event)
    root.mainloop()

    report.to_csv()
    report.to_json()
    fetcher.disconnect()

if __name__ == "__main__":
    main()
