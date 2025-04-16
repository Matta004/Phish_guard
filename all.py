import imapclient
import email
from email.header import decode_header
import re
import os
import requests
import csv
import json
import onnxruntime as ort
import numpy as np
import tkinter as tk
from tkinter import messagebox
import threading
from concurrent.futures import ThreadPoolExecutor

# =======================
# Global Configurations
# =======================
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = "kambucharestaurant@gmail.com"
EMAIL_PASSWORD = "plqc mgzk ccvu opqn"  # For Gmail, use an App Password or OAuth2 tokens
VIRUSTOTAL_API_KEY = "65a0adbb6446f2dbe6effb13bb1699b0b1331e0ef4c8999a754f511ca00e5584"
PHISHING_MODEL_PATH = "phishing_email_pipeline.onnx"  # Path to your ONNX model

# =======================
# Utility Functions
# =======================
def extract_urls(text):
    """
    Extract URLs from a given text using a regex pattern.
    """
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

# =======================
# Email Fetching & Parsing
# =======================
class EmailFetcher:
    def __init__(self, imap_server, email_account, email_password):
        self.imap_server = imap_server
        self.email_account = email_account
        self.email_password = email_password
        self.connection = None

    def connect(self):
        try:
            self.connection = imapclient.IMAPClient(self.imap_server, ssl=True)
            self.connection.login(self.email_account, self.email_password)
            print("Connected to email server.")
        except Exception as e:
            print("Failed to connect:", e)

    def fetch_emails(self, folder="INBOX"):
        emails = []
        try:
            self.connection.select_folder(folder)
            messages = self.connection.search("ALL")
            for msgid in messages:
                raw_message = self.connection.fetch([msgid], ['RFC822'])[msgid][b'RFC822']
                msg = email.message_from_bytes(raw_message)
                emails.append((msgid, msg))
            return emails
        except Exception as e:
            print("Error fetching emails:", e)
            return emails

    def disconnect(self):
        if self.connection:
            self.connection.logout()

class EmailAnalyzer:
    def __init__(self):
        pass

    def parse_email(self, msg):
        """
        Parse an email message, extract subject, sender, date, URLs, attachments, and body text.
        """
        email_data = {}
        # Decode subject
        subject, encoding = decode_header(msg.get("Subject"))[0]
        if isinstance(subject, bytes):
            try:
                subject = subject.decode(encoding if encoding else "utf-8")
            except Exception:
                subject = subject.decode("utf-8", errors="ignore")
        email_data["subject"] = subject
        email_data["from"] = msg.get("From")
        email_data["date"] = msg.get("Date")
        email_data["urls"] = []
        email_data["attachments"] = []
        email_data["headers"] = dict(msg.items())
        email_data["body"] = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                # Process plain text parts (avoid attachments)
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body = part.get_payload(decode=True).decode()
                        email_data["body"] += body
                        email_data["urls"].extend(extract_urls(body))
                    except Exception as e:
                        print("Error decoding text part:", e)
                        continue
                # Process attachments
                elif "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        data = part.get_payload(decode=True)
                        email_data["attachments"].append((filename, data))
        else:
            # For non-multipart emails
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                try:
                    body = msg.get_payload(decode=True).decode()
                    email_data["body"] += body
                    email_data["urls"].extend(extract_urls(body))
                except Exception as e:
                    print("Error decoding single part email:", e)
        return email_data

    def analyze_headers(self, msg):
        """
        Check email headers for suspicious authentication results.
        """
        headers = dict(msg.items())
        suspicious = False
        reasons = []
        auth_results = headers.get("Authentication-Results", "")
        if "fail" in auth_results.lower():
            suspicious = True
            reasons.append("Authentication-Results indicates failure.")
        # Further header analysis (SPF, DKIM, DMARC) can be added here
        return suspicious, reasons

# =======================
# VirusTotal Integration
# =======================
class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def scan_url(self, url):
        """
        Check URL reputation with VirusTotal.
        """
        headers = {"x-apikey": self.api_key}
        # URL must be URL encoded for the API
        url_id = requests.utils.quote(url, safe='')
        vt_url = f"{self.base_url}/urls/{url_id}"
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return malicious > 0, data
        else:
            # If URL is not yet analyzed, you can submit it (simplified here)
            submit_url = f"{self.base_url}/urls"
            response = requests.post(submit_url, headers=headers, data={"url": url})
            if response.status_code == 200:
                return False, response.json()
            return False, {}

    def scan_file(self, file_bytes, filename):
        """
        Check file attachment reputation with VirusTotal.
        """
        headers = {"x-apikey": self.api_key}
        files = {"file": (filename, file_bytes)}
        vt_url = f"{self.base_url}/files"
        response = requests.post(vt_url, headers=headers, files=files)
        if response.status_code == 200:
            data = response.json()
            file_id = data.get("data", {}).get("id")
            if file_id:
                analysis_url = f"{self.base_url}/analyses/{file_id}"
                analysis_response = requests.get(analysis_url, headers=headers)
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                    malicious = stats.get("malicious", 0)
                    return malicious > 0, analysis_data
        return False, {}

# =======================
# AI-based Phishing Detection
# =======================
class PhishingDetector:
    def __init__(self, model_path):
        self.model_path = model_path
        try:
            self.session = ort.InferenceSession(self.model_path)
            print("Phishing model loaded successfully.")
        except Exception as e:
            print("Error loading model:", e)
            self.session = None

    def predict(self, email_data):
        """
        Prepares the input from the email data, runs the ONNX model, and maps the numeric
        output to a string classification ("Safe Email" or "Phishing Email").
        """
        input_text = email_data["subject"] + " " + email_data["body"]
        # The ONNX model expects input as a 2D array (batch size, features)
        inputs = {"text_input": np.array([[input_text]])}
        result = self.session.run(None, inputs)
        # Assuming the first output is the predicted numeric label:
        predicted_label = result[0][0]
        classification = "Safe Email" if predicted_label == 0 else "Phishing Email"
        # Set risk score based on classification (adjust thresholds as needed)
        risk_score = 0.2 if classification == "Safe Email" else 0.8
        return classification, risk_score

# =======================
# Reporting & Logging
# =======================
class ReportGenerator:
    def __init__(self, output_csv="flagged_emails.csv"):
        self.output_csv = output_csv
        self.results = []

    def add_result(self, email_info):
        self.results.append(email_info)

    def generate_csv(self):
        keys = ["id", "from", "subject", "date", "risk", "classification", "reasons",
                "score_url", "score_attachment", "score_ai", "score_cert", "total_score"]
        try:
            with open(self.output_csv, "w", newline='', encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for result in self.results:
                    writer.writerow(result)
            print(f"CSV report generated: {self.output_csv}")
        except Exception as e:
            print("Error generating CSV report:", e)

    def generate_json(self, output_json="report.json"):
        try:
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=4)
            print(f"JSON report generated: {output_json}")
        except Exception as e:
            print("Error generating JSON report:", e)

# =======================
# Optional GUI for Alerts
# =======================
class SecurityScannerGUI:
    def __init__(self, master, report_generator):
        self.master = master
        self.report_generator = report_generator
        master.title("Email Security Scanner")
        self.label = tk.Label(master, text="Email Security Scanner", font=("Arial", 16))
        self.label.pack(pady=10)
        self.scan_button = tk.Button(master, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)
        self.status_text = tk.StringVar(value="Idle")
        self.status_label = tk.Label(master, textvariable=self.status_text)
        self.status_label.pack(pady=5)

    def start_scan(self):
        self.status_text.set("Scanning...")
        threading.Thread(target=self.simulate_scan).start()

    def simulate_scan(self):
        import time
        time.sleep(2)  # Simulate scanning delay
        self.status_text.set("Scan complete. Report generated.")
        messagebox.showinfo("Scan Complete", "Email scan completed. Check the report for details.")

# =======================
# Main Application Flow
# =======================
def main():
    # Initialize components
    fetcher = EmailFetcher(IMAP_SERVER, EMAIL_ACCOUNT, EMAIL_PASSWORD)
    analyzer = EmailAnalyzer()
    vt_scanner = VirusTotalScanner(VIRUSTOTAL_API_KEY)
    phishing_detector = PhishingDetector(PHISHING_MODEL_PATH)
    report_gen = ReportGenerator()

    # Connect to the email server and fetch emails
    fetcher.connect()
    emails = fetcher.fetch_emails()
    print(f"Fetched {len(emails)} emails.")

    # Process each email concurrently using multithreading
    def process_email(item):
        msgid, msg = item
        email_info = analyzer.parse_email(msg)
        suspicious_header, header_reasons = analyzer.analyze_headers(msg)

        # Scan URLs in the email body
        url_flags = []
        for url in email_info.get("urls", []):
            is_malicious, vt_data = vt_scanner.scan_url(url)
            url_flags.append((url, is_malicious))
        
        # Scan email attachments
        attachment_flags = []
        for filename, data in email_info.get("attachments", []):
            is_malicious, vt_data = vt_scanner.scan_file(data, filename)
            attachment_flags.append((filename, is_malicious))
        
        # Run AI-based phishing detection using the ONNX model
        classification, risk_score = phishing_detector.predict(email_info)

        # Determine overall risk reasons
        risk_reasons = []
        if suspicious_header:
            risk_reasons.extend(header_reasons)
        for url, flag in url_flags:
            if flag:
                risk_reasons.append(f"Suspicious URL: {url}")
        for filename, flag in attachment_flags:
            if flag:
                risk_reasons.append(f"Suspicious attachment: {filename}")
        if classification == "Phishing Email":
            risk_reasons.append("AI model flagged email as phishing.")

        # Calculate scores for each check:
        # 1. VirusTotal URL check: if no URL is flagged, award 1 point.
        score_url = 1 if not any(flag for _, flag in url_flags) else 0
        # 2. VirusTotal attachment check: if no attachment is flagged, award 1 point.
        score_attachment = 1 if not any(flag for _, flag in attachment_flags) else 0
        # 3. AI-based phishing detection: award 1 point if classification is "Safe Email".
        score_ai = 1 if classification == "Safe Email" else 0
        # 4. Mailing certifications: award 1 point if headers do not indicate failure.
        score_cert = 1 if not suspicious_header else 0

        total_score = score_url + score_attachment + score_ai + score_cert

        overall_risk = "High" if risk_reasons else "Low"

        result = {
            "id": msgid,
            "from": email_info.get("from"),
            "subject": email_info.get("subject"),
            "date": email_info.get("date"),
            "risk": overall_risk,
            "classification": classification,
            "reasons": "; ".join(risk_reasons),
            "score_url": score_url,
            "score_attachment": score_attachment,
            "score_ai": score_ai,
            "score_cert": score_cert,
            "total_score": total_score
        }
        # Save flagged emails (or all emails if desired) to the report.
        if overall_risk == "High" or total_score < 4:
            report_gen.add_result(result)
        print(f"Processed email {msgid}: Total Score {total_score} (URL: {score_url}, Attachment: {score_attachment}, AI: {score_ai}, Cert: {score_cert})")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(process_email, emails)

    # Generate CSV and JSON reports for flagged emails
    report_gen.generate_csv()
    report_gen.generate_json()

    # Disconnect from the email server
    fetcher.disconnect()

    # Optionally, launch a simple GUI for alerts and interaction
    root = tk.Tk()
    gui = SecurityScannerGUI(root, report_gen)
    root.mainloop()

if __name__ == "__main__":
    main()
