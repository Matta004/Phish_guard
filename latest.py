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
from tkinter import messagebox, ttk, filedialog
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import logging
from logging.handlers import RotatingFileHandler
from html import unescape
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

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
# Default configurations
DEFAULT_CONFIG = {
    'imap_server': "imap.gmail.com",
    'email_account': "kambucharestaurant@gmail.com",
    'email_password': "plqc mgzk ccvu opqn",
    'vt_api_key': "65a0adbb6446f2dbe6effb13bb1699b0b1331e0ef4c8999a754f511ca00e5584",
    'poll_interval': 30,
    'vt_interval': 15,
    'detected_folder': "Detected Phishing",
    'phishing_model_path': "rf_model.joblib"
}

# Load configurations from file or use defaults
def load_config():
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            return {**DEFAULT_CONFIG, **config}  # Merge with defaults
    except (FileNotFoundError, json.JSONDecodeError):
        return DEFAULT_CONFIG

# Load configurations
config = load_config()
IMAP_SERVER = config['imap_server']
EMAIL_ACCOUNT = config['email_account']
EMAIL_PASSWORD = config['email_password']
VIRUSTOTAL_API_KEY = config['vt_api_key']
POLL_INTERVAL = config['poll_interval']
VT_CALL_INTERVAL = config['vt_interval']
DETECTED_FOLDER = config['detected_folder']
PHISHING_MODEL_PATH = config['phishing_model_path']

# =======================
# Utility Functions
# =======================

def extract_urls(text):
    return re.findall(r'https?://[^\s"\'()]+', text)

def strip_html(html):
    text = re.sub(r'<[^>]+>', '', html)
    return unescape(text)

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
        self.server = server
        self.user = user
        self.password = password
        self.conn = None
        self.max_retries = 3
        self.retry_delay = 5  # seconds

    def connect(self):
        """Connect to IMAP server with retry logic"""
        for attempt in range(self.max_retries):
            try:
                if self.conn:
                    try:
                        self.conn.logout()
                    except:
                        pass
                    self.conn = None

                self.conn = imapclient.IMAPClient(self.server, ssl=True, timeout=30)
                self.conn.login(self.user, self.password)
                logging.info("Connected to IMAP server.")
                
                # Create detected folder if it doesn't exist
                folders = [f[2] for f in self.conn.list_folders()]
                if DETECTED_FOLDER not in folders:
                    self.conn.create_folder(DETECTED_FOLDER)
                    logging.info("Created folder '%s'", DETECTED_FOLDER)
                return True
            except Exception as e:
                logging.error(f"IMAP connect attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    logging.error("Failed to connect to IMAP server after %d attempts", self.max_retries)
                    return False

    def fetch_unseen(self):
        """Fetch unseen emails with reconnection logic"""
        for attempt in range(self.max_retries):
            try:
                if not self.conn:
                    if not self.connect():
                        return None
                
                # Select folder without marking as read
                self.conn.select_folder("INBOX")
                # Search for unseen emails without marking them
                uids = self.conn.search("UNSEEN")
                msgs = []
                
                for uid in uids:
                    try:
                        # Fetch without marking as seen
                        raw = self.conn.fetch([uid], ['RFC822', 'FLAGS'])[uid]
                        msgs.append((uid, email.message_from_bytes(raw[b'RFC822'])))
                    except Exception as e:
                        logging.error(f"Error fetching message {uid}: {e}")
                        continue
                
                return msgs
            except Exception as e:
                logging.error(f"Fetch unseen attempt {attempt + 1} failed: {e}")
                self.conn = None  # Force reconnection
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    logging.error("Failed to fetch emails after %d attempts", self.max_retries)
                    return None

    def move_to_detected(self, uids):
        """Move emails to detected folder with error handling"""
        if not uids:
            return
            
        for attempt in range(self.max_retries):
            try:
                if not self.conn:
                    if not self.connect():
                        return
                
                self.conn.move(uids, DETECTED_FOLDER)
                logging.info("Moved %s to '%s'", uids, DETECTED_FOLDER)
                return
            except Exception as e:
                logging.error(f"Move attempt {attempt + 1} failed: {e}")
                self.conn = None  # Force reconnection
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    logging.error("Failed to move emails after %d attempts", self.max_retries)

    def disconnect(self):
        """Safely disconnect from IMAP server"""
        if self.conn:
            try:
                self.conn.logout()
                logging.info("Logged out from IMAP server.")
            except Exception as e:
                logging.error("Logout error: %s", e)
            finally:
                self.conn = None

    def mark_as_unread(self, uids):
        """Mark emails as unread"""
        if not uids:
            return
            
        for attempt in range(self.max_retries):
            try:
                if not self.conn:
                    if not self.connect():
                        return
                
                self.conn.select_folder("INBOX")
                self.conn.remove_flags(uids, ['\\Seen'])
                logging.info("Marked emails %s as unread", uids)
                return
            except Exception as e:
                logging.error(f"Mark unread attempt {attempt + 1} failed: {e}")
                self.conn = None  # Force reconnection
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                else:
                    logging.error("Failed to mark emails as unread after %d attempts", self.max_retries)

# =======================
# Email Analysis
# =======================
class EmailAnalyzer:
    def parse(self, msg):
        data = {'subject':'', 'from':msg.get('From'), 'date':msg.get('Date'),
                'body':'', 'urls':[], 'attachments':[], 'headers':dict(msg.items())}
        subj, enc = decode_header(msg.get('Subject') or '')[0]
        if isinstance(subj, bytes):
            subj = subj.decode(enc or 'utf-8', errors='ignore')
        data['subject'] = subj

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                dispo = str(part.get('Content-Disposition') or '')
                if ctype == 'text/plain' and 'attachment' not in dispo:
                    try:
                        txt = part.get_payload(decode=True).decode(errors='ignore')
                        data['body'] += txt
                        data['urls'] += extract_urls(txt)
                    except:
                        pass
                elif ctype == 'text/html' and 'attachment' not in dispo:
                    try:
                        html = part.get_payload(decode=True).decode(errors='ignore')
                        txt  = strip_html(html)
                        data['body'] += txt
                        data['urls'] += extract_urls(html)
                    except:
                        pass
                elif 'attachment' in dispo:
                    fname = part.get_filename()
                    if fname:
                        data['attachments'].append((fname, part.get_payload(decode=True)))
        else:
            if msg.get_content_type() == 'text/plain':
                try:
                    txt = msg.get_payload(decode=True).decode(errors='ignore')
                    data['body'] += txt
                    data['urls'] += extract_urls(txt)
                except:
                    pass
        return data

    def analyze_headers(self, msg):
        """Analyze email headers for authentication and security checks"""
        reasons = []
        auth_failures = 0
        
        # Get Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        
        # Check SPF
        spf_result = self._extract_auth_result(auth_results, 'spf')
        if spf_result:
            if 'fail' in spf_result.lower():
                reasons.append('SPF authentication failed')
                auth_failures += 1
            elif 'softfail' in spf_result.lower():
                reasons.append('SPF soft fail (suspicious)')
                auth_failures += 0.5
        else:
            reasons.append('No SPF authentication results found')
            auth_failures += 0.5

        # Check DKIM
        dkim_result = self._extract_auth_result(auth_results, 'dkim')
        if dkim_result:
            if 'fail' in dkim_result.lower():
                reasons.append('DKIM signature verification failed')
                auth_failures += 1
            elif 'neutral' in dkim_result.lower():
                reasons.append('DKIM neutral result (suspicious)')
                auth_failures += 0.5
        else:
            reasons.append('No DKIM signature found')
            auth_failures += 0.5

        # Check DMARC
        dmarc_result = self._extract_auth_result(auth_results, 'dmarc')
        if dmarc_result:
            if 'fail' in dmarc_result.lower():
                reasons.append('DMARC authentication failed')
                auth_failures += 1
            elif 'softfail' in dmarc_result.lower():
                reasons.append('DMARC soft fail (suspicious)')
                auth_failures += 0.5
        else:
            reasons.append('No DMARC authentication results found')
            auth_failures += 0.5

        # Check Received-SPF header
        received_spf = msg.get('Received-SPF', '')
        if received_spf:
            if 'fail' in received_spf.lower():
                reasons.append('Received-SPF header indicates failure')
                auth_failures += 0.5

        # Check Return-Path vs From
        return_path = msg.get('Return-Path', '')
        from_addr = msg.get('From', '')
        if return_path and from_addr:
            # Extract email addresses
            return_email = self._extract_email(return_path)
            from_email = self._extract_email(from_addr)
            if return_email and from_email and return_email.lower() != from_email.lower():
                reasons.append('Return-Path and From addresses do not match')
                auth_failures += 0.5

        # Check for suspicious headers
        suspicious_headers = [
            'X-Originating-IP',
            'X-Forwarded-For',
            'X-Forwarded-By',
            'X-Originating-Email'
        ]
        for header in suspicious_headers:
            if msg.get(header):
                reasons.append(f'Suspicious header found: {header}')
                auth_failures += 0.5

        # Determine overall authentication status
        if auth_failures >= 2:
            return True, reasons  # Likely phishing
        elif auth_failures >= 1:
            return True, reasons  # Suspicious
        else:
            return False, reasons  # Likely legitimate

    def _extract_auth_result(self, auth_results, auth_type):
        """Extract authentication result for a specific type from Authentication-Results header"""
        if not auth_results:
            return None
            
        # Look for pattern like: auth_type=result
        pattern = rf'{auth_type}=([^\s;]+)'
        match = re.search(pattern, auth_results, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_email(self, header_value):
        """Extract email address from header value"""
        # Common email pattern
        pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        match = re.search(pattern, header_value)
        if match:
            return match.group(0)
        return None

# =======================
# VirusTotal Integration
# =======================
class VirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        self.last_request_time = 0
        self.min_request_interval = 15  # Minimum seconds between requests to respect rate limits
        self.max_retries = 3  # Maximum number of retries for failed requests
        self.analysis_wait_time = 30  # Seconds to wait for analysis completion

    def _wait_for_rate_limit(self):
        """Ensure we respect rate limits by waiting if necessary"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        self.last_request_time = time.time()

    def _make_request(self, url, method='GET', files=None, retry_count=0):
        """Make a request to VirusTotal API with proper error handling and retries"""
        try:
            self._wait_for_rate_limit()
            if method == 'GET':
                response = requests.get(url, headers=self.headers, timeout=30)
            else:
                response = requests.post(url, headers=self.headers, files=files, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:  # Rate limit
                logging.warning("VirusTotal rate limit reached, waiting...")
                time.sleep(60)  # Wait a minute before retrying
                if retry_count < self.max_retries:
                    return self._make_request(url, method, files, retry_count + 1)
                return None
            elif response.status_code == 404:  # Not found
                logging.warning(f"Resource not found: {url}")
                return None
            else:
                logging.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                if retry_count < self.max_retries:
                    time.sleep(5)  # Wait before retry
                    return self._make_request(url, method, files, retry_count + 1)
                return None
        except requests.exceptions.RequestException as e:
            logging.error(f"VirusTotal request error: {e}")
            if retry_count < self.max_retries:
                time.sleep(5)  # Wait before retry
                return self._make_request(url, method, files, retry_count + 1)
            return None

    def _submit_url_for_analysis(self, url):
        """Submit a URL for analysis and return the analysis ID"""
        try:
            # Submit URL for analysis
            submit_url = f"{self.base_url}/urls"
            # Properly format the URL data
            submit_data = {"url": url}
            submit_result = self._make_request(
                submit_url,
                method='POST',
                files={'url': (None, url)}  # Correct format for URL submission
            )
            
            if not submit_result:
                logging.error("Failed to submit URL for analysis")
                return None
                
            # Extract analysis ID
            analysis_id = submit_result.get("data", {}).get("id")
            if not analysis_id:
                logging.error("No analysis ID received")
                return None
                
            return analysis_id
        except Exception as e:
            logging.error(f"Error submitting URL for analysis: {e}")
            return None

    def _get_analysis_results(self, analysis_id):
        """Get analysis results for a given analysis ID"""
        try:
            analysis_url = f"{self.base_url}/analyses/{analysis_id}"
            result = self._make_request(analysis_url)
            
            if not result:
                return None
                
            # Check if analysis is complete
            status = result.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return result
            elif status == "queued":
                return None  # Analysis still in progress
            else:
                logging.error(f"Analysis failed with status: {status}")
                return None
        except Exception as e:
            logging.error(f"Error getting analysis results: {e}")
            return None

    def scan_url(self, url):
        """Scan a URL and return detailed results"""
        try:
            # First try to get existing analysis
            url_id = requests.utils.quote(url, safe='')
            result = self._make_request(f"{self.base_url}/urls/{url_id}")
            
            if not result:
                # If no existing analysis, submit for new analysis
                analysis_id = self._submit_url_for_analysis(url)
                if not analysis_id:
                    return {'malicious': False, 'error': 'Failed to submit URL for analysis'}
                
                # Wait for analysis to complete
                start_time = time.time()
                while time.time() - start_time < self.analysis_wait_time:
                    result = self._get_analysis_results(analysis_id)
                    if result:
                        break
                    time.sleep(5)  # Wait before checking again
                
                if not result:
                    return {'malicious': False, 'error': 'Analysis timed out'}
                
                # Get the final URL analysis
                result = self._make_request(f"{self.base_url}/urls/{url_id}")
                if not result:
                    return {'malicious': False, 'error': 'Failed to get final analysis'}
            
            data = result.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                'malicious': stats.get("malicious", 0) > 0,
                'harmless': stats.get("harmless", 0),
                'suspicious': stats.get("suspicious", 0),
                'undetected': stats.get("undetected", 0),
                'total_engines': sum(stats.values()),
                'last_analysis_date': attributes.get("last_analysis_date"),
                'categories': attributes.get("categories", [])
            }
        except Exception as e:
            logging.error(f"URL scan error: {e}")
            return {'malicious': False, 'error': str(e)}

    def scan_file(self, file_bytes, filename):
        """Scan a file and return detailed results"""
        try:
            # First upload the file
            files = {"file": (filename, file_bytes)}
            upload_result = self._make_request(f"{self.base_url}/files", method='POST', files=files)
            
            if not upload_result:
                return {'malicious': False, 'error': 'File upload failed'}
            
            file_id = upload_result.get("data", {}).get("id")
            if not file_id:
                return {'malicious': False, 'error': 'No file ID received'}
            
            # Wait for analysis to complete
            time.sleep(5)  # Wait for initial analysis
            
            # Get analysis results
            analysis_result = self._make_request(f"{self.base_url}/analyses/{file_id}")
            
            if not analysis_result:
                return {'malicious': False, 'error': 'Analysis request failed'}
            
            data = analysis_result.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("stats", {})
            
            return {
                'malicious': stats.get("malicious", 0) > 0,
                'harmless': stats.get("harmless", 0),
                'suspicious': stats.get("suspicious", 0),
                'undetected': stats.get("undetected", 0),
                'total_engines': sum(stats.values()),
                'analysis_date': attributes.get("date"),
                'analysis_id': file_id
            }
        except Exception as e:
            logging.error(f"File scan error: {e}")
            return {'malicious': False, 'error': str(e)}

# =======================
# Phishing Detection
# =======================
class PhishingDetector:
    def __init__(self, model_path):
        self.model_path = model_path
        try:
            loaded = joblib.load(model_path)
            
            # Handle case where loaded object is a tuple/list
            if isinstance(loaded, (tuple, list)):
                # Try to find the model in the tuple/list
                for item in loaded:
                    if hasattr(item, 'predict'):
                        self.pipeline = item
                        logging.info("Found model in tuple/list")
                        break
                else:
                    raise ValueError("No model object found in loaded tuple/list")
            else:
                self.pipeline = loaded
                
            if not hasattr(self.pipeline, 'predict'):
                raise ValueError("Loaded object is not a valid scikit-learn pipeline")
            logging.info("Phishing model pipeline loaded successfully")
        except Exception as e:
            logging.error(f"Failed to load phishing model: {e}")
            self.pipeline = None

    def _prepare_features(self, email_data):
        """Prepare input features in the format expected by the pipeline"""
        # Combine subject and body with proper spacing
        email_text = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
        
        # Create a DataFrame with the same structure as training data
        df = pd.DataFrame({
            'Email_Text': [email_text]
        })
        
        return df

    def predict(self, email_data):
        try:
            if not self.pipeline:
                return "Error", 0.0
            
            # Prepare input data
            df = self._prepare_features(email_data)
            
            # Get probability scores
            prob = self.pipeline.predict_proba(df)[0][1]  # Probability of being phishing
            
            # Adjust confidence thresholds
            PHISHING_THRESHOLD = 0.4  # Lower threshold to catch more phishing emails
            SAFE_THRESHOLD = 0.6      # Higher threshold to be more certain about safe emails
            
            # Adjust confidence scoring
            if prob > SAFE_THRESHOLD:
                return "Safe Email", prob
            elif prob < PHISHING_THRESHOLD:
                return "Phishing Email", (1 - prob)
            else:
                # For uncertain cases, be more conservative and mark as phishing
                return "Phishing Email", (1 - prob)
            
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return "Error", 0.0

    def explain(self, email_data):
        try:
            if not self.pipeline:
                return "Model not loaded"
            
            # Prepare input data
            df = self._prepare_features(email_data)
            
            # Get probability scores
            prob = self.pipeline.predict_proba(df)[0][1]
            
            # Generate explanation based on adjusted thresholds
            if prob > 0.6:
                return "Very likely to be safe"
            elif prob > 0.4:
                return "Potentially suspicious"
            else:
                return "Likely phishing"
            
        except Exception as e:
            logging.error(f"Explanation error: {e}")
            return "Error generating explanation"

# =======================
# Report Generation
# =======================
class ReportGenerator:
    def __init__(self):
        self.entries = []
        self.total = 0
        self.phish = 0
        self.safe = 0

    def add(self, info):
        self.entries.append(info)
        self.total += 1
        if info['classification'] == 'Phishing Email':
            self.phish += 1
        else:
            self.safe += 1

    def generate_csv(self, filename="flagged_emails.csv"):
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.entries[0].keys() if self.entries else [])
                writer.writeheader()
                writer.writerows(self.entries)
            logging.info(f"Report saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to generate CSV report: {e}")

    def generate_json(self, filename="report.json"):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.entries, f, indent=4)
            logging.info(f"Report saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to generate JSON report: {e}")

# =======================
# GUI
# =======================
class SecurityScannerGUI:
    def __init__(self, root, report, stop_event):
        self.report = report
        self.stop_event = stop_event
        self.root = root
        self.auto_refresh_interval = 5000  # 5 seconds
        self.auto_refresh_id = None  # Store the after ID
        self.setup_gui()
        self.setup_menu()
        self.setup_status_bar()
        self.start_auto_refresh()
        self.refresh()

    def start_auto_refresh(self):
        """Start the auto-refresh timer"""
        if self.auto_refresh_var.get() and not self.stop_event.is_set():
            self.refresh()
            # Store the after ID so we can cancel it if needed
            self.auto_refresh_id = self.root.after(self.auto_refresh_interval, self.start_auto_refresh)

    def setup_gui(self):
        self.root.title('Email Security Scanner')
        self.root.geometry('1200x700')
        self.root.minsize(1000, 600)

        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create left and right frames
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(10, 0))

        # Header in left frame
        header_frame = ttk.Frame(left_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text='Email Security Scanner', font=('Arial', 16, 'bold')).pack(side=tk.LEFT)
        
        # Stats frame
        stats_frame = ttk.Frame(header_frame)
        stats_frame.pack(side=tk.RIGHT)
        
        self.total_lbl = ttk.Label(stats_frame, text='Total: 0', font=('Arial', 10))
        self.total_lbl.pack(side=tk.RIGHT, padx=5)
        self.phish_lbl = ttk.Label(stats_frame, text='Phishing: 0', font=('Arial', 10))
        self.phish_lbl.pack(side=tk.RIGHT, padx=5)
        self.safe_lbl = ttk.Label(stats_frame, text='Safe: 0', font=('Arial', 10))
        self.safe_lbl.pack(side=tk.RIGHT, padx=5)

        # Control buttons
        control_frame = ttk.Frame(left_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(control_frame, text='Refresh', command=self.refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text='Export CSV', command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text='Export JSON', command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text='Settings', command=self.show_settings).pack(side=tk.LEFT, padx=5)

        # Add auto-refresh controls
        refresh_control_frame = ttk.Frame(control_frame)
        refresh_control_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Label(refresh_control_frame, text="Auto-refresh:").pack(side=tk.LEFT, padx=2)
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(refresh_control_frame, variable=self.auto_refresh_var, 
                       command=self.toggle_auto_refresh).pack(side=tk.LEFT, padx=2)
        
        ttk.Label(refresh_control_frame, text="Interval (s):").pack(side=tk.LEFT, padx=2)
        self.interval_var = tk.StringVar(value="5")
        interval_entry = ttk.Entry(refresh_control_frame, textvariable=self.interval_var, width=3)
        interval_entry.pack(side=tk.LEFT, padx=2)
        interval_entry.bind('<Return>', self.update_interval)

        # Treeview in left frame
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        cols = ('UID', 'Subject', 'From', 'Date', 'Risk', 'Class', 'URL', 'Att', 'AI', 'Cert')
        self.tree = ttk.Treeview(tree_frame, columns=cols, show='headings', height=15)
        
        # Configure columns
        col_widths = {
            'UID': 50, 'Subject': 200, 'From': 150, 'Date': 120,
            'Risk': 60, 'Class': 100, 'URL': 50, 'Att': 50,
            'AI': 50, 'Cert': 50
        }
        
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths[col], anchor='w')
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        
        # Configure tags for color coding
        self.tree.tag_configure('phishing', background='#ffdddd')  # Light red
        self.tree.tag_configure('safe', background='#ddffdd')      # Light green
        
        self.tree.bind('<Double-1>', self.show_details)
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

        # Chart frame in right frame
        chart_frame = ttk.LabelFrame(right_frame, text="Email Classification Distribution", padding="5")
        chart_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create figure for the chart
        self.fig, self.ax = plt.subplots(figsize=(4, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize empty chart
        self.update_chart()

    def update_chart(self):
        try:
            self.ax.clear()
            
            # Prepare data
            categories = ['Safe', 'Phishing']
            counts = [self.report.safe, self.report.phish]
            colors = ['#4CAF50', '#F44336']  # Green and Red
            
            # Create bar chart
            bars = self.ax.bar(categories, counts, color=colors)
            
            # Add value labels on top of bars
            for bar in bars:
                height = bar.get_height()
                self.ax.text(bar.get_x() + bar.get_width()/2., height,
                            f'{int(height)}',
                            ha='center', va='bottom')
            
            # Customize chart
            self.ax.set_title('Email Classification Distribution')
            self.ax.set_ylabel('Number of Emails')
            self.ax.grid(axis='y', linestyle='--', alpha=0.7)
            
            # Adjust layout
            plt.tight_layout()
            
            # Update canvas
            self.canvas.draw()
        except Exception as e:
            logging.error(f"Error updating chart: {e}")

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export CSV", command=self.export_csv)
        file_menu.add_command(label="Export JSON", command=self.export_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", command=self.refresh)
        view_menu.add_command(label="Settings", command=self.show_settings)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def setup_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_auto_refresh(self):
        """Toggle auto-refresh on/off"""
        if self.auto_refresh_var.get():
            self.start_auto_refresh()
        else:
            # Cancel any existing auto-refresh
            if self.auto_refresh_id:
                self.root.after_cancel(self.auto_refresh_id)
                self.auto_refresh_id = None
            self.status_var.set("Auto-refresh disabled")

    def update_interval(self, event=None):
        """Update the auto-refresh interval"""
        try:
            interval = int(self.interval_var.get())
            if interval < 1:
                interval = 1
            self.auto_refresh_interval = interval * 1000  # Convert to milliseconds
            
            # If auto-refresh is on, restart it with new interval
            if self.auto_refresh_var.get():
                if self.auto_refresh_id:
                    self.root.after_cancel(self.auto_refresh_id)
                self.start_auto_refresh()
            
            self.status_var.set(f"Auto-refresh interval set to {interval} seconds")
        except ValueError:
            self.status_var.set("Invalid interval value")
            self.interval_var.set("5")

    def refresh(self):
        try:
            self.status_var.set("Refreshing...")
            self.root.update()
            
            # Update statistics
            self.total_lbl.config(text=f'Total: {self.report.total}')
            self.phish_lbl.config(text=f'Phishing: {self.report.phish}')
            self.safe_lbl.config(text=f'Safe: {self.report.safe}')
            
            # Update email list
            for i in self.tree.get_children():
                self.tree.delete(i)
            
            for info in self.report.entries:
                # Format classification with confidence
                classification = f"{info['classification']} ({info.get('confidence', 'N/A')})"
                
                vals = (
                    info['id'],
                    (info['subject'][:47] + '…') if len(info['subject']) > 50 else info['subject'],
                    info['from'],
                    info['date'],
                    info['risk'],
                    classification,  # Use the formatted classification
                    info['score_url'],
                    info['score_attachment'],
                    info['score_ai'],
                    info['score_cert']
                )
                tag = 'phishing' if info['classification'] == 'Phishing Email' else 'safe'
                self.tree.insert('', 'end', values=vals, tags=(tag,))
            
            # Update the chart
            self.update_chart()
            
            if self.auto_refresh_var.get():
                self.status_var.set(f"Auto-refreshing every {self.auto_refresh_interval//1000} seconds")
            else:
                self.status_var.set("Ready")
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to refresh: {str(e)}")

    def show_details(self, event):
        try:
            sel = self.tree.selection()
            if not sel:
                return
            
            vals = self.tree.item(sel[0], 'values')
            uid = vals[0]
            rec = next((r for r in self.report.entries if r['id'] == uid), None)
            
            if rec:
                detail_window = tk.Toplevel(self.root)
                detail_window.title(f"Email Details - UID {uid}")
                detail_window.geometry("800x600")
                
                # Create notebook for tabs
                notebook = ttk.Notebook(detail_window)
                notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                # Summary tab
                summary_frame = ttk.Frame(notebook)
                notebook.add(summary_frame, text="Summary")
                
                # Create text widget with scrollbar
                text_frame = ttk.Frame(summary_frame)
                text_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                text = tk.Text(text_frame, wrap=tk.WORD)
                text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                
                scrollbar = ttk.Scrollbar(text_frame, command=text.yview)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                text.config(yscrollcommand=scrollbar.set)
                
                # Add content with confidence information
                detail_text = (
                    f"From: {rec['from']}\n"
                    f"Subject: {rec['subject']}\n"
                    f"Date: {rec['date']}\n"
                    f"Risk Level: {rec['risk']}\n"
                    f"Classification: {rec['classification']} ({rec.get('confidence', 'N/A')})\n"
                    f"Total Score: {rec['total_score']}/4\n\n"
                    f"Detailed Scores:\n"
                    f"URL Analysis: {rec['score_url']}/1\n"
                    f"Attachment Scan: {rec['score_attachment']}/1\n"
                    f"AI Classification: {rec['score_ai']}/3\n"
                    f"Certificate Check: {rec['score_cert']}/1\n\n"
                    f"Reasons:\n{rec['reasons']}\n\n"
                    f"AI Explanation:\n{rec['explanation']}"
                )
                
                text.insert(tk.END, detail_text)
                text.config(state=tk.DISABLED)
                
                # Content tab
                content_frame = ttk.Frame(notebook)
                notebook.add(content_frame, text="Content")
                
                content_text = tk.Text(content_frame, wrap=tk.WORD)
                content_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                # Add email content
                if 'body' in rec:
                    content_text.insert(tk.END, rec['body'])
                else:
                    content_text.insert(tk.END, "No content available")
                content_text.config(state=tk.DISABLED)
                
                # URLs tab
                urls_frame = ttk.Frame(notebook)
                notebook.add(urls_frame, text="URLs")
                
                urls_text = tk.Text(urls_frame, wrap=tk.WORD)
                urls_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
                
                if 'urls' in rec and rec['urls']:
                    urls_text.insert(tk.END, "\n".join(rec['urls']))
                else:
                    urls_text.insert(tk.END, "No URLs found")
                urls_text.config(state=tk.DISABLED)
                
                # Buttons
                button_frame = ttk.Frame(detail_window)
                button_frame.pack(fill=tk.X, padx=10, pady=10)
                
                ttk.Button(button_frame, text="Close", command=detail_window.destroy).pack(side=tk.RIGHT)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show details: {str(e)}")

    def export_csv(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if filename:
                self.report.generate_csv(filename)
                self.status_var.set(f"Exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")

    def export_json(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                self.report.generate_json(filename)
                self.status_var.set(f"Exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export JSON: {str(e)}")

    def show_settings(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("500x400")
        settings_window.resizable(False, False)
        
        # Create main frame
        main_frame = ttk.Frame(settings_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Email Settings
        email_frame = ttk.LabelFrame(main_frame, text="Email Settings", padding="5")
        email_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(email_frame, text="IMAP Server:").grid(row=0, column=0, sticky=tk.W, pady=2)
        imap_server = ttk.Entry(email_frame, width=40)
        imap_server.insert(0, IMAP_SERVER)
        imap_server.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(email_frame, text="Email Account:").grid(row=1, column=0, sticky=tk.W, pady=2)
        email_account = ttk.Entry(email_frame, width=40)
        email_account.insert(0, EMAIL_ACCOUNT)
        email_account.grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(email_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=2)
        email_password = ttk.Entry(email_frame, width=40, show="*")
        email_password.insert(0, EMAIL_PASSWORD)
        email_password.grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # VirusTotal Settings
        vt_frame = ttk.LabelFrame(main_frame, text="VirusTotal Settings", padding="5")
        vt_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(vt_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W, pady=2)
        vt_api_key = ttk.Entry(vt_frame, width=40)
        vt_api_key.insert(0, VIRUSTOTAL_API_KEY)
        vt_api_key.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Monitoring Settings
        monitor_frame = ttk.LabelFrame(main_frame, text="Monitoring Settings", padding="5")
        monitor_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(monitor_frame, text="Poll Interval (seconds):").grid(row=0, column=0, sticky=tk.W, pady=2)
        poll_interval = ttk.Spinbox(monitor_frame, from_=10, to=300, width=10)
        poll_interval.set(POLL_INTERVAL)
        poll_interval.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(monitor_frame, text="VT Call Interval (seconds):").grid(row=1, column=0, sticky=tk.W, pady=2)
        vt_interval = ttk.Spinbox(monitor_frame, from_=5, to=60, width=10)
        vt_interval.set(VT_CALL_INTERVAL)
        vt_interval.grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        def save_settings():
            try:
                # Update global variables
                global IMAP_SERVER, EMAIL_ACCOUNT, EMAIL_PASSWORD, VIRUSTOTAL_API_KEY, POLL_INTERVAL, VT_CALL_INTERVAL
                IMAP_SERVER = imap_server.get()
                EMAIL_ACCOUNT = email_account.get()
                EMAIL_PASSWORD = email_password.get()
                VIRUSTOTAL_API_KEY = vt_api_key.get()
                POLL_INTERVAL = int(poll_interval.get())
                VT_CALL_INTERVAL = int(vt_interval.get())
                
                # Save to config file
                config = {
                    'imap_server': IMAP_SERVER,
                    'email_account': EMAIL_ACCOUNT,
                    'email_password': EMAIL_PASSWORD,
                    'vt_api_key': VIRUSTOTAL_API_KEY,
                    'poll_interval': POLL_INTERVAL,
                    'vt_interval': VT_CALL_INTERVAL
                }
                with open('config.json', 'w') as f:
                    json.dump(config, f, indent=4)
                
                messagebox.showinfo("Success", "Settings saved successfully!")
                settings_window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
        
        ttk.Button(button_frame, text="Save", command=save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side=tk.RIGHT, padx=5)

    def show_about(self):
        about_text = (
            "Email Security Scanner\n\n"
            "Version: 1.0\n"
            "A tool for detecting phishing emails and malicious content.\n\n"
            "Features:\n"
            "- Real-time email monitoring\n"
            "- AI-based phishing detection\n"
            "- URL and attachment scanning\n"
            "- Detailed reporting and analysis"
        )
        messagebox.showinfo("About", about_text)

    def on_close(self):
        """Handle window close event"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # Cancel any running auto-refresh
            if self.auto_refresh_id:
                self.root.after_cancel(self.auto_refresh_id)
            self.stop_event.set()
            self.root.destroy()

# =======================
# Processing & Monitoring
# =======================
def process_and_handle(item, fetcher, analyzer, vt, detector, report):
    uid, msg = item
    try:
        data = analyzer.parse(msg)
        header_fail, reasons = analyzer.analyze_headers(msg)
        
        # Process URLs with new VT format
        url_flags = []
        for url in data['urls']:
            result = vt.scan_url(url)
            if result.get('error'):
                logging.warning(f"URL scan error for {url}: {result['error']}")
            url_flags.append((url, result.get('malicious', False)))
            if result.get('malicious'):
                reasons.append(f"URL {url} flagged by {result.get('total_engines', 0)} engines")
        
        # Process attachments with new VT format
        att_flags = []
        for name, content in data['attachments']:
            result = vt.scan_file(content, name)
            if result.get('error'):
                logging.warning(f"File scan error for {name}: {result['error']}")
            att_flags.append((name, result.get('malicious', False)))
            if result.get('malicious'):
                reasons.append(f"Attachment {name} flagged by {result.get('total_engines', 0)} engines")
        
        # Get classification and confidence
        cls, confidence = detector.predict(data)
        expl = detector.explain(data)
        
        if header_fail:
            reasons.append('Header authentication failure')
        
        # Calculate scores (each out of 1)
        score_url = 0 if any(f for _, f in url_flags) else 1
        score_att = 0 if any(f for _, f in att_flags) else 1
        score_cert = 0 if header_fail else 1
        
        # Calculate AI score based on confidence (out of 3)
        if cls == "Safe Email":
            score_ai = min(3, int(confidence * 3))
        else:
            score_ai = min(3, int((1 - confidence) * 3))
        
        total = score_url + score_att + score_cert + score_ai
        
        # Determine risk level
        if total < 2 or (header_fail and total < 3):
            risk = 'High'
        elif total < 3 or len(reasons) > 0:
            risk = 'Medium'
        else:
            risk = 'Low'
        
        # Prepare email info
        info = {
            'id': uid,
            'from': data['from'],
            'subject': data['subject'],
            'date': data['date'],
            'risk': risk,
            'classification': cls,
            'reasons': '; '.join(reasons),
            'score_url': score_url,
            'score_attachment': score_att,
            'score_ai': score_ai,
            'score_cert': score_cert,
            'total_score': total,
            'explanation': expl,
            'confidence': f"{confidence*100:.1f}%",
            'urls': data['urls'],
            'attachments': [name for name, _ in data['attachments']]
        }
        
        # Add to report
        report.add(info)
        logging.info("Processed email UID %s: total_score=%s, risk=%s", uid, total, risk)
        
        # Handle phishing emails
        if risk == 'High' or (risk == 'Medium' and cls == 'Phishing Email'):
            try:
                # Ensure connection is active
                if not fetcher.conn:
                    if not fetcher.connect():
                        logging.error("Failed to connect to IMAP server for moving phishing email")
                        return
                
                # Move to detected folder
                fetcher.move_to_detected([uid])
                logging.info("Moved phishing email UID %s to detected folder", uid)
                
                # Send alert
                alert_msg = (
                    f"Phishing email detected!\n\n"
                    f"From: {data['from']}\n"
                    f"Subject: {data['subject']}\n"
                    f"Risk Level: {risk}\n"
                    f"Total Score: {total}/4\n"
                    f"Reasons: {'; '.join(reasons)}\n"
                    f"URLs: {', '.join(data['urls'])}\n"
                    f"Attachments: {', '.join(name for name, _ in data['attachments'])}"
                )
                send_alert('Phishing Detected', alert_msg)
            except Exception as e:
                logging.error("Failed to handle phishing email UID %s: %s", uid, e)
        else:
            # Mark as unread if not phishing
            try:
                fetcher.mark_as_unread([uid])
                logging.info("Marked email UID %s as unread", uid)
            except Exception as e:
                logging.error("Failed to mark email UID %s as unread: %s", uid, e)
            
    except Exception as e:
        logging.error("Processing error UID %s: %s", uid, e)

def live_email_monitor(fetcher, analyzer, vt, detector, report, stop_event, interval=POLL_INTERVAL):
    seen = set()
    while not stop_event.is_set():
        try:
            # Ensure connection is active
            if not fetcher.conn:
                if not fetcher.connect():
                    logging.error("Failed to connect to IMAP server")
                    time.sleep(interval)
                    continue
            
            # Fetch only unseen emails
            try:
                unseen = fetcher.fetch_unseen()
                if unseen is None:  # Handle fetch failure
                    logging.error("Failed to fetch unseen emails")
                    time.sleep(interval)
                    continue
            except Exception as e:
                logging.error("Error fetching unseen emails: %s", e)
                time.sleep(interval)
                continue
            
            new = [(u, m) for u, m in unseen if u not in seen]
            
            if new:
                logging.info("Found %d new emails", len(new))
                
                # Process emails in parallel but limit concurrent processing
                with ThreadPoolExecutor(max_workers=3) as ex:
                    futures = []
                    for item in new:
                        futures.append(ex.submit(process_and_handle, item, fetcher, analyzer, vt, detector, report))
                    
                    # Wait for all processing to complete
                    for future in futures:
                        try:
                            future.result()
                        except Exception as e:
                            logging.error("Error in email processing: %s", e)
                
                # Only mark emails as processed if fetch was successful
                for u, _ in new:
                    seen.add(u)
                
                # Clean up old seen UIDs to prevent memory growth
                if len(seen) > 1000:
                    seen = set(list(seen)[-1000:])
            
        except Exception as e:
            logging.error("Polling error: %s", e)
            try:
                fetcher.connect()
            except Exception as ex:
                logging.error("Reconnect failed: %s", ex)
        
        time.sleep(interval)

def main():
    stop_event = threading.Event()
    fetcher = EmailFetcher(IMAP_SERVER, EMAIL_ACCOUNT, EMAIL_PASSWORD)
    analyzer = EmailAnalyzer()
    vt = VirusTotalScanner(VIRUSTOTAL_API_KEY)
    detector = PhishingDetector(PHISHING_MODEL_PATH)
    report = ReportGenerator()
    
    fetcher.connect()
    t = threading.Thread(target=live_email_monitor, args=(fetcher, analyzer, vt, detector, report, stop_event), daemon=True)
    t.start()
    
    root = tk.Tk()
    SecurityScannerGUI(root, report, stop_event)
    root.mainloop()
    
    # Fix method names to match the class implementation
    report.generate_csv()
    report.generate_json()
    fetcher.disconnect()

if __name__ == '__main__':
    main()
