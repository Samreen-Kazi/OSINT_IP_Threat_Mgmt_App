import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import requests
import csv
import logging
import config
from datetime import datetime
import re
import pycountry
import os
import threading

# Font styles for consistency
default_font = ("Segoe UI", 13)
result_font = ("Consolas", 11)

# Common suspicious ports
suspicious_ports = {"23", "445", "3389", "21", "25", "1433", "3306"}

logging.basicConfig(filename="error_log.txt", level=logging.ERROR)

# ========== API Query Functions ==========
def query_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': config.ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        r = requests.get(url, headers=headers, params=params).json()['data']
        return r.get('abuseConfidenceScore', 0), r.get('totalReports', 0), r.get('lastReportedAt', 'N/A')
    except Exception as e:
        logging.error(f"AbuseIPDB error for {ip}: {str(e)}")
        return "N/A", "N/A", "N/A"

def query_ipinfo(ip):
    try:
        url = f"https://ipinfo.io/{ip}?token={config.IPINFO_TOKEN}"
        r = requests.get(url).json()
        org = r.get('org', 'N/A')
        country_code = r.get('country', 'N/A')
        hostname = r.get('hostname', 'N/A')
        country_name = get_country_name(country_code)
        asn = extract_asn(org)
        if asn:
            org = org.replace(asn, '').strip()
        return country_name, org, asn, hostname
    except Exception as e:
        logging.error(f"IPInfo error for {ip}: {str(e)}")
        return "N/A", "N/A", "N/A", "N/A"

def extract_asn(org_field):
    match = re.search(r"(AS\d+)", org_field)
    return match.group(1) if match else None

def get_country_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name if country else "Unknown"
    except:
        return "Unknown"

# ========== Threat Calculation ==========
def check_suspicious_ports(port_str):
    ports = port_str.split(",") if port_str and port_str != "None" else []
    flagged = [p.strip() for p in ports if p.strip() in suspicious_ports]
    return flagged

def calculate_custom_threat_score(abuse, vt_mal, port_count):
    try:
        abuse = int(abuse) if str(abuse).isdigit() else 0
        vt_mal = int(vt_mal) if str(vt_mal).isdigit() else 0
        score = abuse + vt_mal * 5 + port_count * 3
        return min(score, 100)
    except:
        return 0

def calculate_threat_level(score, vt_malicious, gn_class):
    try:
        if isinstance(score, str) and not score.isdigit(): return "Unknown"
        score = int(score)
        vt_malicious = int(vt_malicious) if str(vt_malicious).isdigit() else 0

        if score >= 85 or vt_malicious >= 10 or gn_class.lower() == "malicious":
            return "High"
        elif score >= 50 or vt_malicious >= 5 or gn_class.lower() == "benign":
            return "Medium"
        elif score > 0:
            return "Low"
        return "None"
    except:
        return "Unknown"

# ========== Core Processing ==========
def process_ip(ip):
    ip = ip.strip()
    country, org, asn, hostname = query_ipinfo(ip)
    abuse_score, total_reports, last_report_raw = query_abuseipdb(ip)
    threat_score = calculate_custom_threat_score(abuse_score, 0, 0)
    threat_level = calculate_threat_level(threat_score, 0, "")

    return {
        "IP": ip,
        "Country": country,
        "Org": org,
        "ASN": asn,
        "Hostname": hostname,
        "Abuse Score": abuse_score,
        "Total Reports": total_reports,
        "Last Report": last_report_raw,
        "Threat Score": threat_score,
        "Threat Level": threat_level,
        "Open Ports": "",
    }

def write_csv(data, filename="osint_output.csv"):
    file_exists = os.path.isfile(filename)
    existing_ips = set()

    if file_exists:
        with open(filename, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            existing_ips = {row["IP"] for row in reader}

    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())

        if not file_exists:
            writer.writeheader()

        for row in data:
            if row["IP"] not in existing_ips:
                writer.writerow(row)

# ========== Suggestions & File Upload ==========
current_session_data = []

def generate_suggestion(ip):
    suggestions = []
    if int(ip.get("Abuse Score", 0)) >= 90:
        suggestions.append("⚠️ Highly abusive IP — consider blocking.")
    risky_ports = check_suspicious_ports(ip.get("Open Ports", ""))
    if risky_ports:
        suggestions.append("⚠️ Risky ports detected: " + ", ".join(risky_ports))
    return "\n".join(suggestions) if suggestions else "No immediate action suggested."

def handle_file_upload():
    threading.Thread(target=process_file_upload_thread).start()

def process_file_upload_thread():
    global current_session_data
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as f:
            ips = f.readlines()
        current_session_data = []
        for ip in ips:
            ip_result = process_ip(ip.strip())
            current_session_data.append(ip_result)
        write_csv(current_session_data)
        display_results(current_session_data)

def display_results(data):
    result_text.delete(1.0, tk.END)
    for idx, item in enumerate(data, 1):
        result_text.insert(tk.END, f"Result #{idx}\n")
        for key, value in item.items():
            result_text.insert(tk.END, f"{key}: {value}\n")
        result_text.insert(tk.END, "\nSuggestions:\n")
        result_text.insert(tk.END, generate_suggestion(item) + "\n")
        result_text.insert(tk.END, "="*50 + "\n\n")

def apply_filter(event=None):
    selected = filter_var.get().strip().lower()
    global current_session_data
    if not current_session_data:
        messagebox.showwarning("No Data", "No IP data available in this session.")
        return
    if selected == "all":
        display_results(current_session_data)
    else:
        filtered = [
            row for row in current_session_data
            if row.get("Threat Level", "").strip().lower() == selected
        ]
        if filtered:
            display_results(filtered)
        else:
            messagebox.showinfo("Filter", f"No {selected.title()} threat IPs found.")

# ========== GUI Setup ==========
root = tk.Tk()
root.title("OSINT IP Threat Intelligence")
root.geometry("900x700")

entry = tk.Entry(root, width=50)
entry.pack(pady=10)

def handle_ip_search():
    ip = entry.get().strip()
    if not ip:
        messagebox.showwarning("Input Error", "Please enter an IP address.")
        return
    result = process_ip(ip)
    write_csv([result])
    global current_session_data
    current_session_data = [result]
    display_results(current_session_data)
    messagebox.showinfo("Complete", "IP processed and saved.")

search_btn = tk.Button(root, text="Search", command=handle_ip_search)
search_btn.pack(pady=5)

upload_btn = tk.Button(root, text="Upload File", command=handle_file_upload)
upload_btn.pack(pady=5)

filter_var = tk.StringVar(value="All")
filter_dropdown = ttk.Combobox(root, textvariable=filter_var, state="readonly", width=12)
filter_dropdown['values'] = ["All", "High", "Medium", "Low", "None"]
filter_dropdown.current(0)
filter_dropdown.pack(pady=5)
filter_dropdown.bind("<<ComboboxSelected>>", apply_filter)

result_text = tk.Text(root, height=30, width=120)
result_text.pack(pady=10)

root.mainloop()
