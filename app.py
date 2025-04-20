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
import matplotlib.pyplot as plt
from fpdf import FPDF
import tempfile

# Font styles
default_font = ("Segoe UI", 13)
result_font = ("Consolas", 11)

# Ports considered suspicious
suspicious_ports = {"23", "445", "3389", "21", "25", "1433", "3306"}
logging.basicConfig(filename="error_log.txt", level=logging.ERROR)

# === Helper functions ===
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

def calculate_threat_level(score):
    try:
        if isinstance(score, str) and not score.isdigit(): return "Unknown"
        score = int(score)
        if score >= 85:
            return "High"
        elif score >= 50:
            return "Medium"
        elif score > 0:
            return "Low"
        return "None"
    except:
        return "Unknown"

def process_ip(ip):
    ip = ip.strip()
    country, org, asn, hostname = query_ipinfo(ip)
    abuse_score, total_reports, last_report_raw = query_abuseipdb(ip)
    threat_score = calculate_custom_threat_score(abuse_score, 0, 0)
    threat_level = calculate_threat_level(threat_score)

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

def visualize_data(data):
    countries = {}
    scores = []

    for row in data:
        country = row.get("Country", "Unknown")
        score = int(row.get("Abuse Score", 0))
        countries[country] = countries.get(country, 0) + 1
        scores.append(score)

    plt.figure(figsize=(6, 4))
    plt.hist(scores, bins=10)
    plt.title("Abuse Score Distribution")
    plt.xlabel("Score")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig("abuse_score_chart.png")

    plt.figure(figsize=(6, 4))
    plt.bar(countries.keys(), countries.values())
    plt.title("IP Country Distribution")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("country_distribution_chart.png")

def export_pdf_report(data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="IP Threat Intelligence Report", ln=True, align="C")

    for row in data:
        pdf.ln(5)
        for key, val in row.items():
            pdf.multi_cell(0, 10, f"{key}: {val}")
        pdf.ln(2)
        pdf.multi_cell(0, 10, "=" * 50)

    pdf.add_page()
    for chart in ["abuse_score_chart.png", "country_distribution_chart.png"]:
        if os.path.exists(chart):
            pdf.image(chart, x=10, w=180)

    pdf.output("IP_Threat_Report.pdf")

# GUI Shell (assumes continuation from previous parts)
root = tk.Tk()
root.title("OSINT Dashboard - Visualizations")
root.geometry("800x600")

def handle_ip_search():
    ip = entry.get().strip()
    if not ip:
        messagebox.showwarning("Input Error", "Please enter an IP address.")
        return
    result = process_ip(ip)
    write_csv([result])
    display_results([result])
    messagebox.showinfo("Complete", "IP processed and saved.")

def display_results(data):
    result_text.delete(1.0, tk.END)
    for row in data:
        for key, val in row.items():
            result_text.insert(tk.END, f"{key}: {val}\n")
        result_text.insert(tk.END, "=" * 50 + "\n")

entry = tk.Entry(root, width=50)
entry.pack(pady=10)

search_btn = tk.Button(root, text="Search", command=handle_ip_search)
search_btn.pack(pady=5)

result_text = tk.Text(root, height=20, width=100)
result_text.pack(pady=10)

visualize_btn = tk.Button(root, text="Generate Charts", command=lambda: visualize_data(current_session_data))
visualize_btn.pack(pady=5)

export_pdf_btn = tk.Button(root, text="Export to PDF", command=lambda: export_pdf_report(current_session_data))
export_pdf_btn.pack(pady=5)

current_session_data = []

root.mainloop()

