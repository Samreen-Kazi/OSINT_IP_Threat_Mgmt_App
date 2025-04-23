import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import csv
import matplotlib.pyplot as plt
import textwrap
from fpdf import FPDF
import os
import re
import pycountry
import threading
import logging
import config
import folium
from collections import Counter
from geopy.geocoders import Nominatim
import logging
import webbrowser
import os
import subprocess
from datetime import datetime
from tkinter import font as tkfont

# Font styles for consistency
default_font = ("Segoe UI", 13)
bold_font = ("Segoe UI", 12, "bold")
result_font = ("Consolas", 11)
# Common suspicious ports (Telnet, RDP, SMB, FTP, etc.)
suspicious_ports = {"23", "445", "3389", "21", "25", "1433", "3306"}


logging.basicConfig(filename="error_log.txt", level=logging.ERROR)

def apply_dark_mode():
    root.config(bg="#2E2E2E")
    input_frame.config(bg="#2E2E2E")
    buttons_frame.config(bg="#2E2E2E")
    result_frame.config(bg="#2E2E2E")
    result_text.config(bg="#4A4A4A", fg="white")
    ip_entry.config(bg="#333333", fg="white", insertbackground='white')

    for widget in buttons_frame.winfo_children():
        if isinstance(widget, tk.Button):
            widget.config(bg="#333333", fg="white")
        elif isinstance(widget, tk.Label):
            widget.config(bg="#2E2E2E", fg="white")

    for widget in input_frame.winfo_children():
        if isinstance(widget, (tk.Label, tk.Entry)):
            widget.config(bg="#333333", fg="white")

    # Combobox dark style
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TCombobox",
                    fieldbackground="#4A4A4A",
                    background="#2E2E2E",
                    foreground="white",
                    selectforeground="white",
                    selectbackground="#4A4A4A")


def apply_light_mode():
    root.config(bg="white")
    input_frame.config(bg="white")
    buttons_frame.config(bg="white")
    result_frame.config(bg="white")
    result_text.config(bg="white", fg="black")
    ip_entry.config(bg="white", fg="black", insertbackground='black')

    for widget in buttons_frame.winfo_children():
        if isinstance(widget, tk.Button):
            widget.config(bg="white", fg="black")
        elif isinstance(widget, tk.Label):
            widget.config(bg="white", fg="black")

    for widget in input_frame.winfo_children():
        if isinstance(widget, (tk.Label, tk.Entry)):
            widget.config(bg="white", fg="black")

    # Combobox light style
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TCombobox",
                    fieldbackground="white",
                    background="white",
                    foreground="black",
                    selectforeground="black",
                    selectbackground="white")

def toggle_theme():
    global is_dark_mode
    if is_dark_mode:
        apply_light_mode()
    else:
        apply_dark_mode()
    is_dark_mode = not is_dark_mode

def extract_asn(org_field):
    match = re.search(r"(AS\d+)", org_field)
    return match.group(1) if match else None

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

def format_timeline(timestamp):
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except:
        return timestamp

def generate_suggestion(ip):
    suggestions = []
    if int(ip.get("Abuse Score", 0)) >= 90:
        suggestions.append("⚠️ Highly abusive IP — consider blocking.")
    if int(ip.get("VT Malicious", 0)) >= 5:
        suggestions.append("⚠️ Malicious flagged by VirusTotal.")
    risky_ports = check_suspicious_ports(ip.get("Open Ports", ""))
    if risky_ports:
        suggestions.append("⚠️ Risky ports detected: " + ", ".join(risky_ports))
    return "\n".join(suggestions) if suggestions else "No immediate action suggested."


def query_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={config.SHODAN_API_KEY}"
        r = requests.get(url).json()
        ports = ','.join(map(str, r.get('ports', []))) or "None"
        tags = ','.join(r.get('tags', [])) or "None"
        return ports, tags
    except Exception as e:
        logging.error(f"Shodan error for {ip}: {str(e)}")
        return "N/A", "N/A"

def query_greynoise(ip):
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": config.GREYNOISE_API_KEY}
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return "Not Seen", "Unknown"
        elif response.status_code == 429:
            return "Rate Limited", "Try again later"
        elif response.status_code != 200:
            return f"Error {response.status_code}", "Unknown"
        r = response.json()
        classification = r.get("classification", "unknown")
        name = r.get("name", "Unknown")
        return classification.capitalize(), name
    except Exception as e:
        logging.error(f"GreyNoise error for {ip}: {str(e)}")
        return "Error", "Error"

def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()['data']['attributes']
            malicious = data['last_analysis_stats']['malicious']
            suspicious = data['last_analysis_stats']['suspicious']
            harmless = data['last_analysis_stats']['harmless']
            undetected = data['last_analysis_stats']['undetected']
            reputation = data.get('reputation', 'N/A')

            return {
                "Malicious": malicious,
                "Suspicious": suspicious,
                "Harmless": harmless,
                "Undetected": undetected,
                "Reputation": reputation
            }
        else:
            logging.error(f"VirusTotal error {response.status_code} for {ip}: {response.text}")
            return {
                "Malicious": "N/A",
                "Suspicious": "N/A",
                "Harmless": "N/A",
                "Undetected": "N/A",
                "Reputation": "N/A"
            }

    except Exception as e:
        logging.error(f"VirusTotal exception for {ip}: {str(e)}")
        return {
            "Malicious": "N/A",
            "Suspicious": "N/A",
            "Harmless": "N/A",
            "Undetected": "N/A",
            "Reputation": "N/A"
        }

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

# ==== Core Logic ====
def process_ip(ip):
    ip = ip.strip()
    country, org, asn, hostname = query_ipinfo(ip)
    abuse_score, total_reports, last_report_raw = query_abuseipdb(ip)
    last_report = format_timeline(last_report_raw)
    ports, tags = query_shodan(ip)
    risky_ports = check_suspicious_ports(ports)
    greynoise_class, greynoise_name = query_greynoise(ip)
    virustotal_results = query_virustotal(ip)
    threat_level = calculate_threat_level(abuse_score, virustotal_results.get("Malicious", 0), greynoise_class)
    threat_score = calculate_custom_threat_score(abuse_score, virustotal_results.get("Malicious", 0), len(risky_ports))

    return {
        "IP": ip,
        "Country": country,
        "Org": org,
        "ASN": asn,
        "Hostname": hostname,
        "Abuse Score": abuse_score,
        "Total Reports": total_reports,
        "Last Report": last_report,
        "Open Ports": ports,
        "Tags": tags,
        "GreyNoise Classification": greynoise_class,
        "GreyNoise Name": greynoise_name,
        # VirusTotal fields:
        "VT Malicious": virustotal_results["Malicious"],
        "VT Suspicious": virustotal_results["Suspicious"],
        "VT Harmless": virustotal_results["Harmless"],
        "VT Undetected": virustotal_results["Undetected"],
        "VT Reputation": virustotal_results["Reputation"],
        "Custom Threat Score": threat_score,
        "Threat Level": threat_level

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
    abuse_scores = [int(ip['Abuse Score']) if str(ip['Abuse Score']).isdigit() else 0 for ip in data]
    countries = [ip['Country'] for ip in data]

    # 1. Abuse Score Bar Chart
    plt.figure(figsize=(10, 5))
    plt.bar(range(len(data)), abuse_scores, color='blue')
    plt.title('Abuse Score Distribution')
    plt.xlabel('IP Index')
    plt.ylabel('Abuse Score')
    plt.tight_layout()
    plt.show()

    # 2. Country Distribution Pie Chart
    country_counts = {country: countries.count(country) for country in set(countries)}
    plt.figure(figsize=(8, 8))
    plt.pie(country_counts.values(), labels=country_counts.keys(), autopct='%1.1f%%', startangle=140)
    plt.title('Country Distribution')
    plt.tight_layout()
    plt.show()

    # 3. VirusTotal Malicious Score Bar Chart
    vt_scores = [int(ip['VT Malicious']) if str(ip['VT Malicious']).isdigit() else 0 for ip in data]
    ip_labels = [ip['IP'] for ip in data]

    plt.figure(figsize=(12, 6))
    plt.bar(ip_labels, vt_scores, color='red')
    plt.title('VirusTotal Malicious Scores by IP')
    plt.xlabel('IP Address')
    plt.ylabel('Malicious Score')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

def export_charts_pdf(data):
    if not data:
        messagebox.showwarning("No Data", "No data available to generate charts.")
        return

    abuse_scores = [int(ip['Abuse Score']) if str(ip['Abuse Score']).isdigit() else 0 for ip in data]
    countries = [ip['Country'] for ip in data]
    vt_scores = [int(ip['VT Malicious']) if str(ip['VT Malicious']).isdigit() else 0 for ip in data]
    ip_labels = [ip['IP'] for ip in data]

    chart_files = []

    # Chart 1: Abuse Score
    plt.figure(figsize=(10, 5))
    plt.bar(range(len(data)), abuse_scores, color='blue')
    plt.title('Abuse Score Distribution')
    plt.xlabel('IP Index')
    plt.ylabel('Abuse Score')
    plt.tight_layout()
    filename1 = "abuse_score_chart.png"
    plt.savefig(filename1)
    chart_files.append(filename1)
    plt.close()

    # Chart 2: Country Distribution
    country_counts = {country: countries.count(country) for country in set(countries)}
    plt.figure(figsize=(8, 8))
    plt.pie(country_counts.values(), labels=country_counts.keys(), autopct='%1.1f%%', startangle=140)
    plt.title('Country Distribution')
    plt.tight_layout()
    filename2 = "country_distribution_chart.png"
    plt.savefig(filename2)
    chart_files.append(filename2)
    plt.close()

    # Chart 3: VT Malicious Score
    plt.figure(figsize=(12, 6))
    plt.bar(ip_labels, vt_scores, color='red')
    plt.title('VirusTotal Malicious Scores by IP')
    plt.xlabel('IP Address')
    plt.ylabel('Malicious Score')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    filename3 = "vt_scores_chart.png"
    plt.savefig(filename3)
    chart_files.append(filename3)
    plt.close()

    # ✅ Save to PDF with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pdf_file = f"osint_charts_report_{timestamp}.pdf"

    pdf = FPDF('P', 'mm', 'A4')
    for chart in chart_files:
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        title = os.path.splitext(chart)[0].replace("_", " ").title()
        pdf.cell(200, 10, title, ln=True, align="C")
        pdf.image(chart, x=10, y=25, w=190)

    pdf.output(pdf_file)
    messagebox.showinfo("Chart Exported", f"Charts saved as {pdf_file}")

    # Clean up chart files
    for file in chart_files:
        if os.path.exists(file):
            os.remove(file)

def wrap_text(text, max_width=35):
    return textwrap.fill(text, width=max_width)

def export_to_pdf(data):
    pdf = FPDF('L', 'mm', 'A4')
    pdf.add_page()
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(270, 10, txt="OSINT Threat Intelligence Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 10)

    columns = ["IP", "Abuse Score", "VT Reputation", "Country", "ASN", "Org"]

    max_org_length = max(len(ip.get("Org", "")) for ip in data)
    org_col_width = min(max(60, max_org_length * 2), 100)

    total_width = 270
    remaining_width = total_width - org_col_width
    other_col_width = remaining_width / (len(columns) - 1)

    col_widths = {
        "IP": other_col_width,
        "Abuse Score": other_col_width,
        "VT Reputation": other_col_width,
        "Country": other_col_width,
        "ASN": other_col_width,
        "Org": org_col_width
    }

    for col in columns:
        pdf.cell(col_widths[col], 10, col, border=1, align='C')
    pdf.ln()

    pdf.set_font('Arial', '', 9)
    row_height = 8
    max_lines_per_page = 30
    line_count = 0

    for ip in data:
        if line_count >= max_lines_per_page:
            pdf.add_page()
            pdf.set_font('Arial', 'B', 10)
            for col in columns:
                pdf.cell(col_widths[col], 10, col, border=1, align='C')
            pdf.ln()
            pdf.set_font('Arial', '', 9)
            line_count = 0
        for col in columns:
            text = str(ip.get(col, "N/A"))  # Safely handle missing keys here
            if col == "Org":
                text = wrap_text(text, max_width=int(org_col_width / 2.5))
            pdf.cell(col_widths[col], row_height, text, border=1)
        pdf.ln()
        line_count += 1

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"osint_report_{timestamp}.pdf"
    pdf.output(filename)
    messagebox.showinfo("Export Complete", f"Report saved as {filename}")


def geocode_country(country_name):
    try:
        geolocator = Nominatim(user_agent="osint_geo_mapper")
        location = geolocator.geocode(country_name, exactly_one=True, timeout=10)
        return (location.latitude, location.longitude) if location else None
    except Exception as e:
        logging.error(f"Geocoding error for {country_name}: {str(e)}")
        return None

def get_marker_color(count):
    if count >= 10:
        return 'red'
    elif count >= 5:
        return 'orange'
    elif count >= 3:
        return 'green'
    else:
        return 'blue'

def visualize_geographic(data):
    country_counts = Counter(ip['Country'] for ip in data if ip['Country'] != "N/A" and ip['Country'] != "Unknown")
    world_map = folium.Map(location=[20, 0], zoom_start=2)

    for country, count in country_counts.items():
        coords = geocode_country(country)
        if coords:
            folium.CircleMarker(
                location=coords,
                radius=5 + count,
                popup=f"{country}: {count} IP(s)",
                color=get_marker_color(count),
                fill=True,
                fill_color=get_marker_color(count),
                fill_opacity=0.7
            ).add_to(world_map)

    map_filename = 'ip_geographic_distribution.html'
    world_map.save(map_filename)

    # Automatically open map without GTK warnings
    full_path = os.path.abspath(map_filename)
    
    try:
        # Redirect stderr to suppress GTK warnings
        subprocess.Popen(['xdg-open', full_path],
                         stderr=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL)
    except Exception as e:
        logging.error(f"Error opening browser: {str(e)}")

# ==== GUI Functions ====

def handle_single_ip():
    threading.Thread(target=process_single_ip_thread).start()

current_session_data = []

def process_single_ip_thread():
    global current_session_data
    ip = ip_entry.get().strip()
    if not ip:
        messagebox.showwarning("Input Error", "Please enter an IP address.")
        return
    result = process_ip(ip)
    write_csv([result])
    current_session_data = [result]  # store current session data
    display_results(current_session_data)
    messagebox.showinfo("IP Search Complete", "IP search completed and saved to CSV.")


def handle_file_upload():
    threading.Thread(target=process_file_upload_thread).start()

def process_file_upload_thread():
    global current_session_data
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as f:
            ips = f.readlines()
        current_session_data = []
        progress["maximum"] = len(ips)
        for idx, ip in enumerate(ips):
            ip_result = process_ip(ip.strip())
            current_session_data.append(ip_result)
            progress["value"] = idx + 1
            root.update_idletasks()
        write_csv(current_session_data)
        display_results(current_session_data)
        messagebox.showinfo("File Upload Complete", "File processed and results saved to CSV.")

def visualize_data_btn():
    results = get_all_results()
    if results:
        visualize_data(results)

def export_pdf_btn():
    global current_session_data
    if current_session_data:
        export_to_pdf(current_session_data)
    else:
        messagebox.showwarning("No Data", "Perform a search or upload file first.")

def export_pdf_all_btn():
    results = get_all_results()
    if results:
        export_to_pdf(results)
    else:
        messagebox.showwarning("No Data", "No data found in CSV.")


def get_all_results():
    try:
        with open("osint_output.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)
    except FileNotFoundError:
        messagebox.showwarning("No Data", "No data found. Please perform a search or upload a file.")
        return []

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
            messagebox.showinfo("Filter", f"No {selected.title()} threat IPs found in current session.")


def display_results(data):
    result_text.delete(1.0, tk.END)

    for idx, item in enumerate(data, 1):
        result_text.insert(tk.END, f"🔍 Result #{idx}\n", "header")

        for key, value in item.items():
            line = f"• {key}: {value}\n"

            if key == "Threat Level":
                level = str(value).strip().lower()
                if level == "high":
                    result_text.insert(tk.END, line, "threat_high")
                elif level == "medium":
                    result_text.insert(tk.END, line, "threat_medium")
                elif level == "low":
                    result_text.insert(tk.END, line, "threat_low")
                elif level == "none":
                    result_text.insert(tk.END, line, "threat_none")
                else:
                    result_text.insert(tk.END, line, "body")
            else:
                result_text.insert(tk.END, line, "body")

        # ✅ Show flagged risky ports
        risky_ports = check_suspicious_ports(item.get("Open Ports", ""))
        if risky_ports:
            result_text.insert(tk.END, f"⚠️ Suspicious Ports: {', '.join(risky_ports)}\n", "warning")

        # ✅ Add security suggestion
        suggestion = generate_suggestion(item)
        result_text.insert(tk.END, "\nSecurity Suggestion:\n", "bold")
        result_text.insert(tk.END, suggestion + "\n", "suggestion")

        result_text.insert(tk.END, "\n" + "—" * 70 + "\n\n", "separator")

    # ✅ Style tags
    result_text.tag_configure("header", font=("Segoe UI", 14, "bold"))
    result_text.tag_configure("body", font=("Consolas", 13))
    result_text.tag_configure("separator", font=("Segoe UI", 12))
    result_text.tag_configure("warning", font=("Segoe UI", 12, "bold"), foreground="red")
    result_text.tag_configure("bold", font=("Segoe UI", 13, "bold"))
    result_text.tag_configure("suggestion", font=("Segoe UI", 12, "italic"), foreground="yellow")
    result_text.tag_configure("threat_high", foreground="red", font=("Segoe UI", 13, "bold"))
    result_text.tag_configure("threat_medium", foreground="orange", font=("Segoe UI", 13, "bold"))
    result_text.tag_configure("threat_low", foreground="green", font=("Segoe UI", 13, "bold"))
    result_text.tag_configure("threat_none", foreground="gray", font=("Segoe UI", 13, "bold"))



# GUI handler function
def visualize_geo_btn():
    results = get_all_results()
    if results:
        visualize_geographic(results)
        messagebox.showinfo("Geographic Visualization", "Geographic visualization saved as ip_geographic_distribution.html.")

def filter_high_threat():
    try:
        with open("osint_output.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            filtered = [row for row in reader if row.get("Threat Level", "").strip().lower() == "high"]
            if not filtered:
                messagebox.showinfo("Filter Result", "No high threat IPs found.")
                return
            display_results(filtered)
    except FileNotFoundError:
        messagebox.showwarning("File Missing", "osint_output.csv not found.")

def clear_ip_input():
    ip_entry.delete(0, tk.END)

def clear_results():
    result_text.delete(1.0, tk.END)

def filter_by_threat_level(event=None):
    selected_level = filter_var.get()
    try:
        with open("osint_output.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if selected_level == "All":
                filtered = list(reader)
            else:
                filtered = [row for row in reader if row.get("Threat Level", "").strip().lower() == selected_level.lower()]
            if not filtered:
                messagebox.showinfo("Filter Result", f"No {selected_level} threat IPs found.")
                return
            display_results(filtered)
    except FileNotFoundError:
        messagebox.showwarning("No Data", "osint_output.csv not found.")



# ==== GUI Setup ====
root = tk.Tk()
root.title("OSINT IP Threat Intelligence Dashboard")
root.geometry("1000x750")

input_frame = tk.Frame(root)
input_frame.pack(pady=10)

tk.Label(input_frame, font=default_font, text="Enter IP Address or Upload a File").pack(side=tk.LEFT)
ip_entry = tk.Entry(input_frame, width=50)
ip_entry.pack(side=tk.LEFT, padx=5)

buttons_frame = tk.Frame(root)
buttons_frame.pack(pady=10)

tk.Button(buttons_frame, text="Search", font=default_font, command=handle_single_ip).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Upload File", font=default_font, command=handle_file_upload).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Visualize Data", font=default_font, command=visualize_data_btn).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Visualize Geographic Map", font=default_font, command=visualize_geo_btn).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Export to PDF", font=default_font, command=export_pdf_btn).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Export All Data to PDF", font=default_font, command=export_pdf_all_btn).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Clear IP Input", font=default_font, command=clear_ip_input).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Clear Results", font=default_font, command=clear_results).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Export Charts to PDF", font=default_font, command=lambda: export_charts_pdf(current_session_data)).pack(side=tk.LEFT, padx=5)
tk.Button(buttons_frame, text="Export All Charts", font=default_font, command=lambda: export_charts_pdf(get_all_results())).pack(side=tk.LEFT, padx=5)

# ⬅️ Filter label and dropdown
filter_label = tk.Label(buttons_frame, text="Threat Filter:", font= default_font)
filter_label.pack(side=tk.LEFT, padx=(10, 2), pady=5)

filter_var = tk.StringVar(value="All")
filter_dropdown = ttk.Combobox(buttons_frame, textvariable=filter_var, state="readonly", width=12, font= default_font)
filter_dropdown['values'] = ["All", "High", "Medium", "Low", "None"]
filter_dropdown.current(0)
filter_dropdown.pack(side=tk.LEFT, padx=5, pady=5, ipady=4)  # increase height
filter_dropdown.bind("<<ComboboxSelected>>", apply_filter)


toggle_button = tk.Button(buttons_frame, text="Toggle Dark/Light Mode", font=default_font, command=toggle_theme)
toggle_button.pack(side=tk.LEFT, padx=10)


progress = ttk.Progressbar(root, orient="horizontal", length=600, mode="determinate")
progress.pack(pady=10)



result_frame = tk.Frame(root)
result_frame.pack(pady=20)

scrollbar = tk.Scrollbar(result_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

result_text = tk.Text(
    result_frame,
    height=35,
    width=140,
    font=result_font,
    wrap="word",
    yscrollcommand=scrollbar.set
)
result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar.config(command=result_text.yview)


is_dark_mode = True
apply_dark_mode()

root.mainloop()