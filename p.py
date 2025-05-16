# Install with: pip install customtkinter requests fake-useragent beautifulsoup4 serpapi pandas

import customtkinter as ctk
import threading
import pandas as pd
import re
import requests
import random
import time
from bs4 import BeautifulSoup
from tkinter import messagebox, filedialog
from serpapi import GoogleSearch
from fake_useragent import UserAgent
from urllib.parse import urlparse, urljoin

SERPAPI_KEY = "00939b326b6715a3921068c5faf81d5f0e569813f4b61feb4dc7b524632f1090"
PROXIES = []

def get_random_proxy():
    return {"http": random.choice(PROXIES), "https": random.choice(PROXIES)} if PROXIES else None

def get_random_headers():
    return {"User-Agent": UserAgent().random}

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except:
        return False

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def generate_search_links(country, city, industry, count, log_callback):
    query = f"{industry} in {city}, {country}"
    log_callback(f"Searching: {query}")
    search = GoogleSearch({"q": query, "api_key": SERPAPI_KEY, "num": count})
    results = search.get_dict()
    links = []
    for result in results.get("organic_results", []):
        link = result.get("link")
        if link:
            links.append({
                "Country": country,
                "City": city,
                "Industry": industry,
                "URL": link
            })
    return links

def is_shopify_site(soup):
    return "cdn.shopify.com" in str(soup) or "Shopify" in soup.text

def is_domain_active_and_fast(url, timeout=5):
    try:
        start = time.time()
        r = requests.get(url, headers=get_random_headers(), proxies=get_random_proxy(), timeout=timeout)
        return r.status_code == 200 and (time.time() - start) <= timeout
    except:
        return False

def extract_emails_and_phones_from_url(url, log_callback):
    emails = set()
    phones = set()
    visited = set()

    def is_possible_phone(number):
        digits_only = re.sub(r"\D", "", number)
        if len(digits_only) < 8:
            return False
        if re.search(r"\b(19|20|21)\d{2}\b", number):
            return False
        if re.search(r"\b\d{4}\s*-\s*\d{4}\b", number):
            return False
        return True

    def extract(url):
        if url in visited or not is_valid_url(url):
            return None
        visited.add(url)

        try:
            log_callback(f"Fetching: {url}")
            r = requests.get(url, headers=get_random_headers(), proxies=get_random_proxy(), timeout=10)
            soup = BeautifulSoup(r.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)

            found_emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            emails.update(found_emails)

            phones_found = re.findall(r"(\+?\d[\d\s\-\(\)]{7,}\d)", text)
            filtered_phones = [p.strip() for p in phones_found if is_possible_phone(p)]
            phones.update(filtered_phones)

            for a in soup.find_all("a", href=True):
                href = a['href'].lower()
                if any(x in href for x in ['contact', 'about']) and urlparse(href).netloc == "":
                    new_url = urljoin(url, a['href'])
                    extract(new_url)

            return soup
        except Exception as e:
            log_callback(f"[ERROR] {url}: {e}")
            return None

    soup = extract(url)
    return soup, list(emails), list(phones)

class ScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📬 Advanced Web Scraper - Emails & Phones")
        self.root.geometry("1000x720")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        self.final_data = []
        self.create_widgets()

    def create_widgets(self):
        self.input_frame = ctk.CTkFrame(self.root)
        self.input_frame.pack(padx=10, pady=10, fill="x")

        ctk.CTkLabel(self.input_frame, text="🌍 Country").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.country_var = ctk.CTkEntry(self.input_frame, width=200)
        self.country_var.grid(row=0, column=1)

        ctk.CTkLabel(self.input_frame, text="🏙️ City").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.city_var = ctk.CTkEntry(self.input_frame, width=200)
        self.city_var.grid(row=1, column=1)

        ctk.CTkLabel(self.input_frame, text="💼 Industry").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.industry_var = ctk.CTkEntry(self.input_frame, width=200)
        self.industry_var.grid(row=2, column=1)

        ctk.CTkLabel(self.input_frame, text="🔢 Result Count").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.count_var = ctk.CTkEntry(self.input_frame, width=100)
        self.count_var.insert(0, "20")
        self.count_var.grid(row=3, column=1)

        self.filter_frame = ctk.CTkFrame(self.root)
        self.filter_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(self.filter_frame, text="Filters:", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, columnspan=3, sticky="w", padx=10)

        self.filter_active = ctk.CTkCheckBox(self.filter_frame, text="✅ Active Domain")
        self.filter_active.grid(row=1, column=0, padx=10)

        self.filter_shopify = ctk.CTkCheckBox(self.filter_frame, text="🛍️ Shopify Sites")
        self.filter_shopify.grid(row=1, column=1, padx=10)

        self.filter_fast = ctk.CTkCheckBox(self.filter_frame, text="⚡ Fast Loading (≤5s)")
        self.filter_fast.grid(row=1, column=2, padx=10)

        self.bottom_frame = ctk.CTkFrame(self.root)
        self.bottom_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.log_frame = ctk.CTkFrame(self.bottom_frame)
        self.log_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        ctk.CTkLabel(self.log_frame, text="📝 Log", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10, pady=(5, 0))
        self.log_box = ctk.CTkTextbox(self.log_frame, height=280)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_box.configure(state="disabled")

        self.results_frame = ctk.CTkScrollableFrame(self.bottom_frame)
        self.results_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))

        self.btn_frame = ctk.CTkFrame(self.root)
        self.btn_frame.pack(pady=10, fill="x")

        self.start_btn = ctk.CTkButton(self.btn_frame, text="🚀 Start Scraping", command=self.start_scraping, fg_color="green")
        self.start_btn.pack(side="left", padx=10)

        self.save_btn = ctk.CTkButton(self.btn_frame, text="💾 Save CSV", command=self.save_csv, state="disabled", fg_color="blue")
        self.save_btn.pack(side="left", padx=10)

    def log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def update_results(self, url, emails, phones):
        result_box = ctk.CTkFrame(self.results_frame)
        result_box.pack(fill="x", pady=5, padx=5)

        def add_section(label, items):
            frame = ctk.CTkFrame(result_box)
            frame.pack(fill="x", pady=3, padx=5)
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(weight="bold")).pack(anchor="w")
            for item in items or ["None"]:
                ctk.CTkLabel(frame, text=item).pack(anchor="w")

        add_section("🌐 URL", [url])
        add_section("📧 Emails", emails)
        add_section("📞 Phones", phones)
        ctk.CTkLabel(result_box, text="─" * 100).pack(pady=(5, 0))

    def start_scraping(self):
        country = self.country_var.get().strip()
        city = self.city_var.get().strip()
        industry = self.industry_var.get().strip()
        count_str = self.count_var.get().strip()

        if not (country and city and industry and count_str.isdigit()):
            messagebox.showwarning("Input Error", "Please fill in all fields correctly.")
            return

        self.start_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.final_data.clear()
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

        for widget in self.results_frame.winfo_children():
            widget.destroy()

        threading.Thread(target=self.scrape, args=(country, city, industry, int(count_str)), daemon=True).start()

    def scrape(self, country, city, industry, count):
        try:
            links = generate_search_links(country, city, industry, count, self.log)
            links = [link for link in links if is_valid_url(link["URL"])]
            seen = set()

            for idx, row in enumerate(links, 1):
                url = row["URL"]
                if url in seen:
                    continue
                seen.add(url)
                self.log(f"[{idx}/{len(links)}] {url}")

                if self.filter_active.get() and not is_domain_active_and_fast(url):
                    self.log("❌ Skipped: inactive or slow")
                    continue

                soup, emails, phones = extract_emails_and_phones_from_url(url, self.log)

                if self.filter_shopify.get() and (not soup or not is_shopify_site(soup)):
                    self.log("❌ Skipped: not Shopify")
                    continue

                if self.filter_fast.get():
                    try:
                        start = time.time()
                        r = requests.get(url, headers=get_random_headers(), timeout=5)
                        if time.time() - start > 5:
                            self.log("❌ Skipped: too slow")
                            continue
                    except:
                        self.log("❌ Skipped: error loading")
                        continue

                valid_emails = [email for email in emails if is_valid_email(email)]

                if not valid_emails and not phones:
                    self.log("❌ Skipped: no emails or phones found")
                    continue

                self.final_data.append({
                    **row,
                    "Emails": ", ".join(valid_emails),
                    "Phones": ", ".join(phones)
                })

                self.update_results(url, valid_emails, phones)

            self.log("✅ Scraping complete.")
            messagebox.showinfo("Done", "Scraping finished.")
            self.save_btn.configure(state="normal")
        except Exception as e:
            self.log(f"[ERROR] {e}")
            messagebox.showerror("Error", str(e))
        finally:
            self.start_btn.configure(state="normal")

    def save_csv(self):
        if not self.final_data:
            messagebox.showwarning("Nothing to save", "No data to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            pd.DataFrame(self.final_data).to_csv(path, index=False)
            messagebox.showinfo("Saved", f"Data saved to:\n{path}")

if __name__ == "__main__":
    app = ctk.CTk()
    ScraperApp(app)
    app.mainloop()
