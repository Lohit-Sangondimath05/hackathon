import random
import re
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import pandas as pd
import requests
from bs4 import BeautifulSoup
from serpapi import GoogleSearch
from fake_useragent import UserAgent
from urllib.parse import urlparse

# Replace with your actual SerpAPI key
SERPAPI_KEY = "00939b326b6715a3921068c5faf81d5f0e569813f4b61feb4dc7b524632f1090"

PROXIES = []  # Add proxies if needed

def get_random_proxy():
    if PROXIES:
        proxy = random.choice(PROXIES)
        return {"http": proxy, "https": proxy}
    return None

def get_random_headers():
    ua = UserAgent()
    return {"User-Agent": ua.random}

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def generate_search_links(country, city, industry, count, log_callback):
    query = f"{industry} in {city} {country}"
    log_callback(f"Searching for: {query}")
    search = GoogleSearch({
        "q": query,
        "api_key": SERPAPI_KEY,
        "num": count
    })
    results = search.get_dict()
    links = []
    for result in results.get("organic_results", []):
        link = result.get("link", "")
        if link:
            links.append({
                "Country": country,
                "City": city,
                "Industry": industry,
                "URL": link
            })
    log_callback(f"Found {len(links)} links from search.")
    return links

def extract_emails_and_phones_from_url(url, log_callback):
    emails = set()
    phones = set()
    try:
        log_callback(f"Requesting URL: {url}")
        response = requests.get(url, headers=get_random_headers(), proxies=get_random_proxy(), timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)

            emails_found = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            emails.update(emails_found)

            phone_pattern = re.compile(
                r'''(
                (\+?\d{1,3}[\s.-]?)?        # country code optional
                (\(?\d{2,4}\)?[\s.-]?)?     # area code optional
                (\d{3,4}[\s.-]?\d{3,4})     # local number
                )''', re.VERBOSE)
            phones_found = phone_pattern.findall(text)
            for match in phones_found:
                phones.add(match[0].strip())
        else:
            log_callback(f"Warning: HTTP {response.status_code} for {url}")
    except Exception as e:
        log_callback(f"[ERROR] Failed {url}: {e}")

    return list(emails), list(phones)

def is_valid_email_simple(email):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

class ScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email & Phone Scraper")
        self.root.geometry("700x600")
        self.root.resizable(False, False)

        self.create_widgets()
        self.final_data = []

    def create_widgets(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Inputs
        ttk.Label(frame, text="Country:").grid(column=0, row=0, sticky=tk.W, pady=5)
        self.country_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.country_var, width=30).grid(column=1, row=0, sticky=tk.W)

        ttk.Label(frame, text="City:").grid(column=0, row=1, sticky=tk.W, pady=5)
        self.city_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.city_var, width=30).grid(column=1, row=1, sticky=tk.W)

        ttk.Label(frame, text="Industry Keyword:").grid(column=0, row=2, sticky=tk.W, pady=5)
        self.industry_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.industry_var, width=30).grid(column=1, row=2, sticky=tk.W)

        ttk.Label(frame, text="Result Count:").grid(column=0, row=3, sticky=tk.W, pady=5)
        self.count_var = tk.StringVar(value="10")
        ttk.Entry(frame, textvariable=self.count_var, width=10).grid(column=1, row=3, sticky=tk.W)

        # Buttons
        self.start_button = ttk.Button(frame, text="Start Scraping", command=self.start_scraping)
        self.start_button.grid(column=0, row=4, pady=15, sticky=tk.W)

        self.save_button = ttk.Button(frame, text="Save Contacts CSV", command=self.save_csv, state=tk.DISABLED)
        self.save_button.grid(column=1, row=4, pady=15, sticky=tk.W)

        # Log / Output box
        ttk.Label(frame, text="Log / Progress:").grid(column=0, row=5, sticky=tk.W)
        self.log_box = scrolledtext.ScrolledText(frame, width=80, height=25, state=tk.DISABLED)
        self.log_box.grid(column=0, row=6, columnspan=2, pady=5)

    def log(self, message):
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.insert(tk.END, message + "\n")
        self.log_box.see(tk.END)
        self.log_box.configure(state=tk.DISABLED)

    def start_scraping(self):
        country = self.country_var.get().strip()
        city = self.city_var.get().strip()
        industry = self.industry_var.get().strip()
        count_str = self.count_var.get().strip()

        if not (country and city and industry):
            messagebox.showwarning("Input Error", "Please fill in Country, City and Industry.")
            return
        if not count_str.isdigit() or int(count_str) <= 0:
            messagebox.showwarning("Input Error", "Please enter a positive integer for Result Count.")
            return
        count = int(count_str)

        # Disable buttons while running
        self.start_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)
        self.log_box.configure(state=tk.NORMAL)
        self.log_box.delete(1.0, tk.END)
        self.log_box.configure(state=tk.DISABLED)

        self.final_data.clear()

        # Run scraping in a thread to keep UI responsive
        threading.Thread(target=self.scrape, args=(country, city, industry, count), daemon=True).start()

    def scrape(self, country, city, industry, count):
        try:
            links = generate_search_links(country, city, industry, count, self.log)
            links = [link for link in links if is_valid_url(link.get("URL", ""))]

            self.log(f"Filtered to {len(links)} valid URLs.")

            for idx, row in enumerate(links, 1):
                url = row['URL']
                self.log(f"[{idx}/{len(links)}] Scraping: {url}")
                emails, phones = extract_emails_and_phones_from_url(url, self.log)

                for email in emails:
                    if is_valid_email_simple(email):
                        self.final_data.append({
                            "Country": row["Country"],
                            "City": row["City"],
                            "Industry": row["Industry"],
                            "Website URL": url,
                            "Contact Type": "Email",
                            "Contact": email
                        })

                for phone in phones:
                    self.final_data.append({
                        "Country": row["Country"],
                        "City": row["City"],
                        "Industry": row["Industry"],
                        "Website URL": url,
                        "Contact Type": "Phone",
                        "Contact": phone
                    })

            self.log("Scraping completed.")
            messagebox.showinfo("Done", "Scraping completed successfully!")
            self.save_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log(f"[ERROR] {e}")
            messagebox.showerror("Error", f"An error occurred:\n{e}")
        finally:
            self.start_button.config(state=tk.NORMAL)

    def save_csv(self):
        if not self.final_data:
            messagebox.showwarning("No Data", "No contact data to save.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")],
                                                 title="Save contacts CSV")
        if file_path:
            df = pd.DataFrame(self.final_data)
            df.to_csv(file_path, index=False)
            messagebox.showinfo("Saved", f"Contacts saved to:\n{file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use('clam')  # nicer modern theme
    app = ScraperApp(root)
    root.mainloop()

