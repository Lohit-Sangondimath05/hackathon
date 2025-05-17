import customtkinter as ctk
import threading
import pandas as pd
import re
import requests
import random
import time
import webbrowser
from bs4 import BeautifulSoup
from tkinter import messagebox, filedialog
from serpapi import GoogleSearch
from fake_useragent import UserAgent
from urllib.parse import urlparse, urljoin
import pyrebase

# --- Firebase config ---
config ={
  "apiKey": "AIzaSyDzEEuBlyeSfEgAT5yuL9dUkFZjXzRdpeo",
  "authDomain": "first1-59246.firebaseapp.com",
  "databaseURL": "https://first1-59246-id-default-rtdb.firebaseio.com",
  "projectId": "first1-59246",
  "storageBucket": "first1-59246.firebasestorage.app",
  "messagingSenderId": "294836761000",
  "appId": "1:294836761000:web:39dcfcdb68e4e445726d9d",
  "measurementId": "G-7FHFMFCCKL"
  
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()

SERPAPI_KEY = "00939b326b6715a3921068c5faf81d5f0e569813f4b61feb4dc7b524632f1090"
PROXIES = []

def firebase_sign_in(email, password):
    try:
        user = auth.sign_in_with_email_and_password(email, password)
        return user
    except:
        return None

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

def is_valid_phone(number):
    digits_only = re.sub(r"\D", "", number)
    if len(digits_only) < 8 or len(digits_only) > 15:
        return False
    if re.search(r"\b(19|20|21)\d{2}\b", number):
        return False
    if re.search(r"\b\d{4}\s*-\s*\d{4}\b", number):
        return False
    if not re.match(r"^\+?\d[\d\s\-\(\)]{7,}\d$", number):
        return False
    return True

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
            filtered_phones = [p.strip() for p in phones_found if is_valid_phone(p)]
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


# ----------- Login Screen --------------

class LoginScreen(ctk.CTk):
    def __init__(self, on_login_success):
        super().__init__()
        self.on_login_success = on_login_success
        self.title("🔐 Firebase Login")
        self.geometry("400x350+{}+{}".format(
            int(self.winfo_screenwidth()/2 - 200),
            int(self.winfo_screenheight()/2 - 175)
        ))
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.create_widgets()

    def create_widgets(self):
        frame = ctk.CTkFrame(self)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Email:").pack(pady=(10, 5))
        self.email_entry = ctk.CTkEntry(frame, width=300)
        self.email_entry.pack()

        ctk.CTkLabel(frame, text="Password:").pack(pady=(10, 5))
        self.password_entry = ctk.CTkEntry(frame, width=300, show="*")
        self.password_entry.pack()

        self.login_btn = ctk.CTkButton(frame, text="Login", command=self.login)
        self.login_btn.pack(pady=20)

        self.register_btn = ctk.CTkButton(frame, text="Register", command=self.open_register)
        self.register_btn.pack(pady=(0, 10))

    def login(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        if not email or not password:
            messagebox.showwarning("Input Error", "Please enter both email and password.")
            return
        result = firebase_sign_in(email, password)
        if result:
            messagebox.showinfo("Success", "Login successful!")
            self.destroy()
            self.on_login_success()
        else:
            messagebox.showerror("Login Failed", "Invalid email or password.")

    def open_register(self):
        RegisterScreen(self)


class RegisterScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("🔐 Register New User")
        self.geometry("400x400+{}+{}".format(
            int(self.winfo_screenwidth()/2 - 200),
            int(self.winfo_screenheight()/2 - 200)
        ))
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.create_widgets()

    def create_widgets(self):
        frame = ctk.CTkFrame(self)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Email:").pack(pady=(10, 5))
        self.email_entry = ctk.CTkEntry(frame, width=300)
        self.email_entry.pack()

        ctk.CTkLabel(frame, text="Password (min 6 chars):").pack(pady=(10, 5))
        self.password_entry = ctk.CTkEntry(frame, width=300, show="*")
        self.password_entry.pack()

        ctk.CTkLabel(frame, text="Confirm Password:").pack(pady=(10, 5))
        self.confirm_password_entry = ctk.CTkEntry(frame, width=300, show="*")
        self.confirm_password_entry.pack()

        self.register_btn = ctk.CTkButton(frame, text="Register", command=self.register)
        self.register_btn.pack(pady=20)

    def register(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        confirm_password = self.confirm_password_entry.get().strip()

        if not email or not password or not confirm_password:
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return
        if password != confirm_password:
            messagebox.showwarning("Input Error", "Passwords do not match.")
            return
        if len(password) < 6:
            messagebox.showwarning("Input Error", "Password must be at least 6 characters.")
            return

        try:
            auth.create_user_with_email_and_password(email, password)
            messagebox.showinfo("Success", "Registration successful! You can now log in.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to register user.\n{e}")


# ----------- Splash Screen --------------

class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.geometry("400x250+{}+{}".format(
            int(self.winfo_screenwidth()/2 - 200),
            int(self.winfo_screenheight()/2 - 125)
        ))
        self.overrideredirect(True)
        self.configure(fg_color="#1f1f1f")

        label = ctk.CTkLabel(self, text="🔍 Advanced Web Scraper", font=ctk.CTkFont(size=24, weight="bold"))
        label.pack(expand=True)

        sublabel = ctk.CTkLabel(self, text="Loading, please wait...", font=ctk.CTkFont(size=14))
        sublabel.pack(pady=(0, 30))

        self.after(3000, self.destroy)


# ----------- Main Scraper App --------------

class ScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("\U0001F4EC Advanced Web Scraper - Emails & Phones")
        self.root.geometry("1000x720")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")
        self.final_data = []
        self.create_widgets()

    def create_widgets(self):
        self.input_frame = ctk.CTkFrame(self.root)
        self.input_frame.pack(padx=10, pady=10, fill="x")

        ctk.CTkLabel(self.input_frame, text="\U0001F30D Country").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.country_var = ctk.CTkEntry(self.input_frame, width=200)
        self.country_var.grid(row=0, column=1)

        ctk.CTkLabel(self.input_frame, text="\U0001F3D9️ City").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.city_var = ctk.CTkEntry(self.input_frame, width=200)
        self.city_var.grid(row=1, column=1)

        ctk.CTkLabel(self.input_frame, text="\U0001F4BC Industry").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.industry_var = ctk.CTkEntry(self.input_frame, width=200)
        self.industry_var.grid(row=2, column=1)

        ctk.CTkLabel(self.input_frame, text="\U0001F522 Result Count").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.count_var = ctk.CTkEntry(self.input_frame, width=100)
        self.count_var.insert(0, "20")
        self.count_var.grid(row=3, column=1)

        self.filter_frame = ctk.CTkFrame(self.root)
        self.filter_frame.pack(pady=10, padx=10, fill="x")

        ctk.CTkLabel(self.filter_frame, text="Filters:", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, columnspan=4, sticky="w", padx=10)
        self.filter_active = ctk.CTkCheckBox(self.filter_frame, text="✅ Active Domain")
        self.filter_active.grid(row=1, column=0, padx=10)

        self.filter_shopify = ctk.CTkCheckBox(self.filter_frame, text="\U0001F6CD️ Shopify Sites")
        self.filter_shopify.grid(row=1, column=1, padx=10)

        self.filter_email = ctk.CTkCheckBox(self.filter_frame, text="📧 Emails")
        self.filter_email.grid(row=1, column=2, padx=10)

        self.filter_phone = ctk.CTkCheckBox(self.filter_frame, text="📞 Phones")
        self.filter_phone.grid(row=1, column=3, padx=10)

        self.run_btn = ctk.CTkButton(self.root, text="Start Scraping", command=self.start_scraping)
        self.run_btn.pack(pady=20)

        self.log_text = ctk.CTkTextbox(self.root, height=15)
        self.log_text.pack(padx=10, pady=10, fill="both", expand=True)

        self.save_btn = ctk.CTkButton(self.root, text="Save Results", command=self.save_results, state="disabled")
        self.save_btn.pack(pady=(0, 20))

    def log(self, message):
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.root.update()

    def start_scraping(self):
        country = self.country_var.get().strip()
        city = self.city_var.get().strip()
        industry = self.industry_var.get().strip()
        try:
            count = int(self.count_var.get().strip())
        except:
            messagebox.showerror("Input Error", "Result count must be a number.")
            return

        if not country or not city or not industry:
            messagebox.showwarning("Input Error", "Please fill all required fields.")
            return

        self.final_data = []
        self.log_text.delete("0.0", "end")
        self.save_btn.configure(state="disabled")
        self.run_btn.configure(state="disabled")

        threading.Thread(target=self.scrape_process, args=(country, city, industry, count), daemon=True).start()

    def scrape_process(self, country, city, industry, count):
        self.log("Starting search for URLs...")
        links = generate_search_links(country, city, industry, count, self.log)

        filter_active = self.filter_active.get()
        filter_shopify = self.filter_shopify.get()
        filter_email = self.filter_email.get()
        filter_phone = self.filter_phone.get()

        self.log(f"Found {len(links)} URLs. Starting detailed scraping...")

        for idx, link_data in enumerate(links):
            url = link_data["URL"]

            if filter_active and not is_domain_active_and_fast(url):
                self.log(f"[SKIP] Inactive or slow domain: {url}")
                continue

            soup, emails, phones = extract_emails_and_phones_from_url(url, self.log)
            if not soup:
                self.log(f"[ERROR] Could not fetch data from: {url}")
                continue

            if filter_shopify and not is_shopify_site(soup):
                self.log(f"[SKIP] Not a Shopify site: {url}")
                continue

            if filter_email and not emails:
                self.log(f"[SKIP] No emails found at: {url}")
                continue

            if filter_phone and not phones:
                self.log(f"[SKIP] No phones found at: {url}")
                continue

            link_data["Emails"] = ", ".join(emails) if emails else ""
            link_data["Phones"] = ", ".join(phones) if phones else ""
            self.final_data.append(link_data)
            self.log(f"[OK] Scraped {url}")

        self.log(f"Scraping complete. Found {len(self.final_data)} valid results.")
        self.save_btn.configure(state="normal")
        self.run_btn.configure(state="normal")

    def save_results(self):
        if not self.final_data:
            messagebox.showinfo("No Data", "No data to save.")
            return

        df = pd.DataFrame(self.final_data)
        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                                 filetypes=[("Excel files", "*.xlsx"), ("CSV files", "*.csv")])
        if file_path:
            try:
                if file_path.endswith(".csv"):
                    df.to_csv(file_path, index=False)
                else:
                    df.to_excel(file_path, index=False)
                messagebox.showinfo("Success", f"Results saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file.\n{e}")


# ----------- App launcher after login -----------

def launch_app():
    root = ctk.CTk()
    root.withdraw()

    splash = SplashScreen(root)
    splash.update()

    def show_main():
        splash.destroy()
        root.deiconify()
        ScraperApp(root)

    root.after(3000, show_main)
    root.mainloop()


# ----------- Main --------------

def main():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("dark-blue")

    def on_login_success():
        launch_app()

    login_screen = LoginScreen(on_login_success)
    login_screen.mainloop()


if __name__ == "__main__":
    main()
