import customtkinter as ctk
import threading
import pandas as pd
import re
import requests
import json
import time
import os
import random
import webbrowser
from tkinter import messagebox, filedialog
from bs4 import BeautifulSoup
from serpapi import GoogleSearch
from dotenv import load_dotenv
from fake_useragent import UserAgent
from validate_email import validate_email
from tenacity import retry, stop_after_attempt, wait_exponential
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence
from langchain_groq import ChatGroq
from urllib.parse import urlparse, urljoin
import pyrebase

# Load environment variables
load_dotenv()
SERPAPI_KEY = os.getenv("SERPAPI_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not SERPAPI_KEY or not GROQ_API_KEY:
    messagebox.showerror("Error", "Missing SERPAPI_KEY or GROQ_API_KEY in .env file.")
    exit()

# Firebase configuration
config = {
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

# Initialize LLM
model = ChatGroq(
    model="llama-3.3-70b-versatile",
    api_key=GROQ_API_KEY,
    temperature=0,
    max_tokens=1500
)

# Firebase authentication functions
def firebase_sign_in(email, password):
    try:
        user = auth.sign_in_with_email_and_password(email, password)
        return user
    except:
        return None

def firebase_register(email, password):
    try:
        user = auth.create_user_with_email_and_password(email, password)
        return user
    except:
        return None

# Common utility functions
def get_random_headers():
    ua = UserAgent()
    return {
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except:
        return False

def is_valid_email(email):
    try:
        return validate_email(email, verify=False)
    except:
        return False

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

def is_shopify_site(soup):
    return "cdn.shopify.com" in str(soup) or "Shopify" in soup.text

def is_domain_active_and_fast(url, timeout=5):
    try:
        start = time.time()
        r = requests.get(url, headers=get_random_headers(), timeout=timeout)
        return r.status_code == 200 and (time.time() - start) <= timeout
    except:
        return False

# Default Mode functions
def generate_search_links_default(country, city, industry, count, log_callback):
    query = f"{industry} in {city}, {country}"
    log_callback(f"🔍 Searching: {query}")
    try:
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
    except Exception as e:
        log_callback(f"❌ [ERROR] Search failed: {e}")
        return []

def extract_emails_and_phones_default(url, log_callback):
    emails = set()
    phones = set()
    visited = set()

    def extract(url):
        if url in visited or not is_valid_url(url):
            return None
        visited.add(url)
        try:
            log_callback(f"🌐 Fetching: {url}")
            r = requests.get(url, headers=get_random_headers(), timeout=10)
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
            log_callback(f"❌ [ERROR] {url}: {e}")
            return None

    soup = extract(url)
    return soup, list(emails), list(phones)

# Query Mode functions
def extract_query_intent(query):
    prompt_template = PromptTemplate.from_template(
        """
        You are an assistant that analyzes a natural language query to determine its intent and extract relevant parameters for finding companies.
        The query is: "{query}"
        Extract the following details and return them in a structured JSON format:
        - Intent
        - Industry
        - Location
        - Keywords
        """
    )
    chain = RunnableSequence(prompt_template | model)
    try:
        result = chain.invoke({"query": query})
        text = result.content.strip()
        if text.startswith("```json"):
            text = text[7:-3].strip()
        return json.loads(text)
    except Exception as e:
        return {
            "Intent": "Unknown",
            "Industry": "Unknown",
            "Location": "Unknown",
            "Keywords": [query.lower()]
        }

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=4, max=10))
def generate_search_links_query(query, intent, industry, location, keywords, count, log_callback):
    base_query = f"{industry} companies" if industry != "Unknown" else "companies"
    if location != "Unknown":
        base_query += f" in {location}"
    if keywords:
        base_query += " " + " ".join(keywords)
    search_query = f"site:.com | site:.org {base_query} company websites | company contact"

    log_callback(f"🔍 Searching: {search_query}")
    params = {
        "q": search_query,
        "api_key": SERPAPI_KEY,
        "num": min(count, 10),
        "engine": "google"
    }
    client = GoogleSearch(params)
    results = client.get_dict()
    links = []
    excluded = ["youtube.com", "linkedin.com", "facebook.com", "twitter.com", "instagram.com"]

    for result in results.get("organic_results", []):
        url = result.get("link", "")
        if is_valid_url(url) and not any(domain in url for domain in excluded):
            links.append({
                "Intent": intent,
                "Industry": industry,
                "Location": location,
                "URL": url
            })
    return links[:count]

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=4, max=10))
def extract_contact_info_query(url, log_callback):
    emails = set()
    phones = set()
    visited = set()

    def extract(url):
        if url in visited or not is_valid_url(url):
            return None
        visited.add(url)
        try:
            log_callback(f"🌐 Fetching: {url}")
            response = requests.get(url, headers=get_random_headers(), timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)

            emails.update(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}", text))
            phone_patterns = [
                r"\(\d{3}\)\s*\d{3}-\d{4}",
                r"\d{3}-\d{3}-\d{4}",
                r"\+91\s*\d{10}",
                r"\+?\d[\d\s\-\(\)]{7,}\d"
            ]
            for pat in phone_patterns:
                found = re.findall(pat, text)
                phones.update(p for p in found if is_valid_phone(p))

            contact_links = [
                urljoin(url, a['href']) for a in soup.find_all("a", href=True)
                if any(k in a['href'].lower() for k in ["contact", "about", "support"])
            ]
            for clink in contact_links[:2]:
                try:
                    res = requests.get(clink, headers=get_random_headers(), timeout=5)
                    page_soup = BeautifulSoup(res.text, 'html.parser')
                    page_text = page_soup.get_text(separator=' ', strip=True)
                    emails.update(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}", page_text))
                    for pat in phone_patterns:
                        found = re.findall(pat, page_text)
                        phones.update(p for p in found if is_valid_phone(p))
                except:
                    pass
            return soup
        except Exception as e:
            log_callback(f"❌ [ERROR] {url}: {e}")
            return None

    soup = extract(url)
    valid_emails = [e for e in emails if is_valid_email(e)] or ["None"]
    valid_phones = list(phones) or ["None"]
    return soup, valid_emails, valid_phones

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=4, max=10))
def extract_webpage_content(url):
    try:
        res = requests.get(url, headers=get_random_headers(), timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        content = soup.get_text(separator=" ", strip=True)
        return re.sub(r"\s+", " ", content)[:2000]
    except:
        return ""

def summarize_content(content, url, intent, industry):
    prompt_template = PromptTemplate.from_template(
        """
        Summarize the following content from: {url}
        Intent: {intent}
        Industry: {industry}
        Content: {content}
        Limit summary to 150 words.
        """
    )
    chain = RunnableSequence(prompt_template | model)
    try:
        result = chain.invoke({
            "url": url,
            "intent": intent,
            "industry": industry,
            "content": content
        })
        return result.content.strip()
    except:
        return "No summary available."

# Login Screen
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

        ctk.CTkLabel(frame, text="Email:", font=ctk.CTkFont(size=14)).pack(pady=(10, 5))
        self.email_entry = ctk.CTkEntry(frame, width=300, placeholder_text="Enter your email")
        self.email_entry.pack()

        ctk.CTkLabel(frame, text="Password:", font=ctk.CTkFont(size=14)).pack(pady=(10, 5))
        self.password_entry = ctk.CTkEntry(frame, width=300, show="*", placeholder_text="Enter your password")
        self.password_entry.pack()

        self.login_btn = ctk.CTkButton(frame, text="Login", command=self.login, fg_color="green", hover_color="darkgreen")
        self.login_btn.pack(pady=20)

        self.register_btn = ctk.CTkButton(frame, text="Register", command=self.open_register, fg_color="blue", hover_color="darkblue")
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

# Register Screen
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

        ctk.CTkLabel(frame, text="Email:", font=ctk.CTkFont(size=14)).pack(pady=(10, 5))
        self.email_entry = ctk.CTkEntry(frame, width=300, placeholder_text="Enter your email")
        self.email_entry.pack()

        ctk.CTkLabel(frame, text="Password (min 6 chars):", font=ctk.CTkFont(size=14)).pack(pady=(10, 5))
        self.password_entry = ctk.CTkEntry(frame, width=300, show="*", placeholder_text="Enter your password")
        self.password_entry.pack()

        ctk.CTkLabel(frame, text="Confirm Password:", font=ctk.CTkFont(size=14)).pack(pady=(10, 5))
        self.confirm_password_entry = ctk.CTkEntry(frame, width=300, show="*", placeholder_text="Confirm your password")
        self.confirm_password_entry.pack()

        self.register_btn = ctk.CTkButton(frame, text="Register", command=self.register, fg_color="blue", hover_color="darkblue")
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

        result = firebase_register(email, password)
        if result:
            messagebox.showinfo("Success", "Registration successful! You can now log in.")
            self.destroy()
        else:
            messagebox.showerror("Error", "Failed to register user. Please try again.")

# Splash Screen
class SplashScreen(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.geometry("500x300+{}+{}".format(
            int(self.winfo_screenwidth()/2 - 250),
            int(self.winfo_screenheight()/2 - 150)
        ))
        self.overrideredirect(True)
        self.configure(fg_color="#1E1E1E")

        frame = ctk.CTkFrame(self, corner_radius=15)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(frame, text="🔍 Advanced Web Scraper", font=ctk.CTkFont(size=28, weight="bold")).pack(pady=20)
        ctk.CTkLabel(frame, text="Initializing...", font=ctk.CTkFont(size=16)).pack()
        self.progress = ctk.CTkProgressBar(frame, mode="indeterminate")
        self.progress.pack(fill="x", padx=50, pady=20)
        self.progress.start()

        self.after(3000, self.destroy)

# GUI Application
class ScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("\U0001F4EC Advanced Web Scraper")
        self.root.geometry("1200x800")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        self.final_data = []
        self.exclude_domains_file = None
        self.progress = 0
        self.status_text = ctk.StringVar(value="Ready")
        self.create_widgets()

    def create_widgets(self):
        # Main container with sidebar and content
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self.main_frame, width=200, corner_radius=10)
        self.sidebar.pack(side="left", fill="y", padx=(0, 10))
        ctk.CTkLabel(self.sidebar, text="⚙ Settings", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        # Theme toggle
        ctk.CTkLabel(self.sidebar, text="Theme").pack(pady=(10, 5))
        self.theme_var = ctk.StringVar(value="Dark")
        ctk.CTkOptionMenu(self.sidebar, values=["Light", "Dark", "System"], variable=self.theme_var, command=self.change_theme).pack(fill="x", padx=10)
        
        # Clear logs
        ctk.CTkButton(self.sidebar, text="🗑 Clear Logs", command=self.clear_logs, fg_color="gray").pack(pady=10, padx=10, fill="x")
        
        # About button
        ctk.CTkButton(self.sidebar, text="ℹ About", command=lambda: messagebox.showinfo("About", "Advanced Web Scraper\nVersion 1.0\n© 2025 xAI"), fg_color="gray").pack(pady=10, padx=10, fill="x")

        # Content area
        self.content_frame = ctk.CTkFrame(self.main_frame, corner_radius=10)
        self.content_frame.pack(side="left", fill="both", expand=True)

        # Tabview for modes
        self.tabview = ctk.CTkTabview(self.content_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabview.add("Default Mode")
        self.tabview.add("Query Mode")

        # Default Mode Tab
        default_tab = self.tabview.tab("Default Mode")
        input_frame = ctk.CTkFrame(default_tab)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Default inputs
        ctk.CTkLabel(input_frame, text="\U0001F30D Country", font=ctk.CTkFont(size=14)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.country_var = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., USA")
        self.country_var.grid(row=0, column=1, pady=5)
        
        ctk.CTkLabel(input_frame, text="\U0001F3D9 City", font=ctk.CTkFont(size=14)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.city_var = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., New York")
        self.city_var.grid(row=1, column=1, pady=5)
        
        ctk.CTkLabel(input_frame, text="\U0001F4BC Industry", font=ctk.CTkFont(size=14)).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.industry_var = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., Technology")
        self.industry_var.grid(row=2, column=1, pady=5)
        
        ctk.CTkLabel(input_frame, text="\U0001F522 Result Count", font=ctk.CTkFont(size=14)).grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.count_var = ctk.CTkEntry(input_frame, width=100, placeholder_text="e.g., 5")
        self.count_var.insert(0, "5")
        self.count_var.grid(row=3, column=1, sticky="w", pady=5)

        # Query Mode Tab
        query_tab = self.tabview.tab("Query Mode")
        query_input_frame = ctk.CTkFrame(query_tab)
        query_input_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(query_input_frame, text="\U0001F50D Query", font=ctk.CTkFont(size=14)).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.query_var = ctk.CTkEntry(query_input_frame, width=500, placeholder_text="e.g., tech companies in San Francisco")
        self.query_var.grid(row=0, column=1, pady=5)
        
        ctk.CTkLabel(query_input_frame, text="\U0001F522 Result Count", font=ctk.CTkFont(size=14)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.count_var_query = ctk.CTkEntry(query_input_frame, width=100, placeholder_text="e.g., 5")
        self.count_var_query.insert(0, "5")
        self.count_var_query.grid(row=1, column=1, sticky="w", pady=5)

        # Filter frame
        self.filter_frame = ctk.CTkFrame(self.content_frame)
        self.filter_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.filter_frame, text="🔧 Filters", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10)
        
        filter_checks = ctk.CTkFrame(self.filter_frame)
        filter_checks.pack(fill="x", padx=10, pady=5)
        self.filter_active = ctk.CTkCheckBox(filter_checks, text="✅ Active Domain")
        self.filter_active.pack(side="left", padx=10)
        self.filter_shopify = ctk.CTkCheckBox(filter_checks, text="\U0001F6CD Shopify Sites")
        self.filter_shopify.pack(side="left", padx=10)
        self.filter_fast = ctk.CTkCheckBox(filter_checks, text="⚡ Fast Loading (≤5s)")
        self.filter_fast.pack(side="left", padx=10)
        
        exclude_frame = ctk.CTkFrame(self.filter_frame)
        exclude_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(exclude_frame, text="📑 Exclude Domains (CSV):").pack(side="left", padx=10)
        self.exclude_domains_btn = ctk.CTkButton(exclude_frame, text="Select CSV", command=self.select_exclude_domains_csv, width=100)
        self.exclude_domains_btn.pack(side="left", padx=5)
        self.exclude_domains_label = ctk.CTkLabel(exclude_frame, text="No file selected", text_color="gray")
        self.exclude_domains_label.pack(side="left", padx=10)

        # Action buttons
        self.btn_frame = ctk.CTkFrame(self.content_frame)
        self.btn_frame.pack(fill="x", padx=10, pady=10)
        self.start_btn = ctk.CTkButton(self.btn_frame, text="\U0001F680 Start Scraping", command=self.start_scraping, fg_color="green", hover_color="darkgreen")
        self.start_btn.pack(side="left", padx=10)
        self.save_btn = ctk.CTkButton(self.btn_frame, text="\U0001F4BE Save CSV", command=self.save_csv, state="disabled", fg_color="blue", hover_color="darkblue")
        self.save_btn.pack(side="left", padx=10)
        self.clear_btn = ctk.CTkButton(self.btn_frame, text="🧹 Clear Inputs", command=self.clear_inputs, fg_color="gray", hover_color="darkgray")
        self.clear_btn.pack(side="left", padx=10)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.content_frame)
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        self.progress_bar.set(0)

        # Output area
        self.output_frame = ctk.CTkFrame(self.content_frame)
        self.output_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.log_frame = ctk.CTkFrame(self.output_frame)
        self.log_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        ctk.CTkLabel(self.log_frame, text="\U0001F4DD Log", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=10)
        self.log_box = ctk.CTkTextbox(self.log_frame, height=300, wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_box.configure(state="disabled")

        self.results_frame = ctk.CTkScrollableFrame(self.output_frame)
        self.results_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))

        # Status bar
        self.status_bar = ctk.CTkFrame(self.content_frame, height=30)
        self.status_bar.pack(fill="x", side="bottom")
        ctk.CTkLabel(self.status_bar, textvariable=self.status_text, font=ctk.CTkFont(size=12)).pack(side="left", padx=10)

    def change_theme(self, theme):
        ctk.set_appearance_mode(theme)
        self.log("🎨 Theme changed to: " + theme)

    def clear_logs(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self.log("🗑 Logs cleared")

    def clear_inputs(self):
        self.country_var.delete(0, "end")
        self.city_var.delete(0, "end")
        self.industry_var.delete(0, "end")
        self.count_var.delete(0, "end")
        self.count_var.insert(0, "5")
        self.query_var.delete(0, "end")
        self.count_var_query.delete(0, "end")
        self.count_var_query.insert(0, "5")
        self.filter_active.deselect()
        self.filter_shopify.deselect()
        self.filter_fast.deselect()
        self.exclude_domains_file = None
        self.exclude_domains_label.configure(text="No file selected")
        self.log("🧹 Inputs cleared")

    def select_exclude_domains_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.exclude_domains_file = file_path
            self.exclude_domains_label.configure(text=os.path.basename(file_path))
            self.log(f"📑 Selected exclude domains CSV: {file_path}")
        else:
            self.exclude_domains_file = None
            self.exclude_domains_label.configure(text="No file selected")

    def read_exclude_domains(self):
        if not self.exclude_domains_file:
            return []
        try:
            df = pd.read_csv(self.exclude_domains_file)
            if "Domain" in df.columns:
                domains = df["Domain"].dropna().str.strip().str.lower().tolist()
            else:
                domains = df.iloc[:, 0].dropna().str.strip().str.lower().tolist()
            self.log(f"📑 Loaded {len(domains)} domains from CSV")
            return domains
        except Exception as e:
            self.log(f"❌ [ERROR] Failed to read CSV: {e}")
            messagebox.showerror("Error", f"Failed to read CSV file: {e}")
            return []

    def log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
        self.root.update()

    def update_results(self, url, emails, phones, summary=None):
        result_box = ctk.CTkFrame(self.results_frame, corner_radius=10)
        result_box.pack(fill="x", pady=5, padx=5)

        def create_clickable_label(parent, text, link, is_mail=False):
            label = ctk.CTkLabel(parent, text=text, text_color="#1E90FF", cursor="hand2")
            label.pack(anchor="w", padx=5)
            label.bind("<Button-1>", lambda e: webbrowser.open(f"mailto:{link}" if is_mail else link))

        def add_section(label, items, is_mail=False, clickable=True):
            frame = ctk.CTkFrame(result_box, fg_color="transparent")
            frame.pack(fill="x", pady=2, padx=5)
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            if not items or items == ["None"]:
                ctk.CTkLabel(frame, text="None", text_color="gray").pack(anchor="w", padx=5)
            else:
                for item in items:
                    if clickable:
                        create_clickable_label(frame, item, item, is_mail)
                    else:
                        ctk.CTkLabel(frame, text=item, wraplength=400).pack(anchor="w", padx=5)

        add_section("🌐 URL", [url], clickable=True)
        add_section("📧 Emails", emails, is_mail=True)
        add_section("📞 Phones", phones, clickable=False)
        if summary and self.tabview.get() == "Query Mode":
            add_section("📝 Summary", [summary], clickable=False)
        ctk.CTkLabel(result_box, text="─" * 100, text_color="gray").pack(pady=(5, 0))
        self.root.update()

    def start_scraping(self):
        count_str = self.count_var.get().strip() if self.tabview.get() == "Default Mode" else self.count_var_query.get().strip()
        if not count_str.isdigit():
            messagebox.showwarning("Input Error", "Please enter a valid result count.")
            return

        if self.tabview.get() == "Default Mode":
            country = self.country_var.get().strip()
            city = self.city_var.get().strip()
            industry = self.industry_var.get().strip()
            if not (country and city and industry):
                messagebox.showwarning("Input Error", "Please fill in all fields (country, city, industry).")
                return
        else:
            query = self.query_var.get().strip()
            if not query:
                messagebox.showwarning("Input Error", "Please enter a valid query.")
                return

        self.start_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self.clear_btn.configure(state="disabled")
        self.final_data.clear()
        self.progress_bar.set(0)
        self.status_text.set("Scraping in progress...")
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

        for widget in self.results_frame.winfo_children():
            widget.destroy()

        if self.tabview.get() == "Default Mode":
            threading.Thread(target=self.scrape_default, args=(country, city, industry, int(count_str)), daemon=True).start()
        else:
            threading.Thread(target=self.scrape_query, args=(query, int(count_str)), daemon=True).start()

    def scrape_default(self, country, city, industry, count):
        try:
            self.status_text.set(f"Searching for {industry} in {city}, {country}")
            links = generate_search_links_default(country, city, industry, count, self.log)
            links = [link for link in links if is_valid_url(link["URL"])]

            exclude_domains = self.read_exclude_domains()
            seen = set()

            for idx, row in enumerate(links, 1):
                url = row["URL"]
                if url in seen:
                    continue
                seen.add(url)

                domain = urlparse(url).netloc.lower()
                if any(ex_domain in domain for ex_domain in exclude_domains):
                    self.log(f"❌ Skipped excluded domain: {domain}")
                    continue

                self.log(f"[{idx}/{len(links)}] Processing {url}")
                self.progress_bar.set(idx / len(links))
                self.status_text.set(f"Processing {idx}/{len(links)}: {url[:30]}...")

                if self.filter_active.get() and not is_domain_active_and_fast(url):
                    self.log("❌ Skipped: inactive or slow")
                    continue

                soup, emails, phones = extract_emails_and_phones_default(url, self.log)

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
                valid_phones = [phone for phone in phones if is_valid_phone(phone)]

                if not valid_phones:
                    self.log("❌ Skipped: no valid phone numbers")
                    continue

                self.final_data.append({
                    **row,
                    "Emails": ", ".join(valid_emails),
                    "Phones": ", ".join(valid_phones)
                })

                self.update_results(url, valid_emails, valid_phones)

            self.log("✅ Scraping complete.")
            self.status_text.set("Scraping complete")
            self.progress_bar.set(1)
            messagebox.showinfo("Done", "Scraping finished.")
            self.save_btn.configure(state="normal")
        except Exception as e:
            self.log(f"❌ [ERROR] {e}")
            self.status_text.set("Error occurred")
            messagebox.showerror("Error", str(e))
        finally:
            self.start_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")

    def scrape_query(self, query, count):
        try:
            self.status_text.set(f"Processing query: {query}")
            self.log(f"🔍 Processing query: {query}")
            intent_data = extract_query_intent(query)
            intent_data = {
                "intent": intent_data.get("Intent", "Unknown"),
                "industry": intent_data.get("Industry", "Unknown"),
                "location": intent_data.get("Location", "Unknown"),
                "keywords": intent_data.get("Keywords", [])
            }
            self.log(f"✅ Intent: {json.dumps(intent_data, indent=2)}")

            links = generate_search_links_query(query, **intent_data, count=count, log_callback=self.log)
            if not links:
                self.log("❌ No valid links found.")
                self.status_text.set("No results found")
                messagebox.showinfo("Done", "No results found.")
                return

            self.log(f"🔗 Found {len(links)} links.")
            exclude_domains = self.read_exclude_domains()
            seen = set()

            for idx, row in enumerate(links, 1):
                url = row["URL"]
                if url in seen:
                    continue
                seen.add(url)

                domain = urlparse(url).netloc.lower()
                if any(ex_domain in domain for ex_domain in exclude_domains):
                    self.log(f"❌ Skipped excluded domain: {domain}")
                    continue

                self.log(f"[{idx}/{len(links)}] Processing {url}")
                self.progress_bar.set(idx / len(links))
                self.status_text.set(f"Processing {idx}/{len(links)}: {url[:30]}...")

                if self.filter_active.get() and not is_domain_active_and_fast(url):
                    self.log("❌ Skipped: inactive or slow")
                    continue

                soup, emails, phones = extract_contact_info_query(url, self.log)

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

                content = extract_webpage_content(url)
                summary = summarize_content(content, url, intent_data["intent"], intent_data["industry"])

                self.final_data.append({
                    **row,
                    "Emails": ", ".join(emails),
                    "Phones": ", ".join(phones),
                    "Summary": summary
                })

                self.update_results(url, emails, phones, summary)

            self.log("✅ Scraping complete.")
            self.status_text.set("Scraping complete")
            self.progress_bar.set(1)
            messagebox.showinfo("Done", "Scraping finished.")
            self.save_btn.configure(state="normal")
        except Exception as e:
            self.log(f"❌ [ERROR] {e}")
            self.status_text.set("Error occurred")
            messagebox.showerror("Error", str(e))
        finally:
            self.start_btn.configure(state="normal")
            self.clear_btn.configure(state="normal")

    def save_csv(self):
        if not self.final_data:
            messagebox.showwarning("Nothing to save", "No data to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            pd.DataFrame(self.final_data).to_csv(path, index=False)
            self.log(f"💾 Data saved to: {path}")
            messagebox.showinfo("Saved", f"Data saved to:\n{path}")

# App launcher after login
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

# Main function
def main():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")

    def on_login_success():
        launch_app()
    
    login_screen = LoginScreen(on_login_success)
    login_screen.mainloop()

if __name__ == "__main__":
    main()