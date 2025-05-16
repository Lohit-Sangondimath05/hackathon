import csv
import random
import re
import pandas as pd
import requests
from bs4 import BeautifulSoup
from serpapi import GoogleSearch
from fake_useragent import UserAgent
from validate_email import validate_email

# Your SerpAPI key here
SERPAPI_KEY = "00939b326b6715a3921068c5faf81d5f0e569813f4b61feb4dc7b524632f1090"  # Replace with your actual SerpAPI key

# Example proxy list — replace with working proxies or leave empty if not needed
PROXIES = [
    # "http://user:pass@proxy1.com:8080",  # proxy with auth
    # "http://103.216.82.216:6666",        # example public proxy
]

def get_random_proxy():
    if PROXIES:
        proxy = random.choice(PROXIES)
        return {"http": proxy, "https": proxy}
    return None

def get_random_headers():
    ua = UserAgent()
    return {"User-Agent": ua.random}

def generate_search_links(country, city, industry, count):
    query = f"{industry} in {city} {country}"
    search = GoogleSearch({
        "q": query,
        "api_key": SERPAPI_KEY,
        "num": count
    })
    results = search.get_dict()
    links = []
    for result in results.get("organic_results", []):
        links.append({
            "Country": country,
            "City": city,
            "Industry": industry,
            "URL": result.get("link", "")
        })
    return links

def extract_emails_from_url(url):
    try:
        response = requests.get(url, headers=get_random_headers(), proxies=get_random_proxy(), timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            return list(set(emails))
    except Exception as e:
        print(f"[ERROR] {url} failed: {e}")
    return []

def is_valid_email(email):
    try:
        return validate_email(email, verify=True)
    except Exception:
        return False

def main():
    country = input("Enter Country: ")
    city = input("Enter City: ")
    industry = input("Enter Industry Keyword: ")
    count = int(input("Enter Result Count: "))

    print("Generating search links...")
    links = generate_search_links(country, city, industry, count)

    # Save search links CSV
    search_df = pd.DataFrame(links)
    search_df.to_csv("search_links.csv", index=False)
    print("Saved search_links.csv")

    final_data = []
    for row in links:
        print(f"Scraping emails from: {row['URL']}")
        emails = extract_emails_from_url(row['URL'])
        for email in emails:
            if is_valid_email(email):
                final_data.append({
                    "Country": row["Country"],
                    "City": row["City"],
                    "Industry": row["Industry"],
                    "Website URL": row["URL"],
                    "Email ID": email
                })

    # Save final emails CSV
    final_df = pd.DataFrame(final_data)
    final_df.to_csv("final_contacts.csv", index=False)
    print("Saved final_contacts.csv")

if __name__ == "__main__":
    main()
