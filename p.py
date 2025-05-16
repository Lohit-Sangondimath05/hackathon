import csv
import random
import re
import pandas as pd
import requests
from bs4 import BeautifulSoup
from serpapi import GoogleSearch
from fake_useragent import UserAgent

SERPAPI_KEY = "00939b326b6715a3921068c5faf81d5f0e569813f4b61feb4dc7b524632f1090"  # Replace your key here
PROXIES = []  # add proxies if needed

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

def extract_emails_and_phones_from_url(url):
    emails = set()
    phones = set()
    try:
        response = requests.get(url, headers=get_random_headers(), proxies=get_random_proxy(), timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)

            # Extract emails
            emails_found = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            emails.update(emails_found)

            # Extract phone numbers (various formats)
            phone_pattern = re.compile(
                r'''(
                (\+?\d{1,3}[\s-]?)?              # country code optional
                (\(?\d{3}\)?[\s-]?)?             # area code optional
                (\d{3}[\s-]?\d{4})               # number
                )''', re.VERBOSE)
            phones_found = phone_pattern.findall(text)
            # phones_found is list of tuples, first element is the full match
            for match in phones_found:
                phones.add(match[0].strip())

    except Exception as e:
        print(f"[ERROR] {url} failed: {e}")

    return list(emails), list(phones)

def is_valid_email_simple(email):
    # Basic validation: email contains @ and .
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

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
        url = row['URL']
        if not url:
            continue
        print(f"Scraping emails and phones from: {url}")
        emails, phones = extract_emails_and_phones_from_url(url)
        for email in emails:
            if is_valid_email_simple(email):
                final_data.append({
                    "Country": row["Country"],
                    "City": row["City"],
                    "Industry": row["Industry"],
                    "Website URL": url,
                    "Contact Type": "Email",
                    "Contact": email
                })
        for phone in phones:
            final_data.append({
                "Country": row["Country"],
                "City": row["City"],
                "Industry": row["Industry"],
                "Website URL": url,
                "Contact Type": "Phone",
                "Contact": phone
            })

    # Save final contacts CSV
    final_df = pd.DataFrame(final_data)
    final_df.to_csv("final_contacts.csv", index=False)
    print("Saved final_contacts.csv")

if __name__ == "__main__":
    main()
