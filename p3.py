import re
import pandas as pd
from requests_html import HTMLSession
from urllib.parse import urljoin
import time

def extract_contact_info_from_url(url):
    session = HTMLSession()
    emails = set()
    phones = set()

    try:
        print(f"🔍 Processing URL: {url}")
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = session.get(url, headers=headers, timeout=20)

        try:
            response.html.render(timeout=30, sleep=2)
        except Exception as render_error:
            print(f"⚠️ Render failed for {url}: {render_error}")
            return [], []

        page_html = response.html.html

        if page_html:
            # Extract emails
            emails.update(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", page_html))

            # Extract phone numbers
            phone_pattern = r"""(?:(?:\+?\d{1,3}[-.\s]?)?    # Optional country code
                                 (?:\(?\d{3}\)?[-.\s]?)?     # Optional area code
                                 \d{3}[-.\s]?\d{4})"""       # Local number
            phones.update(re.findall(phone_pattern, page_html, re.VERBOSE))

            # Extract mailto and tel links
            for link in response.html.find('a'):
                href = link.attrs.get('href', '')
                if href.startswith('mailto:'):
                    email = href.replace('mailto:', '').split('?')[0]
                    if email:
                        emails.add(email)
                elif href.startswith('tel:'):
                    phone = href.replace('tel:', '').strip()
                    if phone:
                        phones.add(phone)

        print(f"✅ Found {len(emails)} emails and {len(phones)} phone numbers on {url}")
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
    finally:
        session.close()

    return list(emails), list(phones)

def main():
    input_csv = "search_links.csv"
    output_csv = "final_contacts.csv"
    results = []

    try:
        df = pd.read_csv(input_csv, encoding='utf-8')
    except Exception as e:
        print(f"❌ Error reading {input_csv}: {e}")
        return

    if "URL" not in df.columns:
        print(f"❌ 'URL' column missing in CSV")
        return

    for index, row in df.iterrows():
        url = str(row.get("URL", "")).strip()
        if not url.startswith("http"):
            print(f"⚠️ Skipping invalid URL at row {index}")
            continue

        emails, phones = extract_contact_info_from_url(url)

        base_data = {
            "Country": row.get("Country", ""),
            "City": row.get("City", ""),
            "Industry": row.get("Industry", ""),
            "Website URL": url
        }

        if not emails and not phones:
            results.append({**base_data, "Email ID": "", "Phone Number": ""})
        else:
            max_items = max(len(emails), len(phones))
            for i in range(max_items):
                results.append({
                    **base_data,
                    "Email ID": emails[i] if i < len(emails) else "",
                    "Phone Number": phones[i] if i < len(phones) else ""
                })

    try:
        pd.DataFrame(results).to_csv(output_csv, index=False, encoding='utf-8-sig')
        print(f"\n📁 Saved {len(results)} rows to {output_csv}")
    except Exception as e:
        print(f"❌ Failed to save to {output_csv}: {e}")

if __name__ == "__main__":
    main()
