import asyncio
from pyppeteer import chromium_downloader
from pathlib import Path

REVISION = '1086792'  # example valid revision

async def main():
    print(f"Starting Chromium download for revision {REVISION}...")
    # Override the revision manually
    download_url = chromium_downloader._get_download_url(REVISION)
    print(f"Downloading from {download_url}")
    download_path = Path(chromium_downloader.DOWNLOADS_FOLDER) / REVISION

    if not download_path.exists():
        chromium_downloader.download_zip(download_url)
        chromium_downloader.extract_zip(download_url, download_path)
        print(f"Chromium downloaded and extracted to {download_path}")
    else:
        print(f"Chromium already downloaded at {download_path}")

asyncio.run(main())
