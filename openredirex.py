#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import sys
import socket
from aiohttp import ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects
from tqdm import tqdm
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List, Optional


# Color constants
LIGHT_GREEN = '\033[92m'  # Light Green
DARK_GREEN = '\033[32m'   # Dark Green
ENDC = '\033[0m'          # Reset to default color

redirect_payloads = [
    # Your predefined payloads...
]

async def load_payloads(payloads_file: Optional[str]) -> List[str]:
    if payloads_file:
        with open(payloads_file) as f:
            return [line.strip() for line in f]
    return redirect_payloads  # Return hardcoded list if no file specified

def fuzzify_url(url: str, keyword: str) -> str:
    if keyword in url:
        return url

    parsed_url = urlparse(url)
    params = parse_qsl(parsed_url.query)
    fuzzed_params = [(k, keyword) for k, _ in params]
    fuzzed_query = urlencode(fuzzed_params)

    return urlunparse(
        [parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, fuzzed_query, parsed_url.fragment])

def load_urls() -> List[str]:
    urls = [fuzzify_url(line.strip(), "FUZZ") for line in sys.stdin]
    return urls

async def fetch_url(session: aiohttp.ClientSession, url: str):
    try:
        async with session.head(url, allow_redirects=True, timeout=10) as response:
            return response
    except (ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects, UnicodeDecodeError, socket.gaierror, asyncio.exceptions.TimeoutError) as e:
        tqdm.write(f'[ERROR] Error fetching {url}: {e}', file=sys.stderr)
        return None

async def process_url(semaphore: asyncio.Semaphore, session: aiohttp.ClientSession, url: str, payloads: List[str], keyword: str, pbar: tqdm):
    async with semaphore:
        for payload in payloads:
            filled_url = url.replace(keyword, payload)
            response = await fetch_url(session, filled_url)
            if response and response.history:
                locations = " --> ".join(str(r.url) for r in response.history)
                if "-->" in locations:
                    tqdm.write(f'{DARK_GREEN}[FOUND]{ENDC} {LIGHT_GREEN}{filled_url} redirects to {locations}{ENDC}')
                else:
                    tqdm.write(f'[INFO] {filled_url} redirects to {locations}')
            pbar.update()

async def process_urls(semaphore: asyncio.Semaphore, session: aiohttp.ClientSession, urls: List[str], payloads: List[str], keyword: str):
    with tqdm(total=len(urls) * len(payloads), ncols=70, desc='Processing', unit='url', position=0) as pbar:
        tasks = [process_url(semaphore, session, url, payloads, keyword, pbar) for url in urls]
        await asyncio.gather(*tasks, return_exceptions=True)

async def main(args):
    payloads = await load_payloads(args.payloads)
    urls = load_urls()
    tqdm.write(f'[INFO] Processing {len(urls)} URLs with {len(payloads)} payloads.')
    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(args.concurrency)
        await process_urls(semaphore, session, urls, payloads, args.keyword)

if __name__ == "__main__":
    banner = """
   ____                   ____           ___               
  / __ \____  ___  ____  / __ \___  ____/ (_)_______  _  __
 / / / / __ \/ _ \/ __ \/ /_/ / _ \/ __  / / ___/ _ \| |/_/
/ /_/ / /_/ /  __/ / / / _, _/  __/ /_/ / / /  /  __/>  <  
\____/ .___/\___/_/ /_/_/ |_|\___/\__,_/_/_/   \___/_/|_|  
    /_/                                                    

    """
    print(banner)
    parser = argparse.ArgumentParser(description="OpenRedireX : A fuzzer for detecting open redirect vulnerabilities")
    parser.add_argument('-p', '--payloads', help='file of payloads', required=False)
    parser.add_argument('-k', '--keyword', help='keyword in URLs to replace with payload (default is FUZZ)', default="FUZZ")
    parser.add_argument('-c', '--concurrency', help='number of concurrent tasks (default is 100)', type=int, default=100)
    parser.add_argument('-u', '--url', help='single URL to test')
    parser.add_argument('-Uu', '--urls', help='comma-separated URLs')
    args = parser.parse_args()

    if args.url and args.urls:
        parser.error("Cannot specify both --url and --urls")
    if args.url:
        sys.stdin = [args.url]
    elif args.urls:
        sys.stdin = args.urls.split(',')

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        sys.exit(0)
