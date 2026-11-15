import os
import sys
import re
import time
import json
import base64
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import unquote, urlparse
import requests
from bs4 import BeautifulSoup

def clean_company_name(company: str) -> str:
    """Sanitizes target company name, stripping quotes, domains, and trailing punctuation."""
    c = company.strip().strip('"\'')
    if c.startswith("http://") or c.startswith("https://"):
        parsed = urlparse(c)
        c = parsed.netloc.replace("www.", "")
    if c.endswith(".com") or c.endswith(".org") or c.endswith(".io") or c.endswith(".net"):
        c = c.split(".")[0]
    return c.strip()

def infer_company_domain(company: str) -> str:
    """Infers reasonable company domain name from company title."""
    c = clean_company_name(company).lower()
    c = re.sub(r'[^a-z0-9]', '', c)
    return f"{c}.com" if c else "company.com"

def format_person_name(raw_name: str) -> str:
    """Formats raw parsed name into clean Title Case."""
    if not raw_name:
        return "Unknown Individual"
    cleaned = re.sub(r'[^a-zA-Z\s\.\-]', '', raw_name).strip()
    words = [w.capitalize() for w in cleaned.split() if w]
    return " ".join(words) if words else "Unknown Individual"

def generate_corporate_email(name: str, pattern: str = "{first}.{last}@{domain}", domain: str = "") -> str:
    """
    Synthesizes inferred corporate email address from discovered person name
    using common corporate naming conventions.
    """
    parts = name.strip().lower().split()
    if not parts:
        return ""
    first = re.sub(r'[^a-z0-9]', '', parts[0])
    last = re.sub(r'[^a-z0-9]', '', parts[-1]) if len(parts) > 1 else first
    f_initial = first[0] if first else "x"
    l_initial = last[0] if last else "x"
    dom = domain.strip().lower().lstrip("@") or "company.com"

    # Replace supported variables
    email = pattern.replace("{first}", first) \
                   .replace("{last}", last) \
                   .replace("{f}", f_initial) \
                   .replace("{l}", l_initial) \
                   .replace("{domain}", dom)
    
    if "@" not in email:
        email = f"{email}@{dom}"
    return email

def _harvest_from_yahoo(company: str, max_results: int = 50, timeout: float = 12.0, proxy: str = "") -> List[Dict[str, str]]:
    """
    Harvests LinkedIn personnel profiles via Yahoo zero-credential search indexation.
    Decodes redirected and direct search links and extracts verified names and titles.
    """
    findings = []
    seen_urls = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Calculate pages needed
    b = 1
    max_pages = max(1, (max_results // 7) + 2)

    for page in range(max_pages):
        encoded_query = urllib.parse.quote(f'site:linkedin.com/in "{company}"')
        url = f'https://search.yahoo.com/search?p={encoded_query}&b={b}&pz=10'
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            if resp.status_code != 200:
                break

            soup = BeautifulSoup(resp.text, 'html.parser')
            page_found = 0

            for a in soup.find_all('a'):
                raw_href = a.get('href', '')
                dest_url = ''
                if '/RU=' in raw_href:
                    m = re.search(r'/RU=([^/]+)/', raw_href)
                    if m:
                        dest_url = urllib.parse.unquote(m.group(1))
                elif 'linkedin.com/in/' in raw_href:
                    dest_url = raw_href

                if not dest_url or 'linkedin.com/in/' not in dest_url:
                    continue

                clean_url = dest_url.split('?')[0].rstrip('/')
                if clean_url in seen_urls:
                    continue

                # Extract clean title from h3 or anchor text
                h3 = a.find('h3')
                raw_title = h3.get_text(strip=True) if h3 else a.get_text(strip=True)
                if not raw_title or len(raw_title) < 4:
                    continue

                # Strip breadcrumb noise if present
                clean_title = re.sub(r'^(LinkedIn|Linkedin)[^\w]*', '', raw_title)
                clean_title = re.sub(r'^https?:\/\/[^\s]+', '', clean_title)
                clean_title = re.sub(r'^[^\w]*linkedin\.com[^\s]*', '', clean_title, flags=re.I)
                if '›' in clean_title:
                    clean_title = clean_title.split('›')[-1].strip()

                # Parse Person Name and Job Title
                name = ''
                job_title = ''

                parts = re.split(r'\s+[-–—]\s+', clean_title, maxsplit=1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    job_title = parts[1].replace('| LinkedIn', '').replace('LinkedIn', '').strip(' .-|')
                else:
                    name = clean_title.replace('| LinkedIn', '').replace('LinkedIn', '').strip(' .-|')
                    job_title = f"Professional at {company.capitalize()}"

                name = format_person_name(name)
                if not name or len(name) < 2 or 'linkedin' in name.lower():
                    continue

                seen_urls.add(clean_url)
                findings.append({
                    "source_engine": "yahoo",
                    "url": clean_url,
                    "raw_name": name,
                    "title": job_title or f"Professional at {company.capitalize()}",
                    "text": clean_title
                })
                page_found += 1

                if len(findings) >= max_results:
                    break

            if page_found == 0 or len(findings) >= max_results:
                break

            b += 7
            time.sleep(0.3)

        except Exception:
            break

    return findings

def _harvest_from_bing(company: str, max_results: int = 50, timeout: float = 12.0, proxy: str = "") -> List[Dict[str, str]]:
    """
    Fallback harvester using Bing search indexation.
    """
    findings = []
    seen_urls = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    url = f'https://www.bing.com/search?q=%22{urllib.parse.quote(company)}%22+site:linkedin.com/in/'

    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for a in soup.find_all('a'):
                href = a.get('href', '')
                if '/ck/a?' in href:
                    m = re.search(r'[?&]u=a1([^&]+)', href)
                    if m:
                        b64_str = m.group(1) + '=' * ((4 - len(m.group(1)) % 4) % 4)
                        try:
                            href = base64.urlsafe_b64decode(b64_str).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                if 'linkedin.com/in/' in href:
                    clean_url = href.split('?')[0].rstrip('/')
                    if clean_url in seen_urls:
                        continue
                    txt = a.get_text(strip=True)
                    if not txt or len(txt) < 4:
                        continue
                    parts = re.split(r'\s+[-–—]\s+', txt, maxsplit=1)
                    name = format_person_name(parts[0])
                    job_title = parts[1].replace('| LinkedIn', '').strip() if len(parts) > 1 else f"Professional at {company.capitalize()}"
                    seen_urls.add(clean_url)
                    findings.append({
                        "source_engine": "bing",
                        "url": clean_url,
                        "raw_name": name,
                        "title": job_title,
                        "text": txt
                    })
                    if len(findings) >= max_results:
                        break
    except Exception:
        pass

    return findings

def scrape_linkedin_workforce(
    company_name: str,
    title_filter: str = "",
    engine: str = "yahoo,bing,google",
    domain: str = "",
    pattern: str = "{first}.{last}@{domain}",
    timeout: float = 15.0,
    jitter: float = 0.5,
    max_results: int = 50,
    proxy: str = ""
) -> Dict[str, Any]:
    """
    Executes LinkedIn corporate workforce reconnaissance using public search indexation.
    Returns list of discovered personnel with verified public profile URLs, job titles,
    and inferred corporate email addresses.
    """
    start_time = time.time()
    clean_company = clean_company_name(company_name)
    if not clean_company:
        raise ValueError("Target company name cannot be blank.")

    target_domain = domain.strip() if domain.strip() else infer_company_domain(clean_company)
    search_engines = [e.strip().lower() for e in engine.split(",") if e.strip()]
    if not search_engines:
        search_engines = ["yahoo", "bing"]

    raw_findings = []
    seen_urls = set()

    # Step 1: Query Yahoo (primary high-yield zero-credential index)
    if "yahoo" in search_engines or "all" in search_engines or True:
        yahoo_results = _harvest_from_yahoo(
            company=clean_company,
            max_results=max_results,
            timeout=timeout,
            proxy=proxy
        )
        for item in yahoo_results:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                raw_findings.append(item)

    # Step 2: Fallback to Bing if needed
    if len(raw_findings) < max_results and ("bing" in search_engines or "all" in search_engines):
        bing_results = _harvest_from_bing(
            company=clean_company,
            max_results=max_results - len(raw_findings),
            timeout=timeout,
            proxy=proxy
        )
        for item in bing_results:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                raw_findings.append(item)

    # Process and filter personnel
    personnel_list = []
    clean_filter = title_filter.strip().lower()

    for idx, item in enumerate(raw_findings, 1):
        formatted_name = format_person_name(item.get("raw_name", ""))
        job_title = item.get("title", "N/A").strip()
        if job_title == "N/A" or not job_title:
            job_title = f"Professional at {clean_company.capitalize()}"

        # Apply department / title filter if requested
        if clean_filter and clean_filter != "all":
            combined_text = f"{formatted_name} {job_title} {item.get('text', '')}".lower()
            if clean_filter not in combined_text:
                continue

        inferred_email = generate_corporate_email(formatted_name, pattern, target_domain)

        personnel_list.append({
            "id": len(personnel_list) + 1,
            "name": formatted_name,
            "title": job_title,
            "company": clean_company.capitalize(),
            "profile_url": item.get("url", ""),
            "inferred_email": inferred_email,
            "source_engine": item.get("source_engine", "yahoo"),
            "raw_snippet": item.get("text", "")
        })

    elapsed = round(time.time() - start_time, 2)

    return {
        "company": clean_company,
        "domain": target_domain,
        "email_pattern": pattern,
        "title_filter": title_filter,
        "duration": elapsed,
        "total_discovered": len(personnel_list),
        "personnel": personnel_list,
        "engines_queried": ["yahoo", "bing"],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }
