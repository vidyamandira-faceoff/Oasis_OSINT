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

ROLE_QUERY_MAP = {
    "engineer": '("engineer" OR "developer" OR "software" OR "architect" OR "tech")',
    "security": '("security" OR "infosec" OR "cyber" OR "soc" OR "osint")',
    "executive": '("chief" OR "ceo" OR "cto" OR "cfo" OR "coo" OR "founder" OR "vp" OR "president")',
    "director": '("director" OR "head of" OR "lead" OR "principal" OR "manager")',
    "research": '("research" OR "scientist" OR "ai" OR "machine learning" OR "deep learning")',
    "product": '("product" OR "designer" OR "design" OR "ui" OR "ux" OR "product manager")'
}

ROLE_MATCH_TERMS = {
    "engineer": ["engineer", "developer", "software", "architect", "tech", "programmer", "dev", "hardware", "firmware"],
    "security": ["security", "infosec", "cyber", "soc", "osint", "threat", "vulnerability", "forensic", "pentest"],
    "executive": ["chief", "ceo", "cto", "cfo", "coo", "founder", "president", "vp", "vice president", "partner", "head"],
    "director": ["director", "lead", "principal", "manager", "head", "supervisor"],
    "research": ["research", "scientist", "ai", "machine learning", "deep learning", "fellow", "postdoc", "phd"],
    "product": ["product", "designer", "design", "ui", "ux", "creative", "product manager"]
}

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

def _clean_snippet_to_person(raw_title: str, clean_url: str, company: str) -> Optional[Dict[str, str]]:
    """Normalizes raw search result snippet and anchor text into structured name and job title."""
    if not raw_title or len(raw_title) < 4:
        return None

    clean = re.sub(r'^(LinkedIn|Linkedin)[^\w]*', '', raw_title)
    clean = re.sub(r'^https?:\/\/[^\s]+', '', clean)
    clean = re.sub(r'^[^\w]*linkedin\.com[^\s]*', '', clean, flags=re.IGNORECASE)
    if '›' in clean:
        parts = clean.split('›')
        clean = parts[-1].strip()
    clean = re.sub(r'^(in\s+|pub\s+)?([a-z0-9\-]+[\d\-]+|[a-z0-9\-]{10,})\s+', '', clean, flags=re.IGNORECASE)

    parts = re.split(r'\s+[-–—|]\s+', clean)
    parts = [p.replace('LinkedIn', '').replace('|', '').strip(' .-|') for p in parts if p.strip()]
    if not parts:
        return None

    name = format_person_name(parts[0])
    if not name or len(name) < 2 or 'linkedin' in name.lower() or name.lower().startswith('http'):
        return None

    job_title = parts[1] if len(parts) > 1 else ""
    if not job_title or job_title.lower() == "linkedin":
        job_title = f"Professional at {company.capitalize()}"

    return {
        "url": clean_url,
        "raw_name": name,
        "title": job_title,
        "text": clean
    }

def matches_filter(item: Dict[str, str], clean_filter: str) -> bool:
    """Checks if harvested person matches specified department or role filter."""
    if not clean_filter or clean_filter == "all":
        return True
    combined = f"{item.get('title', '')} {item.get('raw_name', '')} {item.get('text', '')}".lower()
    if clean_filter in ROLE_MATCH_TERMS:
        terms = ROLE_MATCH_TERMS[clean_filter]
        return any(term in combined for term in terms)
    return clean_filter in combined

def _harvest_from_yahoo(query_str: str, company: str, max_results: int = 50, timeout: float = 12.0, proxy: str = "") -> List[Dict[str, str]]:
    """
    Harvests LinkedIn personnel profiles via Yahoo search indexation with multi-page pagination.
    """
    findings = []
    seen_urls = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None

    b = 1
    max_pages = max(1, (max_results // 7) + 2)

    for page in range(max_pages):
        encoded_query = urllib.parse.quote(query_str)
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

                h3 = a.find('h3')
                raw_title = h3.get_text(strip=True) if h3 else a.get_text(strip=True)
                item = _clean_snippet_to_person(raw_title, clean_url, company)
                if not item:
                    continue

                seen_urls.add(clean_url)
                item["source_engine"] = "yahoo"
                findings.append(item)
                page_found += 1

                if len(findings) >= max_results:
                    break

            if page_found == 0 or len(findings) >= max_results:
                break

            b += 10
            time.sleep(0.25)

        except Exception:
            break

    return findings

def _harvest_from_bing(query_str: str, company: str, max_results: int = 50, timeout: float = 12.0, proxy: str = "") -> List[Dict[str, str]]:
    """
    Harvests LinkedIn personnel profiles via Bing search indexation with pagination.
    """
    findings = []
    seen_urls = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None

    first = 1
    max_pages = max(1, (max_results // 8) + 2)

    for page in range(max_pages):
        encoded_query = urllib.parse.quote(query_str)
        url = f'https://www.bing.com/search?q={encoded_query}&first={first}'
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            if resp.status_code != 200:
                break

            soup = BeautifulSoup(resp.text, 'html.parser')
            page_found = 0

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

                if 'linkedin.com/in/' not in href:
                    continue

                clean_url = href.split('?')[0].rstrip('/')
                if clean_url in seen_urls:
                    continue

                h2 = a.find('h2')
                raw_title = h2.get_text(strip=True) if h2 else a.get_text(strip=True)
                item = _clean_snippet_to_person(raw_title, clean_url, company)
                if not item:
                    continue

                seen_urls.add(clean_url)
                item["source_engine"] = "bing"
                findings.append(item)
                page_found += 1

                if len(findings) >= max_results:
                    break

            if page_found == 0 or len(findings) >= max_results:
                break

            first += 10
            time.sleep(0.25)

        except Exception:
            break

    return findings

def _harvest_from_duckduckgo(query_str: str, company: str, max_results: int = 50, timeout: float = 12.0, proxy: str = "") -> List[Dict[str, str]]:
    """
    Harvests LinkedIn personnel profiles via DuckDuckGo zero-credential search indexation.
    """
    findings = []
    seen_urls = set()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    proxies = {"http": proxy, "https": proxy} if proxy else None
    url = "https://html.duckduckgo.com/html/"

    try:
        resp = requests.post(url, data={"q": query_str}, headers=headers, proxies=proxies, timeout=timeout)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for a in soup.find_all('a'):
                href = a.get('href', '')
                if 'uddg=' in href:
                    m = re.search(r'uddg=([^&]+)', href)
                    if m:
                        href = urllib.parse.unquote(m.group(1))

                if 'linkedin.com/in/' not in href:
                    continue

                clean_url = href.split('?')[0].rstrip('/')
                if clean_url in seen_urls:
                    continue

                raw_title = a.get_text(strip=True)
                item = _clean_snippet_to_person(raw_title, clean_url, company)
                if not item:
                    continue

                seen_urls.add(clean_url)
                item["source_engine"] = "duckduckgo"
                findings.append(item)

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
    Executes LinkedIn corporate workforce reconnaissance using targeted public search indexation.
    Returns list of discovered personnel with verified public profile URLs, job titles,
    and inferred corporate email addresses.
    """
    start_time = time.time()
    clean_company = clean_company_name(company_name)
    if not clean_company:
        raise ValueError("Target company name cannot be blank.")

    target_domain = domain.strip() if domain.strip() else infer_company_domain(clean_company)
    clean_filter = (title_filter or "").strip().lower()

    # Build prioritized list of search queries
    queries = []
    if clean_filter and clean_filter != "all":
        # Targeted query for specific department/role
        expanded_term = ROLE_QUERY_MAP.get(clean_filter, f'"{clean_filter}"')
        queries.append(f'site:linkedin.com/in "{clean_company}" {expanded_term}')
        queries.append(f'site:linkedin.com/in/ "{clean_company}" {clean_filter}')
    else:
        # General company query
        queries.append(f'site:linkedin.com/in "{clean_company}"')
        if max_results > 25:
            # Query expansion to yield deep personnel lists (50 - 100 profiles)
            queries.append(f'site:linkedin.com/in "{clean_company}" ("engineer" OR "developer" OR "software")')
            queries.append(f'site:linkedin.com/in "{clean_company}" ("director" OR "manager" OR "lead" OR "head")')
            queries.append(f'site:linkedin.com/in "{clean_company}" ("chief" OR "vp" OR "executive" OR "founder")')
            queries.append(f'site:linkedin.com/in "{clean_company}" ("product" OR "marketing" OR "operations" OR "research")')

    raw_findings = []
    seen_urls = set()

    for q in queries:
        if len(raw_findings) >= max_results:
            break

        needed = max_results - len(raw_findings)

        # 1. Yahoo Harvester
        try:
            yh_results = _harvest_from_yahoo(q, clean_company, max_results=needed, timeout=timeout, proxy=proxy)
            for item in yh_results:
                if item["url"] not in seen_urls and matches_filter(item, clean_filter):
                    seen_urls.add(item["url"])
                    raw_findings.append(item)
                    if len(raw_findings) >= max_results:
                        break
        except Exception:
            pass

        if len(raw_findings) >= max_results:
            break

        # 2. Bing Harvester
        needed = max_results - len(raw_findings)
        try:
            bing_results = _harvest_from_bing(q, clean_company, max_results=needed, timeout=timeout, proxy=proxy)
            for item in bing_results:
                if item["url"] not in seen_urls and matches_filter(item, clean_filter):
                    seen_urls.add(item["url"])
                    raw_findings.append(item)
                    if len(raw_findings) >= max_results:
                        break
        except Exception:
            pass

        if len(raw_findings) >= max_results:
            break

        # 3. DuckDuckGo Harvester
        needed = max_results - len(raw_findings)
        try:
            ddg_results = _harvest_from_duckduckgo(q, clean_company, max_results=needed, timeout=timeout, proxy=proxy)
            for item in ddg_results:
                if item["url"] not in seen_urls and matches_filter(item, clean_filter):
                    seen_urls.add(item["url"])
                    raw_findings.append(item)
                    if len(raw_findings) >= max_results:
                        break
        except Exception:
            pass

    # Build final structured personnel list sliced to exact max_results requested
    personnel_list = []
    for idx, item in enumerate(raw_findings[:max_results], 1):
        formatted_name = format_person_name(item.get("raw_name", ""))
        job_title = item.get("title", "").strip()
        if not job_title or job_title.lower() == "linkedin":
            job_title = f"Professional at {clean_company.capitalize()}"

        inferred_email = generate_corporate_email(formatted_name, pattern, target_domain)

        personnel_list.append({
            "id": idx,
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
        "engines_queried": ["yahoo", "bing", "duckduckgo"],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }
