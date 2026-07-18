"""Phases 84-89: OSINT (WHOIS, ASN, dorking, Shodan, employee harvest, passive DNS)."""
from reconchain.phases.helpers import *


async def phase_84_WHOIS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"84-WHOIS"}:
        return {}
    if only and "84-WHOIS" not in only:
        return {}
    _out = outdir / "whois.txt"
    if _out.exists() and not force:
        return {"84-WHOIS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 84-WHOIS: WHOIS registration intelligence")
    findings: List[str] = []
    whois_data = ""
    if t.has("whois"):
        await _run("whois", ["whois", domain], 30, outdir)
        log_path = outdir / "logs" / "whois.log"
        if log_path.exists():
            whois_data = log_path.read_text(encoding="utf-8", errors="ignore")
    else:
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.iana.org", 43))
            s.send((domain + "\r\n").encode())
            resp = b""
            recv_total = 0
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                recv_total += len(chunk)
                if recv_total > MAX_RECV:
                    break
                resp += chunk
            s.close()
            whois_data = resp.decode("utf-8", errors="ignore")
        except Exception:
            pass
    if not whois_data:
        log("warn", "84-WHOIS: no WHOIS data retrieved")
        ensure(_out).write_text("[no WHOIS data available]\n")
        return {"84-WHOIS": str(_out), "count": 0}
    fields = {
        "registrant_name": r"(?i)Registrant Name:\s*(.+)",
        "registrant_org": r"(?i)Registrant Organization:\s*(.+)",
        "creation_date": r"(?i)Creation Date:\s*(.+)",
        "expiry_date": r"(?i)(?:Registry Expiry Date|Expiry Date|Expiration Date):\s*(.+)",
        "name_servers": r"(?i)Name Server:\s*(.+)",
        "registrar": r"(?i)Registrar:\s*(.+)",
        "registrant_country": r"(?i)Registrant Country:\s*(.+)",
        "updated_date": r"(?i)Updated Date:\s*(.+)",
        "status": r"(?i)Domain Status:\s*(.+)",
    }
    for label, pattern in fields.items():
        matches = re.findall(pattern, whois_data)
        if matches:
            seen: Set[str] = set()
            for m in matches:
                m = m.strip()
                if m and m not in seen:
                    seen.add(m)
                    findings.append(f"{label}: {m}")
    privacy_indicators = ["privacy", "redacted", "protected", "proxy", "whoisguard", "domains by proxy"]
    is_privacy = any(ind in whois_data.lower() for ind in privacy_indicators)
    if is_privacy:
        findings.append("privacy_protection: YES (registration details hidden)")
    else:
        findings.append("privacy_protection: NO")
    creation_match = re.search(r"(?i)Creation Date:\s*(.+)", whois_data)
    if creation_match:
        try:
            from dateutil import parser as _dp
            created = _dp.parse(creation_match.group(1).strip())
            age_months = (datetime.now(tz=created.tzinfo) - created).days / 30
            if age_months < 6:
                findings.append(f"FLAG: domain registered {age_months:.0f} months ago (< 6 months = suspicious)")
            else:
                findings.append(f"age: {age_months:.0f} months")
        except Exception:
            findings.append(f"creation_date_raw: {creation_match.group(1).strip()}")
    findings.append(f"raw_length: {len(whois_data)} bytes")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"84-WHOIS: {len(findings)} findings → {out}")
    return {"84-WHOIS": str(_out), "count": len(findings)}


async def phase_85_ASN(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"85-ASN"}:
        return {}
    if only and "85-ASN" not in only:
        return {}
    _out = outdir / "asn_ranges.txt"
    if _out.exists() and not force:
        return {"85-ASN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 85-ASN: ASN/IP range enumeration")
    findings: List[str] = []
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    resolved_file = outdir / "resolved.txt"
    ips: Set[str] = set()
    if resolved_file.exists():
        for ln in read_lines(resolved_file):
            ln = ln.strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ln):
                ips.add(ln)
    if not ips:
        import socket as _sock
        try:
            ip = _sock.gethostbyname(domain)
            ips.add(ip)
        except Exception:
            pass
    if not ips:
        log("warn", "85-ASN: no IPs found for reverse ASN lookup")
        ensure(_out).write_text("[no IPs found]\n")
        return {"85-ASN": str(_out), "count": 0}
    findings.append(f"target_ips={len(ips)}")
    asns: Set[str] = set()
    cidrs: Set[str] = set()
    for ip in sorted(ips)[:50]:
        await _throttle_rate()
        try:
            url = f"https://api.bgpview.io/ip/{ip}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=10)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for r in (data.get("data") or {}).get("prefixes") or []:
                    asn_num = r.get("asn")
                    prefix = r.get("prefix")
                    name = r.get("name", "")
                    if asn_num:
                        asns.add(str(asn_num))
                        findings.append(f"ip={ip} asn={asn_num} name={name} prefix={prefix}")
                    if prefix:
                        cidrs.add(prefix)
        except Exception:
            pass
    for asn in sorted(asns)[:10]:
        await _throttle_rate()
        try:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=10)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for p in (data.get("data") or {}).get("ipv4_prefixes") or []:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.add(prefix)
                        findings.append(f"asn={asn} ipv4_prefix={prefix}")
                for p in (data.get("data") or {}).get("ipv6_prefixes") or []:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.add(prefix)
                        findings.append(f"asn={asn} ipv6_prefix={prefix}")
        except Exception:
            pass
    for cidr in sorted(cidrs):
        findings.append(f"cidr={cidr}")
    if not any("asn=" in f for f in findings):
        findings.append("[no ASN data found via BGPView API]")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"85-ASN: {len(findings)} findings → {out}")
    return {"85-ASN": str(_out), "count": len(findings)}


async def phase_86_DORK(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"86-DORK"}:
        return {}
    if only and "86-DORK" not in only:
        return {}
    _out = outdir / "dork_findings.txt"
    if _out.exists() and not force:
        return {"86-DORK": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 86-DORK: search engine dorking")
    findings: List[str] = []
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    dorks = [
        f"site:{domain} filetype:sql",
        f"site:{domain} inurl:admin",
        f"site:{domain} ext:env",
        f"site:{domain} ext:log",
        f"site:{domain} ext:bak",
        f'"{domain}" + password',
        f'"{domain}" + "api key"',
        f"site:{domain} intitle:\"index of\"",
        f"site:{domain} ext:xml",
        f"site:{domain} inurl:backup",
    ]
    url_re = re.compile(r'<a[^>]+href="(https?://[^"]+)"', re.I)
    for dork in dorks:
        await _throttle_rate()
        await asyncio.sleep(2)
        try:
            encoded = urllib.parse.quote_plus(dork)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **extra_h,
            })
            status, _, body = await _async_urlopen(opener, req, timeout=15)
            if status == 200:
                html = body.decode("utf-8", errors="ignore")
                urls = url_re.findall(html)
                for u in urls:
                    if domain in u and u not in findings:
                        findings.append(f"[{dork}] {u}")
                if urls:
                    log("info", f"86-DORK: {len(urls)} results for '{dork}'")
        except Exception:
            pass
    if not findings:
        findings.append("[no dork results found]")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"86-DORK: {len(findings)} dork findings → {out}")
    return {"86-DORK": str(_out), "count": len(findings)}


async def phase_87_SHODAN(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"87-SHODAN"}:
        return {}
    if only and "87-SHODAN" not in only:
        return {}
    _out = outdir / "shodan_hosts.txt"
    if _out.exists() and not force:
        return {"87-SHODAN": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 87-SHODAN: Shodan/Censys integration")
    findings: List[str] = []
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        log("warn", "87-SHODAN: SHODAN_API_KEY not set; skipping")
        ensure(_out).write_text("[SHODAN_API_KEY not set]\n")
        return {"87-SHODAN": str(_out), "count": 0}
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?type=A&key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            for sub in (data.get("data") or []):
                hostname = sub.get("hostname", "")
                ip = sub.get("ip", "")
                if hostname or ip:
                    findings.append(f"[dns] {hostname} → {ip}")
        else:
            findings.append(f"[dns-query] HTTP {status}")
    except Exception as e:
        findings.append(f"[dns-query-error] {e}")
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            for match in (data.get("matches") or [])[:20]:
                ip = match.get("ip_str", "")
                port = match.get("port", "")
                org = match.get("org", "")
                product = match.get("product", "")
                hostnames = match.get("hostnames", [])
                findings.append(f"[host] {ip}:{port} org={org} product={product} hosts={','.join(hostnames[:3])}")
        else:
            findings.append(f"[search-query] HTTP {status}")
    except Exception as e:
        findings.append(f"[search-query-error] {e}")
    try:
        fav_url = f"https://{domain}/favicon.ico"
        req = urllib.request.Request(fav_url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=10)
        if status == 200 and body:
            h = _mmh3_hash(body)
            if h == -862577723:
                findings.append(f"[favicon] Shodan favicon hash match: {h}")
            else:
                findings.append(f"[favicon] hash={h} (no known match)")
    except Exception:
        pass
    if not findings:
        findings.append("[no Shodan data found]")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"87-SHODAN: {len(findings)} findings → {out}")
    return {"87-SHODAN": str(_out), "count": len(findings)}


async def phase_88_EMPLOYEE(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"88-EMPLOYEE"}:
        return {}
    if only and "88-EMPLOYEE" not in only:
        return {}
    _out = outdir / "employees.txt"
    _wl = outdir / "wordlist_generated.txt"
    if _out.exists() and _wl.exists() and not force:
        return {"88-EMPLOYEE": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 88-EMPLOYEE: employee name harvesting")
    findings: List[str] = []
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    name_re = re.compile(r'<h2[^>]*>\s*<span[^>]*>([^<]+)</span>\s*<span[^>]*>([^<]+)</span>', re.I)
    title_re = re.compile(r'at\s+' + re.escape(domain.split('.')[0]), re.I)
    employees: Set[Tuple[str, str]] = set()
    dork = f'site:linkedin.com/in "at {domain.split(".")[0]}"'
    encoded = urllib.parse.quote_plus(dork)
    try:
        url = f"https://html.duckduckgo.com/html/?q={encoded}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            **extra_h,
        })
        await _throttle_rate()
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            html = body.decode("utf-8", errors="ignore")
            for m in name_re.finditer(html):
                first, last = m.group(1).strip(), m.group(2).strip()
                if first and last and len(first) < 30 and len(last) < 30:
                    employees.add((first.lower(), last.lower()))
    except Exception:
        pass
    for first, last in sorted(employees):
        findings.append(f"{first} {last}")
    if not findings:
        findings.append("[no employee names found via public search]")
    ensure(_out).write_text("\n".join(findings) + ("\n" if findings else ""))
    wordlist: Set[str] = set()
    domain_name = domain.split(".")[0].lower()
    for first, last in employees:
        wordlist.add(f"{first}.{last}@{domain}")
        wordlist.add(f"{first[0]}{last}@{domain}")
        wordlist.add(f"{first}.{last[0]}@{domain}")
        wordlist.add(f"{first}{last}@{domain}")
        wordlist.add(f"{first}@{domain}")
    wordlist.add(f"admin@{domain}")
    wordlist.add(f"info@{domain}")
    wordlist.add(f"support@{domain}")
    wordlist.add(f"root@{domain}")
    wordlist.add(f"security@{domain}")
    ensure(_wl).write_text("\n".join(sorted(wordlist)) + ("\n" if wordlist else ""))
    log("ok", f"88-EMPLOYEE: {len(findings)} employees, {len(wordlist)} wordlist entries → {_out}")
    return {"88-EMPLOYEE": str(_out), "count": len(findings)}


async def phase_89_PASSIVEDNS(
    domain: str, outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, force: bool = False,
) -> Dict[str, Any]:
    if skip & {"89-PASSIVEDNS"}:
        return {}
    if only and "89-PASSIVEDNS" not in only:
        return {}
    _out = outdir / "passive_dns_subs.txt"
    if _out.exists() and not force:
        return {"89-PASSIVEDNS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 89-PASSIVEDNS: passive DNS aggregation")
    findings: Set[str] = set()
    opener = _get_urlopener()
    extra_h = _extra_headers_dict()
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            req = urllib.request.Request(url, headers={"x-apikey": vt_key, "User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=15)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for item in (data.get("data") or []):
                    sub = item.get("id", "")
                    if sub and sub != domain:
                        findings.add(sub)
                        log("info", f"89-PASSIVEDNS: VT found {sub}")
            else:
                log("warn", f"89-PASSIVEDNS: VirusTotal HTTP {status}")
        except Exception as e:
            log("warn", f"89-PASSIVEDNS: VirusTotal error: {e}")
    else:
        log("info", "89-PASSIVEDNS: VIRUSTOTAL_API_KEY not set, skipping VirusTotal")
    st_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
    if st_key:
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            req = urllib.request.Request(url, headers={"apikey": st_key, "User-Agent": "Mozilla/5.0", **extra_h})
            status, _, body = await _async_urlopen(opener, req, timeout=15)
            if status == 200:
                data = json.loads(body.decode("utf-8", errors="ignore"))
                for sub_record in (data.get("subdomains") or []):
                    sub = f"{sub_record}.{domain}" if isinstance(sub_record, str) else ""
                    if sub:
                        findings.add(sub)
                        log("info", f"89-PASSIVEDNS: ST found {sub}")
            else:
                log("warn", f"89-PASSIVEDNS: SecurityTrails HTTP {status}")
        except Exception as e:
            log("warn", f"89-PASSIVEDNS: SecurityTrails error: {e}")
    else:
        log("info", "89-PASSIVEDNS: SECURITYTRAILS_API_KEY not set, skipping SecurityTrails")
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", **extra_h})
        status, _, body = await _async_urlopen(opener, req, timeout=15)
        if status == 200:
            data = json.loads(body.decode("utf-8", errors="ignore"))
            for result in (data.get("results") or [])[:50]:
                page = result.get("page", {})
                hostname = page.get("domain", "")
                if hostname and hostname != domain:
                    findings.add(hostname)
                    ip = page.get("ip", "")
                    if ip:
                        findings.add(f"{hostname} ({ip})")
            log("info", f"89-PASSIVEDNS: urlscan.io returned {len(findings)} subdomains")
        else:
            log("warn", f"89-PASSIVEDNS: urlscan.io HTTP {status}")
    except Exception as e:
        log("warn", f"89-PASSIVEDNS: urlscan.io error: {e}")
    clean_subs: List[str] = []
    for f in sorted(findings):
        sub = f.split("(")[0].strip().lower()
        if sub and _is_valid_hostname(sub) and (_is_under_domain(sub, domain) or sub == domain):
            clean_subs.append(sub)
    out = ensure(_out)
    out.write_text("\n".join(sorted(set(clean_subs))) + ("\n" if clean_subs else "[no passive DNS subdomains found]\n"))
    if clean_subs:
        all_subs = outdir / "all_subs.txt"
        if all_subs.exists():
            merge_unique([_out], all_subs)
    log("ok", f"89-PASSIVEDNS: {len(clean_subs)} subdomains → {out}")
    return {"89-PASSIVEDNS": str(_out), "count": len(clean_subs)}
