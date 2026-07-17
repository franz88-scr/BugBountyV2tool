"""Cloud and DevOps phases: CI/CD, Docker, Kubernetes, Terraform, API versioning, load balancer detection, vhost, rate limit bypass."""
from reconchain.phases.helpers import *


async def phase_127_CICD(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"127-CICD"}:
        return {}
    _out = outdir / "cicd_exposure.txt"
    if _out.exists() and not force:
        return {"127-CICD": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 127-CICD: CI/CD Pipeline File Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "127-CICD: no live hosts; skipping")
        return {"127-CICD": str(_out), "count": 0}
    cicd_paths = [
        "/.gitlab-ci.yml", "/Jenkinsfile", "/.github/workflows/",
        "/.circleci/config.yml", "/.travis.yml", "/appveyor.yml",
        "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
        "/buildspec.yml", "/cloudbuild.yaml",
    ]
    for host in hosts:
        for path in cicd_paths:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[cicd-file] {host} path={path}")
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    if any(kw in body_str.lower() for kw in ("password", "secret", "token", "api_key", "aws_secret")):
                        findings.append(f"[cicd-secrets] {host} path={path} detail=Potential secrets in CI/CD file")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[cicd-file] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"127-CICD: {len(findings)} findings \u2192 {out}")
    return {"127-CICD": str(out), "count": len(findings)}


async def phase_128_DOCKER(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"128-DOCKER"}:
        return {}
    _out = outdir / "docker_registry.txt"
    if _out.exists() and not force:
        return {"128-DOCKER": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 128-DOCKER: Docker Registry Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "128-DOCKER: no live hosts; skipping")
        return {"128-DOCKER": str(_out), "count": 0}
    for host in hosts:
        registry_url = f"https://{host}/v2/"
        try:
            req = urllib.request.Request(registry_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status in (200, 401):
                findings.append(f"[docker-registry] {host}")
                catalog_url = f"https://{host}/v2/_catalog"
                try:
                    cat_req = urllib.request.Request(catalog_url, headers=_extra_h, method="GET")
                    cat_status, cat_headers, cat_body = await _async_urlopen(_urlopen, cat_req, timeout=10)
                    if cat_status == 200:
                        cat_data = json.loads(cat_body)
                        images = cat_data.get("repositories", [])
                        if images:
                            findings.append(f"[docker-images] {host} images={','.join(images)}")
                except Exception:
                    pass
        except Exception:
            pass
        for path in ("/docker-compose.yml", "/Dockerfile"):
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    tag = "[docker-compose]" if path == "/docker-compose.yml" else "[dockerfile]"
                    findings.append(f"{tag} {host}")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[docker-registry] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"128-DOCKER: {len(findings)} findings \u2192 {out}")
    return {"128-DOCKER": str(out), "count": len(findings)}


async def phase_129_K8S(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"129-K8S"}:
        return {}
    _out = outdir / "k8s_exposure.txt"
    if _out.exists() and not force:
        return {"129-K8S": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 129-K8S: Kubernetes Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "129-K8S: no live hosts; skipping")
        return {"129-K8S": str(_out), "count": 0}
    api_endpoints = [
        ("/api/v1", "[k8s-api]"),
        ("/apis", "[k8s-api]"),
        ("/healthz", "[k8s-api]"),
        ("/version", "[k8s-api]"),
    ]
    for host in hosts:
        for endpoint, tag in api_endpoints:
            url = f"https://{host}:6443{endpoint}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"{tag} {host} endpoint={endpoint}")
            except Exception:
                pass
        kubelet_endpoints = ["/pods", "/stats/summary"]
        for ep in kubelet_endpoints:
            url = f"https://{host}:10250{ep}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[k8s-kubelet] {host} endpoint={ep}")
            except Exception:
                pass
        etcd_url = f"https://{host}:2379/v2/keys"
        try:
            req = urllib.request.Request(etcd_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[k8s-etcd] {host}")
        except Exception:
            pass
        ro_kubelet_url = f"https://{host}:10255/pods"
        try:
            req = urllib.request.Request(ro_kubelet_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[k8s-kubelet] {host} endpoint=/pods (read-only)")
        except Exception:
            pass
        dashboard_url = f"https://{host}/api/v1/namespaces/kube-system/services/kubernetes-dashboard"
        try:
            req = urllib.request.Request(dashboard_url, headers=_extra_h, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
            if status == 200:
                findings.append(f"[k8s-dashboard] {host}")
        except Exception:
            pass
        await _throttle_rate()
    if not findings:
        findings.append("[k8s-api] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"129-K8S: {len(findings)} findings \u2192 {out}")
    return {"129-K8S": str(out), "count": len(findings)}


async def phase_130_TERRAFORM(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"130-TERRAFORM"}:
        return {}
    _out = outdir / "terraform_exposure.txt"
    if _out.exists() and not force:
        return {"130-TERRAFORM": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 130-TERRAFORM: Terraform State File Exposure")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()
    hosts = _load_live_hosts(outdir)
    if not hosts:
        log("warn", "130-TERRAFORM: no live hosts; skipping")
        return {"130-TERRAFORM": str(_out), "count": 0}
    tf_paths = [
        "/terraform.tfstate", "/terraform.tfstate.backup",
        "/state/terraform.tfstate", "/infra/terraform.tfstate",
    ]
    aws_key_re = re.compile(r"AKIA[0-9A-Z]{16}")
    pwd_re = re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"&]+)")
    ip_re = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
    token_re = re.compile(r"(?i)(token|api_key|secret)\s*[:=]\s*['\"]?([^\s'\"&]+)")
    for host in hosts:
        for path in tf_paths:
            url = f"https://{host}{path}"
            try:
                req = urllib.request.Request(url, headers=_extra_h, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=10)
                if status == 200:
                    findings.append(f"[terraform-state] {host} path={path}")
                    body_str = body_bytes.decode("utf-8", errors="replace")
                    for m in aws_key_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=AWS_ACCESS_KEY detail={m.group()}")
                    for m in pwd_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=PASSWORD detail={m.group(2)[:50]}")
                    for m in ip_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=PRIVATE_IP detail={m.group()}")
                    for m in token_re.finditer(body_str):
                        findings.append(f"[terraform-secrets] {host} type=API_TOKEN detail={m.group(2)[:50]}")
            except Exception:
                pass
        await _throttle_rate()
    if not findings:
        findings.append("[terraform-state] No findings (expected)")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"130-TERRAFORM: {len(findings)} findings \u2192 {out}")
    return {"130-TERRAFORM": str(out), "count": len(findings)}

async def phase_133_APIVERSION(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"133-APIVERSION"}:
        return {}
    _out = outdir / "api_version_bypass.txt"
    if _out.exists() and not force:
        return {"133-APIVERSION": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 133-APIVERSION: API versioning bypass testing")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    api_urls = [u.strip() for u in all_urls if u.strip() and "/api/" in u.lower()]

    if not api_urls:
        log("warn", "133-APIVERSION: no /api/ URLs found; skipping")
        return {"133-APIVERSION": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_urls_apiversion", 20))
    api_urls = api_urls[:sample]

    version_swaps = [
        (r'(/api/)v\d+(.*)', r'\1v0\2'),
        (r'(/api/)v\d+(.*)', r'\1internal\2'),
        (r'(/api/)v\d+(.*)', r'\1legacy\2'),
        (r'(/api/)v\d+(.*)', r'\1beta\2'),
    ]
    version_patterns = [
        (r'(/?)v\d+(/.*)', r'\1v0\2'),
        (r'(/?)v\d+(/.*)', r'\1api\2'),
    ]

    for url in api_urls:
        await _throttle_rate()
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        qs = parsed.query

        variants = []

        for pat, repl in version_swaps:
            new_path = re.sub(pat, repl, path, count=1)
            if new_path != path:
                variants.append(("old_version", new_path))

        for pat, repl in version_patterns:
            new_path = re.sub(pat, repl, path, count=1)
            if new_path != path:
                variants.append(("old_version", new_path))

        no_version = re.sub(r'/v\d+', '', path, count=1)
        if no_version != path:
            variants.append(("no_version", no_version))

        path_parts = path.split("/")
        for i, part in enumerate(path_parts):
            if re.match(r'^v\d+$', part):
                for older in ["v0", "v1", "v2"]:
                    if older != part:
                        new_parts = path_parts[:]
                        new_parts[i] = older
                        variants.append(("older_version", "/".join(new_parts)))
                break

        for tag, variant_path in variants:
            await _throttle_rate()
            variant_url = base + variant_path
            if qs:
                variant_url += "?" + qs
            try:
                req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200:
                    findings.append(f"[api-version-bypass] {url} {tag}={variant_path} status={status}")
            except urllib.error.HTTPError:
                pass
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Test /api/internal/ path
        internal_path = re.sub(r'(/api/)v\d+', r'\1internal', path, count=1)
        if internal_path != path:
            await _throttle_rate()
            internal_url = base + internal_path
            if qs:
                internal_url += "?" + qs
            try:
                req = urllib.request.Request(internal_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200:
                    findings.append(f"[api-internal] {url} path={internal_path}")
            except urllib.error.HTTPError:
                pass
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

    if not findings:
        findings.append("[api-version-bypass] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"133-APIVERSION: {len(findings)} findings → {out}")
    return {"133-APIVERSION": str(out), "count": len(findings)}


async def phase_134_LBDETECT(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"134-LBDETECT"}:
        return {}
    _out = outdir / "load_balancer_bypass.txt"
    if _out.exists() and not force:
        return {"134-LBDETECT": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 134-LBDETECT: load balancer detection & bypass")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []

    if not hosts:
        log("warn", "134-LBDETECT: no hosts; skipping")
        return {"134-LBDETECT": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_hosts_lbdetect", 15))
    hosts = hosts[:sample]

    lb_signatures = {
        "AWS_ALB": ["x-amzn-trace-id", "x-amzn-requestid", "x-amz-cf-id", "x-forwarded-by"],
        "CloudFront": ["x-amz-cf-id", "x-cache", "via"],
        "Cloudflare": ["cf-ray", "cf-cache-status", "server"],
        "F5_BIGIP": ["x-wa-info", "x-bigip", "server"],
        "HAProxy": ["x-ha-proxy", "x-haproxy", "server"],
        "Akamai": ["x-akamai-transformed", "x-akamai-request-id", "server"],
        "Fastly": ["x-served-by", "x-cache", "x-fastly-request-id"],
        "Envoy": ["x-envoy-upstream-service-time", "x-envoy-decorator-operation"],
    }

    origin_file = outdir / "origin.txt"
    origin_ips = read_lines(origin_file) if origin_file.exists() else []

    for host in hosts:
        host = host.strip()
        if not host:
            continue

        await _throttle_rate()
        url = f"https://{host}/"
        try:
            req = urllib.request.Request(url, headers={"Accept": "*/*", **_extra_h}, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            headers = {k.lower(): v for k, v in resp_headers.items()}
            body = body_bytes.decode("utf-8", errors="replace")

            detected_lb = None
            for lb_type, sig_headers in lb_signatures.items():
                for sh in sig_headers:
                    if sh.lower() in headers:
                        detected_lb = lb_type
                        break
                if detected_lb:
                    break

            if detected_lb:
                findings.append(f"[lb-detected] {host} type={detected_lb}")

                origin_ip = None
                for oip in origin_ips:
                    oip = oip.strip()
                    if oip:
                        origin_ip = oip
                        break

                if origin_ip:
                    await _throttle_rate()
                    origin_url = f"https://{origin_ip}/"
                    try:
                        oreq = urllib.request.Request(
                            origin_url,
                            headers={"Host": host, "Accept": "*/*", **_extra_h},
                            method="GET",
                        )
                        _, _, oresp_body = await _async_urlopen(_urlopen, oreq, timeout=12)
                        obody = oresp_body.decode("utf-8", errors="replace")
                        diff = "YES" if obody.strip() != body.strip() else "NO"
                        findings.append(f"[lb-bypass] {host} origin={origin_ip} diff={diff}")
                    except (urllib.error.URLError, urllib.error.HTTPError, OSError, socket.timeout):
                        findings.append(f"[lb-bypass] {host} origin={origin_ip} diff=UNREACHABLE")
                    except Exception:
                        pass

        except urllib.error.HTTPError as e:
            detected_lb = None
            hdrs = {}
            if hasattr(e, "headers") and e.headers:
                for key, val in e.headers.items():
                    hdrs[key.lower()] = val
            for lb_type, sig_headers in lb_signatures.items():
                for sh in sig_headers:
                    if sh.lower() in hdrs:
                        detected_lb = lb_type
                        break
                if detected_lb:
                    break
            if detected_lb:
                findings.append(f"[lb-detected] {host} type={detected_lb}")
        except (urllib.error.URLError, OSError, socket.timeout):
            pass
        except Exception:
            pass

    if not findings:
        findings.append("[lb-detected] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"134-LBDETECT: {len(findings)} findings → {out}")
    return {"134-LBDETECT": str(out), "count": len(findings)}


async def phase_135_VHOST(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"135-VHOST"}:
        return {}
    _out = outdir / "vhost_discovery.txt"
    if _out.exists() and not force:
        return {"135-VHOST": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 135-VHOST: virtual host enumeration")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    hosts_file = outdir / "hosts.txt"
    hosts = read_lines(hosts_file) if hosts_file.exists() else []

    if not hosts:
        log("warn", "135-VHOST: no hosts; skipping")
        return {"135-VHOST": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_hosts_vhost", 10))
    hosts = hosts[:sample]

    for host in hosts:
        host = host.strip()
        if not host:
            continue

        await _throttle_rate()
        # Extract IP if possible (for reporting), else use hostname
        ip = host
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            pass

        target_domain = host
        if "." in host:
            parts = host.split(".")
            if len(parts) >= 2:
                target_domain = ".".join(parts[-2:])

        host_headers_to_try = [
            target_domain,
            f"admin.{target_domain}",
            f"mail.{target_domain}",
            f"internal.{target_domain}",
            f"staging.{target_domain}",
            f"dev.{target_domain}",
            f"api.{target_domain}",
            f"test.{target_domain}",
        ]

        baseline_status = None
        baseline_len = None
        baseline_title = None
        results = []

        for i, hh in enumerate(host_headers_to_try):
            await _throttle_rate()
            url = f"https://{host}/"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Host": hh, "Accept": "*/*", **_extra_h},
                    method="GET",
                )
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                body = body_bytes.decode("utf-8", errors="replace")
                content_len = len(body)

                title_match = re.search(r'<title[^>]*>([^<]*)</title>', body, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip()[:80] if title_match else ""

                if i == 0:
                    baseline_status = status
                    baseline_len = content_len
                    baseline_title = title

                results.append((hh, status, content_len, title))

            except urllib.error.HTTPError as e:
                status = e.code
                title = ""
                content_len = 0
                if i == 0:
                    baseline_status = status
                    baseline_len = content_len
                    baseline_title = title
                results.append((hh, status, content_len, title))
            except (urllib.error.URLError, OSError, socket.timeout):
                if i == 0:
                    baseline_status = 0
                    baseline_len = 0
                    baseline_title = ""
                results.append((hh, 0, 0, ""))
            except Exception:
                if i == 0:
                    baseline_status = 0
                    baseline_len = 0
                    baseline_title = ""
                results.append((hh, 0, 0, ""))

        for hh, status, content_len, title in results[1:]:
            if status == 0:
                continue
            len_diff = abs(content_len - (baseline_len or 0)) if baseline_len else content_len
            title_diff = title != baseline_title if baseline_title else bool(title)
            status_diff = status != baseline_status if baseline_status else True

            if status_diff or len_diff > 100 or title_diff:
                findings.append(f"[vhost-found] {ip} host={hh} status={status} len={content_len} title={title}")

    if not findings:
        findings.append("[vhost-found] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"135-VHOST: {len(findings)} findings → {out}")
    return {"135-VHOST": str(out), "count": len(findings)}


async def phase_136_RATELIMITBYPASS(
    outdir: Path, t: Tools, only: PhaseSet, skip: PhaseSet, prev: Dict[str, Any], force: bool = False,
) -> Dict[str, Any]:
    if skip & {"136-RATELIMITBYPASS"}:
        return {}
    _out = outdir / "rate_limit_bypass.txt"
    if _out.exists() and not force:
        return {"136-RATELIMITBYPASS": str(_out), "count": count_nonblank(_out)}
    log("info", "Phase 136-RATELIMITBYPASS: application rate limit bypass")
    findings: List[str] = []
    _urlopen = _get_urlopener()
    _extra_h = _extra_headers_dict()

    urls_file = outdir / "urls_all.txt"
    all_urls = read_lines(urls_file) if urls_file.exists() else []

    if not all_urls:
        log("warn", "136-RATELIMITBYPASS: no URLs found; skipping")
        return {"136-RATELIMITBYPASS": str(_out), "count": 0}

    sample = int(getattr(_PIPELINE_CFG, "sample_urls_ratelimitbypass", 20))
    urls = [u.strip() for u in all_urls if u.strip()][:sample]

    ip_rotation_headers = [
        ("X-Forwarded-For", [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("X-Real-IP", [f"172.16.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("X-Originating-IP", [f"192.168.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("CF-Connecting-IP", [f"104.28.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
        ("X-Forwarded-Host", [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 255, 50)]),
    ]

    case_transforms = [
        lambda p: p.upper(),
        lambda p: re.sub(r'[a-z]', lambda m: m.group(0).upper(), p),
        lambda p: "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(p)),
    ]

    unicode_swaps = [
        (".", "．"),
        ("-", "﹘"),
        ("/", "∕"),
    ]

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        qs = parsed.query

        # Baseline request to check if rate limiting exists
        baseline_status = None
        try:
            req = urllib.request.Request(url, headers={"Accept": "*/*", **_extra_h}, method="GET")
            baseline_status, _, _ = await _async_urlopen(_urlopen, req, timeout=12)
        except urllib.error.HTTPError as e:
            baseline_status = e.code
        except (urllib.error.URLError, OSError, socket.timeout):
            continue
        except Exception:
            continue

        if baseline_status != 429 and baseline_status != 403:
            # Still try a few quick checks for URLs that might be rate-limited
            pass

        # Technique 1: X-Forwarded-For rotation with fake IPs
        for hdr_name, ip_list in ip_rotation_headers:
            await _throttle_rate()
            fake_ip = ip_list[0] if ip_list else "1.2.3.4"
            try:
                headers = {"Accept": "*/*", hdr_name: fake_ip, **_extra_h}
                req = urllib.request.Request(url, headers=headers, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method={hdr_name}:{fake_ip} status={status}")
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method={hdr_name}:{fake_ip} status={e.code}")
                    break
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Technique 2: Different HTTP methods
        for method in ["GET", "POST", "PUT", "PATCH", "OPTIONS"]:
            await _throttle_rate()
            try:
                req = urllib.request.Request(url, headers={"Accept": "*/*", **_extra_h}, method=method)
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=HTTP_{method} status={status}")
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=HTTP_{method} status={e.code}")
                    break
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Technique 3: Random query params
        await _throttle_rate()
        timestamp = int(__import__("time").time())
        variant_qs = f"_={timestamp}"
        if qs:
            variant_qs = f"{qs}&_={timestamp}"
        variant_url = f"{base}{path}?{variant_qs}"
        try:
            req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
            status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
            if status == 200 and baseline_status in (429, 403):
                findings.append(f"[ratelimit-bypass] {url} method=RANDOM_PARAM status={status}")
        except urllib.error.HTTPError as e:
            if e.code == 200 and baseline_status in (429, 403):
                findings.append(f"[ratelimit-bypass] {url} method=RANDOM_PARAM status={e.code}")
        except (urllib.error.URLError, OSError, socket.timeout):
            pass
        except Exception:
            pass

        # Technique 4: Case variation in URL path
        for transform in case_transforms:
            await _throttle_rate()
            new_path = transform(path)
            if new_path == path:
                continue
            variant_url = f"{base}{new_path}"
            if qs:
                variant_url += "?" + qs
            try:
                req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=CASE_VARIATION status={status}")
                    break
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=CASE_VARIATION status={e.code}")
                    break
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

        # Technique 5: Unicode/special chars in path
        await _throttle_rate()
        unicode_path = path
        for orig, repl in unicode_swaps:
            unicode_path = unicode_path.replace(orig, repl)
        if unicode_path != path:
            variant_url = f"{base}{unicode_path}"
            if qs:
                variant_url += "?" + qs
            try:
                req = urllib.request.Request(variant_url, headers={"Accept": "*/*", **_extra_h}, method="GET")
                status, resp_headers, body_bytes = await _async_urlopen(_urlopen, req, timeout=12)
                if status == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=UNICODE_PATH status={status}")
            except urllib.error.HTTPError as e:
                if e.code == 200 and baseline_status in (429, 403):
                    findings.append(f"[ratelimit-bypass] {url} method=UNICODE_PATH status={e.code}")
            except (urllib.error.URLError, OSError, socket.timeout):
                pass
            except Exception:
                pass

    if not findings:
        findings.append("[ratelimit-bypass] No findings (expected)")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("ok", f"136-RATELIMITBYPASS: {len(findings)} findings → {out}")
    return {"136-RATELIMITBYPASS": str(out), "count": len(findings)}
