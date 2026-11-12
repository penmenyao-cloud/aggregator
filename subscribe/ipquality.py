# -*- coding: utf-8 -*-

# IP quality filter backed by ip.net.coffee (no login / API key needed).
#
# For every alive proxy, resolve its `server` to an IP and query
# https://ip.net.coffee/api/iprisk/<ip>, which returns a `trust_score`
# (0-100, higher = more trusted) plus geo/ASN flags. Proxies whose IP
# scores below QUALITY_MIN_SCORE (default 60) are dropped.
#
# Fail-open by design: any lookup failure (DNS, HTTP error, timeout,
# rate limit, unparsable reply) keeps the proxy, so a checker outage
# never empties the subscription. A circuit breaker plus a global
# deadline bound the total checking time when the checker is down.
#
# Results are cached on disk (QUALITY_CACHE_FILE) with a TTL so
# repeated runs do not re-query the same IP; the workflow persists
# the cache file with actions/cache. A per-run report is written to
# QUALITY_REPORT_FILE for dashboards / debugging.

import concurrent.futures
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from logger import logger
except Exception:  # pragma: no cover - standalone use outside the repo
    import logging

    logger = logging.getLogger(__name__)

API_BASE = "https://ip.net.coffee/api/iprisk"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
REFERER = "https://ip.net.coffee/gpt/"

_REPO_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _default_cache_file() -> str:
    return os.environ.get("QUALITY_CACHE_FILE") or os.path.join(_REPO_ROOT, "data", "quality_cache.json")


def _default_report_file() -> str:
    return os.environ.get("QUALITY_REPORT_FILE") or os.path.join(_REPO_ROOT, "data", "quality_report.json")


def _resolve_ip(server: str):
    """Resolve a hostname to one public IP (prefer IPv4). Return None on failure.

    Non-public addresses (private, CGNAT, benchmarking ranges such as a
    DNS wildcard returning 198.18.x.x) are treated as unresolvable so a
    broken resolver can never get a node scored against a fake IP.
    """
    server = (server or "").strip().strip("[]")
    if not server:
        return None
    try:
        ip = ipaddress.ip_address(server)
        return str(ip) if ip.is_global else None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(server, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        return None
    ipv4, ipv6 = None, None
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if not ip.is_global:
            continue
        if ":" not in str(ip) and ipv4 is None:
            ipv4 = str(ip)
        elif ":" in str(ip) and ipv6 is None:
            ipv6 = str(ip)
    return ipv4 or ipv6


def _query_ip(ip: str, timeout: float):
    """Query ip.net.coffee for one IP. Return info dict or None on failure."""
    url = f"{API_BASE}/{urllib.parse.quote(ip, safe='')}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Referer": REFERER})
    last_error = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    last_error = f"HTTP {resp.status}"
                    if resp.status in (429, 500, 502, 503, 504) and attempt == 0:
                        time.sleep(2)
                        continue
                    return None
                data = json.loads(resp.read().decode("utf8", "ignore"))
            score = data.get("trust_score")
            if score is None:
                return None
            return {
                "score": int(score),
                "country": data.get("country") or "",
                "country_code": data.get("countryCode") or "",
                "region": data.get("region") or "",
                "city": data.get("city") or "",
                "asn": data.get("asn") or "",
                "isp": data.get("asOrganization") or data.get("company_name") or "",
                "is_datacenter": bool(data.get("is_datacenter")),
                "is_residential": bool(data.get("isResidential")),
            }
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
            last_error = str(e)
            if attempt == 0:
                time.sleep(1)
    logger.debug(f"ip quality lookup failed, ip={ip}, error={last_error}")
    return None


def _load_cache(path: str, ttl_seconds: float) -> dict:
    try:
        with open(path, "r", encoding="utf8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    now = time.time()
    fresh = {}
    for ip, entry in raw.items():
        if not isinstance(entry, dict) or entry.get("score") is None:
            continue
        try:
            ts = float(entry.get("ts", 0))
        except (TypeError, ValueError):
            continue
        if now - ts <= ttl_seconds:
            fresh[ip] = entry
    return fresh


def _save_cache(path: str, cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf8") as f:
            json.dump(cache, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception as e:
        logger.warning(f"cannot save ip quality cache, file={path}, error={e}")


def filter_proxies(proxies, group: str = ""):
    """Drop proxies whose server IP trust_score is below the threshold.

    Returns the filtered list. Lookup failures keep the proxy.
    Always writes the per-run report file when the filter is enabled.
    """
    enabled = os.environ.get("QUALITY_CHECK_ENABLED", "1").strip() not in ("0", "false", "no")
    if not enabled:
        logger.info("ip quality check disabled, skip")
        return proxies
    if not proxies:
        return proxies

    min_score = _env_int("QUALITY_MIN_SCORE", 60)
    max_workers = max(1, _env_int("QUALITY_MAX_WORKERS", 10))
    timeout = max(5.0, _env_float("QUALITY_TIMEOUT", 15.0))
    ttl = max(0.0, _env_float("QUALITY_CACHE_TTL_HOURS", 24.0)) * 3600
    deadline = time.time() + max(60.0, _env_float("QUALITY_DEADLINE_SECONDS", 240.0))
    breaker_limit = max(5, _env_int("QUALITY_BREAKER_FAILURES", 15))
    cache_file = _default_cache_file()
    report_file = _default_report_file()

    # 1. resolve each unique server to an IP (threaded, DNS may be slow)
    servers = []
    seen = set()
    for p in proxies:
        server = (p.get("server") or "") if isinstance(p, dict) else ""
        if server and server not in seen:
            seen.add(server)
            servers.append(server)

    server_ip = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for server, ip in pool.map(lambda s: (s, _resolve_ip(s)), servers):
            server_ip[server] = ip

    # 2. score each unique IP, reusing fresh cache entries
    cache = _load_cache(cache_file, ttl)
    ips = sorted({ip for ip in server_ip.values() if ip})
    to_query = [ip for ip in ips if ip not in cache]
    results = {ip: cache[ip] for ip in ips if ip in cache}
    failures = 0
    if to_query:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_ip = {pool.submit(_query_ip, ip, timeout): ip for ip in to_query}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                if time.time() > deadline or failures >= breaker_limit:
                    # checker looks down: stop querying, keep the rest unchecked
                    break
                try:
                    info = future.result()
                except Exception:
                    info = None
                if info is None:
                    failures += 1
                    continue
                failures = 0
                entry = dict(info, ts=time.time())
                results[ip] = entry
                cache[ip] = entry
        _save_cache(cache_file, cache)

    # 3. decide per proxy (fail-open) and build the report
    kept, nodes = [], []
    dropped, unknown = 0, 0
    for p in proxies:
        if not isinstance(p, dict):
            continue
        name = p.get("name") or ""
        server = (p.get("server") or "").strip()
        ip = server_ip.get(server)
        info = results.get(ip) if ip else None
        if not server:
            keep, reason = True, "no_server_kept"
        elif not ip:
            keep, reason = True, "unresolved_kept"
        elif info is None:
            keep, reason = True, "lookup_failed_kept"
        elif info["score"] >= min_score:
            keep, reason = True, "ok"
        else:
            keep, reason = False, "below_threshold"
        if keep:
            kept.append(p)
            if reason != "ok":
                unknown += 1
        else:
            dropped += 1
        nodes.append(
            {
                "name": name,
                "server": server,
                "ip": ip or "",
                "country": (info or {}).get("country", ""),
                "region": (info or {}).get("region", ""),
                "city": (info or {}).get("city", ""),
                "country_code": (info or {}).get("country_code", ""),
                "asn": (info or {}).get("asn", ""),
                "isp": (info or {}).get("isp", ""),
                "is_datacenter": (info or {}).get("is_datacenter"),
                "is_residential": (info or {}).get("is_residential"),
                "score": (info or {}).get("score"),
                "kept": keep,
                "reason": reason,
            }
        )

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "group": group,
        "min_score": min_score,
        "total": len(proxies),
        "kept": len(kept),
        "dropped": dropped,
        "unknown_kept": unknown,
        "ips_checked": len(ips),
        "ips_from_cache": len(ips) - len(to_query),
        "nodes": nodes,
    }
    try:
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        with open(report_file, "w", encoding="utf8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"cannot write ip quality report, file={report_file}, error={e}")

    logger.info(
        f"ip quality check finished, group=[{group}], total={len(proxies)}, "
        f"kept={len(kept)}, dropped={dropped}, unknown_kept={unknown}, "
        f"threshold={min_score}"
    )
    return kept
