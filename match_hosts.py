#!/usr/bin/env python3
"""Bulk scanner: request every link, find which of N hosts appear in the FULL response.

Full response = status line + headers (incl. redirect Location of every hop)
              + body (decompressed, size-capped)
              + TLS certificate SANs of every HTTPS hop (SSL errors ignored)

Matching is done with a single Aho-Corasick automaton pass over the haystack,
so 1500 hosts cost the same as 1 host per response (no 1500x grep).

Output line format:
    <link requested> : <matched host>, <matched host>

Failed requests go to the optional -e file as:
    <link requested> : <error>

The run checkpoints every processed link to <output>.processed, so an
interrupted 333K-link run continues where it stopped (use --no-resume to redo).

Usage:
    python3 match_hosts.py -l links.txt -H hosts.txt -o matches.txt -e errors.txt

Requires: aiohttp (needed), pyahocorasick + cryptography (recommended; the
script falls back to a built-in Aho-Corasick and stdlib cert decoding).
"""

import argparse
import asyncio
import re
import ssl
import sys
import time
from urllib.parse import urljoin, urlsplit

try:
    import ahocorasick  # C implementation
except ImportError:
    ahocorasick = None

try:
    from cryptography import x509 as _x509
except ImportError:
    _x509 = None

try:
    import aiohttp
except ImportError:  # pragma: no cover
    raise SystemExit("aiohttp is required:  pip3 install aiohttp")

# --------------------------------------------------------------------------- #
# hosts
# --------------------------------------------------------------------------- #


def normalize_host(raw: str) -> str:
    """'https://User@Foo.Example.com:8443/a?b=1' -> 'foo.example.com'

    Wildcard targets ('*.foo.com', 'x*.foo.com') are reduced to the literal
    suffix that every expansion contains, so they can still be matched.
    """
    s = raw.strip().strip(",;'\"").rstrip('),.;').lstrip('(')
    if not s:
        return ""
    s = s.lower()
    s = s.replace("###", "*")  # bugcrowd-style host placeholder
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.count(":") == 1:  # host:port (not IPv6)
        s = s.split(":", 1)[0]
    elif s.startswith("[") and "]:" in s:
        s = s[1:].split("]:", 1)[0]
    if "*" in s:
        s = s.split("*", 1)[1]
    return s.strip("[]")


def load_hosts(path: str):
    """-> list of unique normalized hosts (lowercase, no scheme/port/path).

    One line may hold several entries separated by commas/whitespace.
    Annotation text that is not a host is dropped.
    """
    seen = {}
    dropped = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            for part in re.split(r"[,\s]+", line.strip()):
                if not part:
                    continue
                h = normalize_host(part)
                if not h:
                    dropped += 1
                    continue
                if not re.fullmatch(r"[a-z0-9._-]+", h) or "." not in h:
                    dropped += 1  # prose / junk, not a hostname
                    continue
                if h not in seen:
                    seen[h] = h
    if dropped:
        print(f"[!] dropped {dropped} non-host entries from {path}", file=sys.stderr)
    return list(seen.keys())


# --------------------------------------------------------------------------- #
# Aho-Corasick automaton (one pass, bulk match of all hosts at once)
# --------------------------------------------------------------------------- #


class Matcher:
    def __init__(self, patterns):
        self.patterns = patterns
        self.ids = {p: i for i, p in enumerate(patterns)}
        self._ac = None
        self._py = None
        if ahocorasick is not None:
            a = ahocorasick.Automaton()
            for i, p in enumerate(patterns):
                a.add_word(p, i)
            a.make_automaton()
            self._ac = a
        else:
            self._build_pure_python(patterns)

    def _build_pure_python(self, patterns):
        goto, fail, out = {0: {}}, {}, {}
        for i, p in enumerate(patterns):
            state = 0
            for ch in p:
                state = goto[state].setdefault(ch, len(goto))
                goto.setdefault(state, {})
            out.setdefault(state, []).append(i)
        from collections import deque

        q = deque(goto[0].values())
        for st in q:
            fail[st] = 0
        while q:
            r = q.popleft()
            for ch, s in goto[r].items():
                q.append(s)
                f = fail[r]
                while f and ch not in goto[f]:
                    f = fail[f]
                fail[s] = goto[f].get(ch, 0) if (f != r or ch in goto[f]) else 0
                out.setdefault(s, []).extend(out.get(fail[s], ()))
        self._py = (goto, fail, out)

    def find(self, text: str):
        """-> set of pattern ids present in text (case: text must be lowercase)."""
        if self._ac is not None:
            return {v for _, v in self._ac.iter(text)}
        goto, fail, out = self._py
        res, state = set(), 0
        for ch in text:
            nxt = goto[state].get(ch)
            while nxt is None and state:
                state = fail[state]
                nxt = goto[state].get(ch)
            if nxt is None:
                state = 0
                continue
            state = nxt
            if state in out:
                res.update(out[state])
        return res


# --------------------------------------------------------------------------- #
# TLS certificate SANs
# --------------------------------------------------------------------------- #

_CERT_CACHE = {}
_CERT_CACHE_MAX = 50000


def sans_from_der(der: bytes):
    if der in _CERT_CACHE:
        return _CERT_CACHE[der]
    names = []
    if _x509 is not None:
        try:
            cert = _x509.load_der_x509_certificate(der)
            try:
                san = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
                val = san.value
                for typ_name in ("DNSName", "IPAddress", "UniformResourceIdentifier"):
                    typ = getattr(_x509, typ_name, None)
                    if typ is None:
                        continue
                    try:
                        names += [str(v) for v in val.get_values_for_type(typ)]
                    except AttributeError:
                        pass
                    except Exception:
                        pass
                # legacy API (cryptography < 46)
                for attr in ("dns_names", "ip_addresses", "uniform_resource_identifiers"):
                    try:
                        names += [str(v) for v in getattr(val, attr)]
                    except AttributeError:
                        pass
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                cn = cert.subject.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)
                names += [a.value for a in cn]
            except Exception:
                pass
        except Exception:
            pass
    else:  # fallback: stdlib decode via temp file
        import tempfile
        import os

        try:
            pem = ssl.DER_cert_to_PEM_cert(der)
            fd, p = tempfile.mkstemp()
            try:
                os.write(fd, pem.encode())
                os.close(fd)
                info = ssl._ssl._test_decode_cert(p)
                for typ, val in info.get("subjectAltName", ()):
                    if typ in ("DNS", "IP Address"):
                        names.append(val)
            finally:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        except Exception:
            pass
    if len(_CERT_CACHE) > _CERT_CACHE_MAX:
        _CERT_CACHE.clear()
    names = list(dict.fromkeys(str(n) for n in names if n))
    _CERT_CACHE[der] = names
    return names


def peer_sans(transport) -> list:
    """Extract TLS certificate SANs from an aiohttp transport."""
    if transport is None:
        return []
    try:
        so = transport.get_extra_info("ssl_object")
        if so is None:
            return []
        der = so.getpeercert(binary_form=True)
        if not der:
            return []
        return sans_from_der(der)
    except Exception:
        return []


# peer (host, port) -> SANs of the certificate it presented
SANS_BY_PEER: dict = {}


class CertConnector(aiohttp.TCPConnector):
    """Records the TLS certificate SANs of every connection it opens.

    The response object does not always expose its socket (servers that close
    right away, HTTP/1.0, etc.), so the certificate is grabbed at connect time.
    """

    async def _wrap_create_connection(self, *args, **kwargs):
        transport, proto = await super()._wrap_create_connection(*args, **kwargs)
        _record_cert(transport, _find_req(args, kwargs))
        return transport, proto

    async def _wrap_existing_connection(self, *args, **kwargs):
        transport, proto = await super()._wrap_existing_connection(*args, **kwargs)
        _record_cert(transport, _find_req(args, kwargs))
        return transport, proto


def _find_req(args, kwargs):
    """Locate the ClientRequest in a connector call (aiohttp version tolerant)."""
    req = kwargs.get("req")
    if req is not None:
        return req
    for a in args:
        if hasattr(a, "connection_key"):
            return a
    return None


def _record_cert(transport, req) -> None:
    try:
        so = transport.get_extra_info("ssl_object")
        if so is None:
            return
        der = so.getpeercert(binary_form=True)
        if not der:
            return
        names = sans_from_der(der)
        keys = []
        if req is not None:
            ck = getattr(req, "connection_key", None)
            if ck is not None:
                keys += [(ck.host, ck.port), (ck.host, None)]
            host = getattr(req, "host", None)
            if host:
                keys += [(host, getattr(req, "port", None)), (host, None)]
        peer = transport.get_extra_info("peername")
        if peer:
            keys.append(tuple(peer[:2]))
        if len(SANS_BY_PEER) > 200000:
            SANS_BY_PEER.clear()
        for k in keys:
            SANS_BY_PEER[k] = names
    except Exception:
        pass


def lookup_sans(parts) -> list:
    """SANs for the first (host, port) key present in `parts`."""
    for key in parts:
        if key in SANS_BY_PEER:
            return SANS_BY_PEER[key]
    return []


# --------------------------------------------------------------------------- #
# fetching
# --------------------------------------------------------------------------- #

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
for _opt in ("OP_LEGACY_SERVER_CONNECT", "OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION"):  # old servers
    _flag = getattr(ssl, _opt, None)
    if _flag is not None:
        CTX.options |= _flag

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "*/*",
    "Connection": "close",
}

_FALLBACK_SANS = {}


def fetch_cert_sans(host: str, port: int, timeout: float = 2.0) -> list:
    """Last resort: open a separate TLS handshake to read the certificate SANs.

    Used only when the connection the response ran on did not expose its
    socket (aiohttp version differences, servers that close immediately).
    Results (including failures) are cached per host:port.
    """
    key = (host, port)
    if key in _FALLBACK_SANS:
        return _FALLBACK_SANS[key]
    import socket

    names = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with CTX.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if der:
            names = sans_from_der(der)
    except Exception:
        names = []
    if len(_FALLBACK_SANS) > 50000:
        _FALLBACK_SANS.clear()
    _FALLBACK_SANS[key] = names
    return names


def headers_text(resp) -> str:
    lines = [f"HTTP {resp.status} {resp.reason}"]
    lines += [f"{k}: {v}" for k, v in resp.headers.items()]
    return "\r\n".join(lines)


async def scan_one(session, url: str, matcher: Matcher, args, deadline: float):
    """Request one link (following redirects). Return (matched_ids, hops, error)."""
    matched = set()
    hops = 0
    visited = set()
    current = url
    err = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            err = err or "timeout"
            break
        if hops >= args.max_redirects:
            err = err or "max-redirects"
            break
        if current in visited:
            err = err or "redirect-loop"
            break
        visited.add(current)
        try:
            to = aiohttp.ClientTimeout(total=min(remaining, args.timeout))
            async with session.get(
                current,
                timeout=to,
                ssl=CTX if urlsplit(current).scheme == "https" else None,
                allow_redirects=False,
                headers=HEADERS,
                compress=True,
            ) as r:
                hops += 1
                parts = [headers_text(r)]
                # TLS certificate SANs of this hop (SSL errors are ignored)
                sp = urlsplit(current)
                if sp.scheme == "https":
                    port = sp.port or 443
                    tr = r.connection.transport if r.connection else None
                    sans = peer_sans(tr)
                    if not sans:
                        sans = lookup_sans([(sp.hostname, port), (sp.hostname, None)])
                    if not sans and getattr(args, "cert_fallback", True) and sp.hostname:
                        left = deadline - time.monotonic()
                        if left > 0.3:
                            sans = await asyncio.get_running_loop().run_in_executor(
                                None, fetch_cert_sans, sp.hostname, port, min(2.0, left)
                            )
                    if sans:
                        parts.append("\n".join(sans))
                body = await r.content.read(args.max_body + 1)
                if body:
                    parts.append(body[: args.max_body].decode("utf-8", "replace"))
                matched |= matcher.find("\n".join(parts).lower())

                loc = r.headers.get("Location")
                if 300 <= r.status < 400 and loc:
                    nxt = urljoin(current, loc)
                    if urlsplit(nxt).scheme in ("http", "https"):
                        current = nxt
                        continue
                break
        except asyncio.CancelledError:
            raise
        except Exception as e:
            err = f"{type(e).__name__}: {e}"[:200]
            break
    return matched, hops, err


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def load_links(path: str, done: set, stats: dict):
    """Yield fetchable, not-yet-processed links (one input line may hold several)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip().strip(",")
            if not raw or raw.startswith("#"):
                continue
            parts = [raw] if raw.count("://") <= 1 else [p.strip() for p in raw.split(",") if p.strip()]
            for u in parts:
                if "://" not in u:
                    u = "http://" + u
                host = urlsplit(u).hostname or ""
                if "*" in host:  # wildcard targets are not fetchable
                    stats["wildcard"] = stats.get("wildcard", 0) + 1
                    continue
                if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
                    stats["invalid"] = stats.get("invalid", 0) + 1
                    continue
                if u in done:
                    stats["resume"] = stats.get("resume", 0) + 1
                    continue
                yield u


async def runner(args):
    hosts = load_hosts(args.hosts)
    if not hosts:
        sys.exit("no usable hosts in %s" % args.hosts)
    matcher = Matcher(hosts)
    engine = "pyahocorasick" if ahocorasick is not None else "pure-python Aho-Corasick"
    print(
        f"[+] {len(hosts)} hosts | matcher={engine} | workers={args.workers} "
        f"| timeout={args.timeout}s | max-body={args.max_body}",
        file=sys.stderr,
    )

    done = set()
    state_path = args.state or (args.output + ".processed")
    if args.resume:
        for path in (state_path, args.output):
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        u = line.split(" : ", 1)[0].strip()
                        if u:
                            done.add(u)
            except FileNotFoundError:
                continue
        if done:
            print(f"[+] resume: {len(done)} links already processed -> skip", file=sys.stderr)

    sem = asyncio.Semaphore(args.workers)
    connector = CertConnector(
        limit=args.workers * 2, ttl_dns_cache=300, force_close=True, ssl=CTX
    )
    out = open(args.output, "a", encoding="utf-8", buffering=1)
    errf = open(args.errors, "a", encoding="utf-8", buffering=1) if args.errors else None
    statef = open(state_path, "a", encoding="utf-8", buffering=1)

    st = {"done": 0, "matched": 0, "errors": 0, "start": time.monotonic()}

    async def worker(url):
        async with sem:
            matched, hops, err = await scan_one(session, url, matcher, args, time.monotonic() + args.timeout)
        st["done"] += 1
        statef.write(url + "\n")
        if err and not matched:
            st["errors"] += 1
            if errf:
                errf.write(f"{url} : {err}\n")
        if matched:
            st["matched"] += 1
            names = ", ".join(hosts[i] for i in sorted(matched))
            out.write(f"{url} : {names}\n")
        if st["done"] % args.progress == 0:
            el = time.monotonic() - st["start"]
            print(
                f"[~] done={st['done']} matched={st['matched']} errors={st['errors']} "
                f"rate={st['done']/el:.1f}/s elapsed={el:.0f}s",
                file=sys.stderr,
                flush=True,
            )

    total = 0
    stats = {}
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for url in load_links(args.links, done, stats):
            tasks.append(asyncio.create_task(worker(url)))
            total += 1
            if len(tasks) >= args.chunk:
                await asyncio.gather(*tasks)
                tasks = []
        if tasks:
            await asyncio.gather(*tasks)
    if stats.get("wildcard"):
        print(f"[!] skipped {stats['wildcard']} wildcard links (not fetchable)", file=sys.stderr)
    if stats.get("invalid"):
        print(f"[!] skipped {stats['invalid']} invalid link lines", file=sys.stderr)
    if stats.get("resume"):
        print(f"[+] skipped {stats['resume']} links already processed", file=sys.stderr)

    out.close()
    statef.close()
    if errf:
        errf.close()
    el = time.monotonic() - st["start"]
    print(
        f"[+] finished: links={total} matched={st['matched']} errors={st['errors']} "
        f"time={el:.0f}s rate={(st['done']/el if el else 0):.1f}/s -> {args.output}",
        file=sys.stderr,
    )


def main():
    p = argparse.ArgumentParser(description="Bulk full-response host matcher (headers+body+cert SANs)")
    p.add_argument("-l", "--links", required=True, help="file with one link per line")
    p.add_argument("-H", "--hosts", required=True, help="file with one host per line")
    p.add_argument("-o", "--output", default="matches.txt", help="results file (append)")
    p.add_argument("-e", "--errors", default=None, help="optional errors file (append)")
    p.add_argument("-w", "--workers", type=int, default=10, help="parallel workers (default 10)")
    p.add_argument("-t", "--timeout", type=float, default=5.0, help="per-link timeout seconds (default 5)")
    p.add_argument("--max-body", type=int, default=5 * 1024 * 1024, help="body bytes to read (default 5MB)")
    p.add_argument("--max-redirects", type=int, default=10)
    p.add_argument("--progress", type=int, default=500, help="progress print every N links")
    p.add_argument("--chunk", type=int, default=2000, help="links scheduled per gather batch")
    p.add_argument(
        "--no-cert-fallback",
        action="store_true",
        help="never open a second TLS handshake to read certificate SANs",
    )
    if hasattr(argparse, "BooleanOptionalAction"):  # Python >= 3.9
        p.add_argument(
            "--resume",
            action=argparse.BooleanOptionalAction,
            default=True,
            help="skip links already in the checkpoint file (default on, use --no-resume to restart)",
        )
    else:
        p.add_argument(
            "--resume", dest="resume", action="store_true", default=True,
            help="skip links already in the checkpoint file (default on)",
        )
        p.add_argument("--no-resume", dest="resume", action="store_false", help=argparse.SUPPRESS)
    p.add_argument(
        "--state",
        default=None,
        help="checkpoint file of processed links (default <output>.processed)",
    )
    args = p.parse_args()
    args.cert_fallback = not args.no_cert_fallback
    try:
        asyncio.run(runner(args))
    except KeyboardInterrupt:
        print("[!] interrupted (results kept, rerun to continue from checkpoint)", file=sys.stderr)


if __name__ == "__main__":
    main()
