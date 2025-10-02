#!/usr/bin/env python3

import argparse
import json
import re
import sys
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qsl, urlsplit, urlencode

# Silence SSL warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

try:
    import requests
except Exception:
    requests = None

try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None

try:
    import jsbeautifier
except Exception:
    jsbeautifier = None

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/118.0 Safari/537.36 js-request-modeler/2.0"
)

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def sha16_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def beautify_js(text: str) -> str:
    if jsbeautifier is not None:
        try:
            opts = jsbeautifier.default_options()
            opts.end_with_newline = True
            opts.wrap_line_length = 120
            opts.keep_array_indentation = False
            return jsbeautifier.beautify(text, opts)
        except Exception:
            pass
    t = re.sub(r';(?!\s*\n)', ';\n', text)
    t = re.sub(r'(\{|\})(?!\s*\n)', r'\1\n', t)
    t = re.sub(r',(?!\s*\n)', ',\n', t)
    return t


def parse_vars(pairs: List[str]) -> Dict[str, str]:
    out = {}
    for p in pairs or []:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip()] = v.strip()
    return out

_VAR_TOKEN = re.compile(r"\$\{\s*([^}]+?)\s*\}")

def substitute_vars(s: str, mapping: Dict[str, str]) -> str:
    if not s or not mapping: return s
    # first, percent-decode once to resolve %7B %7D etc.
    try:
        s_dec = unquote(s)
    except Exception:
        s_dec = s
    def repl(m):
        key = m.group(1)
        return mapping.get(key, m.group(0))
    return _VAR_TOKEN.sub(repl, s_dec)


def headers_list_to_dict(hlist: List[str]) -> Dict[str, str]:
    out = {}
    for h in hlist or []:
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out

_HTTP_METHODS = r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
_q = r"['\"`]"
PATTERNS = [
    # fetch('url', { method: 'POST', body: ... })
    re.compile(rf"fetch\(\s*{_q}(?P<url>.+?){_q}\s*(?:,\s*\{{(?P<opts>.*?)\}}\s*)?\)", re.DOTALL),
    # axios.get('url', ...)
    re.compile(rf"axios\.(?P<meth>get|post|put|delete|patch|head|options)\s*\(\s*{_q}(?P<url>.+?){_q}\s*(?P<rest>\,.*?\))", re.DOTALL|re.IGNORECASE),
    # $http.get('url', ...)
    re.compile(rf"\$http\.(?P<meth>get|post|put|delete|patch|head|options)\s*\(\s*{_q}(?P<url>.+?){_q}\s*(?P<rest>\,.*?\))", re.DOTALL|re.IGNORECASE),
    # $.ajax({ url: '...', method: '...' })
    re.compile(rf"\$\.ajax\s*\(\s*\{{(?P<opts>.*?)\}}\s*\)", re.DOTALL),
    # XHR.open('GET','url')
    re.compile(rf"\.open\(\s*{_q}(?P<meth>{_HTTP_METHODS}){_q}\s*,\s*{_q}(?P<url>.+?){_q}", re.DOTALL|re.IGNORECASE),
    # angular http.*('url', ...)
    re.compile(rf"\bhttp\.(?P<meth>get|post|put|delete|patch|head|options)\s*\(\s*{_q}(?P<url>.+?){_q}\s*(?P<rest>\,.*?\))", re.DOTALL|re.IGNORECASE),
    # HttpClient.request('GET','url', ...)
    re.compile(rf"\bhttp(?:Client)?\.request\s*\(\s*{_q}(?P<meth>{_HTTP_METHODS}){_q}\s*,\s*{_q}(?P<url>.+?){_q}\s*(?P<rest>\,.*?\))", re.DOTALL|re.IGNORECASE),
    # http.post(`${base}/foo`, ...)
    re.compile(rf"\bhttp(?:Client)?\.(?P<meth>get|post|put|delete|patch|head|options)\s*\(\s*{_q}(?P<url>.+?){_q}\s*(?P<rest>\,.*?\))", re.DOTALL|re.IGNORECASE),
    # HttpClient.request(methodVar, 'url', ...)
    re.compile(rf"\bhttp(?:Client)?\.request\s*\(\s*(?P<methvar>[A-Za-z_][\w\.]*)\s*,\s*{_q}(?P<url>.+?){_q}\s*(?P<rest>\,.*?\))", re.DOTALL|re.IGNORECASE),
]

KEY_CAPTURE = re.compile(r"([A-Za-z0-9_\-$]+)\s*:", re.MULTILINE)
PLACEHOLDER_PATTERNS = [
    re.compile(r"/:(?P<name>[A-Za-z0-9_]+)\b"),
    re.compile(r"\{(?P<name>[A-Za-z0-9_]+)\}"),
    re.compile(r"\$\{\s*(?P<name>[A-Za-z0-9_]+)\s*\}"),
    re.compile(r"<(?P<name>[A-Za-z0-9_]+)>"),
]

def _balance_from(text: str, start_idx: int, open_char="{", close_char="}") -> Optional[Tuple[int,int]]:
    depth = 0; i = start_idx; in_str = None; esc = False
    while i < len(text):
        ch = text[i]
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == in_str: in_str = None
        else:
            if ch in ("'", '"', "`"): in_str = ch
            elif ch == open_char: depth += 1
            elif ch == close_char:
                depth -= 1
                if depth == 0: return (start_idx, i)
        i += 1
    return None

def _resolve_literal_assignment(js_text: str, varname: str, pos: int, back_bytes: int = 5000) -> Optional[str]:
    start = max(0, pos - back_bytes)
    chunk = js_text[start:pos]
    rx = re.compile(rf"(?:const|let|var)\s+{re.escape(varname)}\s*=\s*(['\"`])(?P<val>.+?)\1", re.DOTALL)
    m = None
    for m in rx.finditer(chunk):
        pass
    if m:
        return m.group("val")
    return None

def extract_params_from_rest(rest: str) -> List[str]:
    if not rest: return []
    idx = rest.find("{")
    if idx == -1: return []
    span = _balance_from(rest, idx, "{", "}")
    if not span: return []
    lit = rest[span[0]:span[1]+1]
    keys = set(KEY_CAPTURE.findall(lit))
    nested_params = set()
    for m in re.finditer(r"data\s*:\s*\{", lit):
        sp = _balance_from(lit, m.end()-1, "{", "}")
        if sp:
            nested = lit[sp[0]:sp[1]+1]
            nested_params.update(KEY_CAPTURE.findall(nested))
    return sorted(set(list(keys) + list(nested_params)))

def extract_placeholders_from_path(path: str) -> List[str]:
    names = set()
    for rx in PLACEHOLDER_PATTERNS:
        for m in rx.finditer(path or ""):
            names.add(m.group("name"))
    return sorted(names)

def extract_query_keys(url: str) -> List[str]:
    try:
        q = urlparse(url).query
        qs = dict(parse_qsl(q, keep_blank_values=True))
        return sorted(qs.keys())
    except Exception:
        return []

def guess_method_from_opts(opts_text: str) -> Optional[str]:
    m = re.search(r"method\s*:\s*['\"](" + _HTTP_METHODS + r")['\"]", opts_text or "", re.IGNORECASE)
    if m: return m.group(1).upper()
    m2 = re.search(r"type\s*:\s*['\"](" + _HTTP_METHODS + r")['\"]", opts_text or "", re.IGNORECASE)
    if m2: return m2.group(1).upper()
    m3 = re.search(r"method\s*=\s*['\"]([A-Z]+)['\"]", opts_text or "", re.IGNORECASE)
    if m3: return m3.group(1).upper()
    return None

def normalize_url(base: str, u: str) -> Optional[str]:
    if not u: return None
    u = u.strip()
    if u.startswith("//"):
        pr = urlparse(base)
        return f"{pr.scheme}:{u}"
    if u.startswith("/"):
        pr = urlparse(base)
        return f"{pr.scheme}://{pr.netloc}{u}"
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return urljoin(base, u)

def extract_endpoints_from_js(js_text: str, base_hint: str, var_map: Dict[str,str]) -> List[Dict]:
    results = []
    for rx in PATTERNS:
        for m in rx.finditer(js_text):
            gd = m.groupdict()
            url = gd.get("url")
            if (not url) and "opts" in gd:
                opts = gd.get("opts") or ""
                mu = re.search(r"url\s*:\s*['\"`](.+?)['\"`]", opts, re.DOTALL)
                url = mu.group(1) if mu else None
            if (not url) and gd.get("rest"):
                mu2 = re.search(r"url\s*=\s*['\"`](.+?)['\"`]", gd.get("rest"), re.DOTALL)
                if mu2: url = mu2.group(1)
            if not url:
                continue
            url = substitute_vars(url, var_map)
            # Method
            meth = gd.get("meth").upper() if gd.get("meth") else None
            if (not meth) and gd.get("opts"):
                meth = guess_method_from_opts(gd.get("opts"))

            rest = gd.get("rest") or gd.get("opts") or ""
            body_params = extract_params_from_rest(rest)
            qkeys = extract_query_keys(url)
            ph = extract_placeholders_from_path(url)

            if not re.match(r"^\s*https?://|^/|^[^${}]+$", url):
                pass 
            results.append({
                "method": meth or None,
                "raw_url": url,
                "url": normalize_url(base_hint, url) or url,
                "query_params": qkeys,
                "path_params": ph,
                "body_params": body_params,
                "evidence": (js_text[max(0,m.start()-100): m.end()+100])[:800]
            })
    return results

# ---------- Playwright crawl + ngsw.json + download ----------

def crawl_and_collect(url: str,
                      out_dir: Path,
                      proxy: Optional[str],
                      wait_ms: int,
                      timeout_ms: int,
                      user_agent: str,
                      extra_headers: Dict[str,str],
                      save_scripts: bool,
                      beautify: bool,
                      click_rounds: int,
                      click_max: int,
                      goto_same_origin: bool,
                      debug: bool=False):
    if sync_playwright is None:
        raise SystemExit("Playwright is required for crawl (pip install playwright; python -m playwright install chromium)")

    js_dir = out_dir / "js"; ensure_dir(js_dir)
    beauty_dir = out_dir / "beauty"; ensure_dir(beauty_dir)
    scripts_found = set()
    net_log = []

    if debug: print("[crawl] launching browser...")
    with sync_playwright() as pw:
        launch_args = dict(headless=True, args=["--disable-dev-shm-usage","--no-sandbox"])
        if proxy:
            p = urlparse(proxy)
            launch_args["proxy"] = {"server": f"{p.scheme}://{p.hostname}:{p.port}"}
            if p.username or p.password:
                launch_args["proxy"]["username"] = p.username or ""
                launch_args["proxy"]["password"] = p.password or ""
        browser = pw.chromium.launch(**launch_args)
        ctx = None
        page = None
        try:
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=user_agent,
                extra_http_headers=extra_headers,
                viewport={"width":1366,"height":900}
            )

            def global_route(route, request):
                rtype = request.resource_type
                if rtype in ("image","media","font","stylesheet","other"):
                    return route.abort()
                return route.continue_()
            ctx.route("**/*", global_route)

            page = ctx.new_page()

            # ---- Instrument fetch & XHR to capture runtime requests ---- * needs improvements
            hook_js = """
            (function(){
              window.__reqLog = window.__reqLog || [];
              function pushRec(rec){ try { window.__reqLog.push(rec); } catch(e){} }
              // fetch
              const _fetch = window.fetch;
              window.fetch = function(input, init){
                try {
                  const url = (typeof input === 'string') ? input : (input && input.url) || '';
                  const method = (init && init.method) ? String(init.method).toUpperCase() : 'GET';
                  pushRec({t: Date.now(), kind:'fetch', method, url});
                } catch(e){}
                return _fetch.apply(this, arguments);
              };
              // XHR
              const XO = window.XMLHttpRequest;
              const open0 = XO.prototype.open;
              XO.prototype.open = function(method, url){
                try { pushRec({t: Date.now(), kind:'xhr', method: String(method||'GET').toUpperCase(), url: String(url||'')}); } catch(e){}
                return open0.apply(this, arguments);
              };
            })();
            """
            page.add_init_script(hook_js)

            def on_request(req):
                try:
                    if req.resource_type == "script":
                        scripts_found.add(req.url)
                    net_log.append({"phase":"request","method":req.method,"url":req.url,"ts":time.time()})
                except Exception: pass
            def on_response(resp):
                try:
                    net_log.append({"phase":"response","status":resp.status,"url":resp.url,"ts":time.time()})
                except Exception: pass

            page.on("request", on_request)
            page.on("response", on_response)

            page.set_default_timeout(timeout_ms)
            page.set_default_navigation_timeout(timeout_ms)

            if debug: print(f"[crawl] goto {url}")
            page.goto(url, wait_until="domcontentloaded")

            try:
                if debug: print("[crawl] waiting for networkidle (short)")
                page.wait_for_load_state("networkidle", timeout=min(10000, timeout_ms))
            except Exception:
                if debug: print("[crawl] networkidle wait skipped/timeout")

            if wait_ms > 0:
                if debug: print(f"[crawl] extra wait {wait_ms}ms")
                page.wait_for_timeout(wait_ms)

            def safe_click_all(max_clicks=100):
                count = 0
                tried = set()
                sel_list = ["a[href]", "[routerlink]", "[role=button]", "button", "input[type=submit]"]
                for sel in sel_list:
                    els = page.query_selector_all(sel)
                    for el in els:
                        if count >= max_clicks: return count
                        try:
                            if not el.is_visible(): continue
                            box = el.bounding_box()
                            if not box: continue
                            href = el.get_attribute("href")
                            rlink = el.get_attribute("routerlink")
                            txt = (el.inner_text() or "")[:40]
                            rid = href or rlink or txt
                            key = f"{sel}|{rid}"
                            if key in tried: continue
                            tried.add(key)
                            el.click(timeout=1000)
                            page.wait_for_timeout(600)
                            count += 1
                        except Exception:
                            continue
                return count

            for i in range(max(0, int(click_rounds))):
                clicked = safe_click_all(max_clicks=int(click_max))
                if debug: print(f"[crawl] click round {i+1}: {clicked} clicks")
                try:
                    page.wait_for_load_state("networkidle", timeout=4000)
                except Exception:
                    pass
                page.wait_for_timeout(800)

            if goto_same_origin:
                origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                anchors = page.query_selector_all("a[href]")
                for a in anchors[:200]:
                    try:
                        href = a.get_attribute("href") or ""
                        if not href: continue
                        full = href if href.startswith("http") else urljoin(url, href)
                        if full.startswith(origin):
                            page.goto(full, wait_until="domcontentloaded")
                            try:
                                page.wait_for_load_state("networkidle", timeout=3000)
                            except Exception:
                                pass
                            page.wait_for_timeout(500)
                    except Exception:
                        continue

            if debug: print("[crawl] collecting script[src]")
            for el in page.query_selector_all("script[src]"):
                try:
                    u = el.get_attribute("src")
                    if u:
                        u = normalize_url(url, u)
                        scripts_found.add(u)
                except Exception:
                    pass

            if save_scripts:
                if debug: print(f"[crawl] saving {len(scripts_found)} scripts")
                for u in list(scripts_found):
                    try:
                        r = page.request.get(u, timeout=timeout_ms, ignore_https_errors=True)
                        if r.ok:
                            b = r.body()
                            h = sha16_bytes(b)
                            raw_path = js_dir / f"{h}.js"
                            raw_path.write_bytes(b)
                            if beautify:
                                try:
                                    txt = b.decode("utf-8", errors="ignore")
                                except Exception:
                                    txt = ""
                                bt = beautify_js(txt)
                                (beauty_dir / f"{h}.beauty.js").write_text(bt, encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

            try:
                reqs = page.evaluate("window.__reqLog || []")
            except Exception:
                reqs = []
            for r in reqs:
                if isinstance(r, dict) and r.get("url"):
                    net_log.append({"phase":"runtime","method":r.get("method","GET"),"url":r["url"],"ts":r.get("t", time.time())})

        finally:
            try:
                if page: page.close()
            except Exception: pass
            try:
                if ctx: ctx.close()
            except Exception: pass
            try:
                browser.close()
            except Exception: pass

    if debug: print(f"[crawl] collected scripts: {len(scripts_found)}")
    return scripts_found, net_log

def fetch_ngsw_list(url: str, timeout_ms: int) -> List[str]:
    if requests is None:
        return []
    candidates = []
    pr = urlparse(url)
    candidates.append(f"{pr.scheme}://{pr.netloc}/ngsw.json")
    candidates.append(urljoin(url, "ngsw.json"))
    assets = []
    for c in candidates:
        try:
            resp = requests.get(c, timeout=timeout_ms/1000, verify=False)
            if resp.ok:
                data = resp.json()
                urls = []
                if "assetGroups" in data:
                    for g in data["assetGroups"]:
                        if "urls" in g:
                            urls.extend(g["urls"] or [])
                        if "resources" in g and isinstance(g["resources"], dict):
                            urls.extend(g["resources"].get("files", []) or [])
                urls = [u for u in urls if isinstance(u, str) and u.endswith((".js",".mjs",".cjs"))]
                for u in urls:
                    if u.startswith("/"):
                        assets.append(f"{pr.scheme}://{pr.netloc}{u}")
                    else:
                        assets.append(urljoin(f"{pr.scheme}://{pr.netloc}/", u))
                break
        except Exception:
            continue
    return sorted(set(assets))

def download_scripts(urls: List[str], out_dir: Path, timeout_ms: int, proxy: Optional[str], beautify: bool) -> List[Path]:
    saved = []
    js_dir = out_dir / "js_all"; ensure_dir(js_dir)
    beauty_dir = out_dir / "beauty"; ensure_dir(beauty_dir)
    if requests is None:
        return saved
    sess = requests.Session()
    sess.verify = False
    if proxy:
        sess.proxies.update({"http": proxy, "https": proxy})
    for u in urls:
        try:
            r = sess.get(u, timeout=timeout_ms/1000)
            if not r.ok: continue
            b = r.content
            h = sha16_bytes(b)
            p = js_dir / f"{h}.js"
            p.write_bytes(b)
            saved.append(p)
            if beautify:
                try:
                    txt = b.decode("utf-8", errors="ignore")
                except Exception:
                    txt = ""
                bt = beautify_js(txt)
                (beauty_dir / f"{h}.beauty.js").write_text(bt, encoding="utf-8", errors="ignore")
        except Exception:
            continue
    return saved

def static_scan(paths: List[Path], base_hint: str, var_map: Dict[str,str]) -> List[Dict]:
    found: List[Dict] = []
    for p in paths:
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            try:
                txt = p.read_text(encoding="latin-1", errors="ignore")
            except Exception:
                txt = ""
        eps = extract_endpoints_from_js(txt, base_hint, var_map)
        for e in eps:
            found.append({
                "method": (e["method"] or "GET").upper(),
                "url": e["url"],
                "raw_url": e["raw_url"],
                "query_params": e["query_params"],
                "path_params": e["path_params"],
                "body_params": e["body_params"],
                "source": str(p.name),
                "evidence": e["evidence"],
            })
    return found

def make_dummy_value(name: str) -> str:
    n = (name or "").lower()
    if "email" in n: return "user@example.com"
    if n.endswith("dt") or "date" in n or "time" in n: return "2024-01-01T00:00:00Z"
    if n in {"$top","$skip","limit","offset","count","page","size"}: return "10"
    if n.endswith("id"): return "1"
    if "interval" in n: return "PT5M"
    if n in {"q","search","term"}: return "test"
    return "test"

def build_burp_http(ep: Dict, base: str, host_header: Optional[str], var_map: Optional[Dict[str,str]] = None) -> str:
    url = ep["url"]
    if var_map:
        url = substitute_vars(url, var_map)
    if not (url.startswith("http://") or url.startswith("https://")):
        url = urljoin(base, url)
    u = urlsplit(url)
    path = u.path or "/"
    # fill path placeholders roughly
    for ph in ep.get("path_params") or []:
        val = make_dummy_value(ph)
        path = path.replace("{" + ph + "}", val).replace(f":{ph}", val)
    qs_items = []
    for q in ep.get("query_params") or []:
        qs_items.append((q, make_dummy_value(q)))
    qs = urlencode(qs_items)
    if qs:
        path_q = path + ("&" if u.query else "?") + qs
    else:
        path_q = path + (("?" + u.query) if u.query else "")
    host = host_header or u.netloc
    method = ep["method"] or "GET"
    hdrs = [
        f"{method} {path_q} HTTP/1.1",
        f"Host: {host}",
        "Accept: application/json",
        "User-Agent: js-request-modeler",
        "Connection: close",
    ]
    body = ""
    if method in ("POST","PUT","PATCH"):
        payload = {k: make_dummy_value(k) for k in (ep.get("body_params") or [])}
        body = json.dumps(payload) if payload else "{}"
        hdrs.append("Content-Type: application/json")
        hdrs.append(f"Content-Length: {len(body.encode('utf-8'))}")
    req = "\r\n".join(hdrs) + "\r\n\r\n" + body
    return req

def send_probes(endpoints: List[Dict], proxy: Optional[str], headers: Dict[str,str], timeout: int, base: Optional[str]) -> List[Dict]:
    if requests is None:
        return []
    sess = requests.Session()
    sess.verify = False
    if proxy:
        sess.proxies.update({"http": proxy, "https": proxy})
    results = []
    for ep in endpoints:
        try:
            m = (ep.get("method") or "GET").upper()
            url = ep.get("url") or ""
            if not (url.startswith("http://") or url.startswith("https://")):
                if base:
                    url = urljoin(base, url)
                else:
                    continue
            data = {k: make_dummy_value(k) for k in (ep.get("body_params") or [])}
            if m in ("GET","HEAD"):
                r = sess.request(m, url, headers=headers, timeout=timeout, allow_redirects=False)
            else:
                r = sess.request(m, url, headers={"Content-Type":"application/json", **headers}, json=(data or {}), timeout=timeout, allow_redirects=False)
            results.append({
                "method": m, "url": url, "status": r.status_code,
                "resp_headers": dict(r.headers or {}),
                "body_snippet": (r.text or "")[:800]
            })
        except Exception as e:
            results.append({"method": ep.get("method"), "url": ep.get("url"), "error": e.__class__.__name__})
    return results

def main():
    import threading, os
    ap = argparse.ArgumentParser(description="Crawl + ngsw + JS indir + statik+runtime analiz ile HTTP istek modeli çıkarıcı")
    ap.add_argument("--url", required=True, help="Hedef URL (root sayfa)")
    ap.add_argument("-o","--out", required=True, help="Çıktı klasörü")
    ap.add_argument("--proxy", default="", help="Proxy (http://127.0.0.1:8080 gibi; kullanıcı:şifre gerekirse URL içinde)")
    ap.add_argument("--headers", action="append", default=[], help='Probe istekleri için header (tekrarlanabilir): "Authorization: Bearer X" veya "Cookie: name=value; ..."')
    ap.add_argument("--var", dest="vars", action="append", default=[], help="Şablon değişkeni: key=value (tekrarlanabilir). Örn: --var this.configuration.basePath=https://api.example.com")
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--wait", type=int, default=6000, help="DOMContentLoaded sonrası bekleme (ms)")
    ap.add_argument("--timeout", type=int, default=25000, help="Tarayıcı ve download timeout (ms)")
    ap.add_argument("--save-scripts", action="store_true", help="Crawl sırasında görülen JS dosyalarını kaydet")
    ap.add_argument("--no-beautify", action="store_true", help="Beautify'ı kapat (varsayılan: AÇIK)")
    ap.add_argument("--ngsw", action="store_true", help="ngsw.json indirip JS listesi ekle")
    ap.add_argument("--send", action="store_true", help="Statik analizden çıkan uçlara örnek probe istekleri gönder")
    ap.add_argument("--base", default="", help="Mutlak taban (örn: https://api.domain.com) — göreli URL'leri bununla birleştirmek için")
    ap.add_argument("--debug", action="store_true", help="Ayrıntılı log yaz")
    ap.add_argument("--max-seconds", type=int, default=300, help="Maksimum çalışma süresi; aşılırsa güvenli çıkış")
    ap.add_argument("--click-rounds", type=int, default=3, help="Otomatik tıklama tur sayısı")
    ap.add_argument("--click-max", type=int, default=120, help="Her turda en fazla tıklama")
    ap.add_argument("--goto-same-origin", action="store_true", help="Aynı origin'deki <a href> linklerine giderek daha fazla rota tetikle")
    args = ap.parse_args()

    def watchdog():
        print("[!] Max runtime exceeded, exiting...", file=sys.stderr)
        try:
            os._exit(2)
        except Exception:
            sys.exit(2)
    t = threading.Timer(max(10, args.max_seconds), watchdog); t.daemon = True; t.start()

    out_dir = Path(args.out); ensure_dir(out_dir)
    headers_dict = headers_list_to_dict(args.headers)
    var_map = parse_vars(args.vars)

    beautify_enabled = not args.no_beautify

    # 1) Crawl (runtime capture)
    scripts_runtime, net_log = crawl_and_collect(
        args.url, out_dir, proxy=(args.proxy or None),
        wait_ms=int(args.wait), timeout_ms=int(args.timeout),
        user_agent=args.user_agent, extra_headers={}, save_scripts=args.save_scripts,
        beautify=beautify_enabled, click_rounds=int(args.click_rounds),
        click_max=int(args.click_max), goto_same_origin=bool(args.goto_same_origin),
        debug=args.debug
    )

    # 2) ngsw.json
    scripts_ngsw = fetch_ngsw_list(args.url, timeout_ms=int(args.timeout)) if args.ngsw else []

    # 3) Download union
    all_scripts = sorted(set(list(scripts_runtime) + list(scripts_ngsw)))
    (out_dir / "scripts_collected.json").write_text(json.dumps(all_scripts, ensure_ascii=False, indent=2), encoding="utf-8")
    downloaded = download_scripts(all_scripts, out_dir, timeout_ms=int(args.timeout), proxy=(args.proxy or None), beautify=beautify_enabled)

    # 4) Static analysis
    base_hint = args.base or args.url
    endpoints = static_scan(downloaded, base_hint=base_hint, var_map=var_map)
    (out_dir / "endpoints_static.json").write_text(json.dumps(endpoints, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5) Runtime endpoints from net_log + runtime hooks
    runtime = []
    for e in net_log:
        if e.get("url") and (e.get("method") or e.get("phase")=="runtime"):
            m = (e.get("method") or "GET").upper()
            runtime.append({"method": m, "url": e["url"]})
    uniq_runtime = { (r["method"], r["url"]): r for r in runtime }
    (out_dir / "endpoints_runtime.json").write_text(json.dumps(list(uniq_runtime.values()), ensure_ascii=False, indent=2), encoding="utf-8")

    # 6) Merge and build Burp templates for static+runtime
    merged_map = {}
    for ep in endpoints:
        key = (ep["method"], ep["url"])
        merged_map[key] = ep
    for r in uniq_runtime.values():
        key = (r["method"], r["url"])
        if key not in merged_map:
            merged_map[key] = {"method": r["method"], "url": r["url"], "raw_url": r["url"], "query_params": [], "path_params": [], "body_params": [], "source": "runtime", "evidence": ""}
    merged = list(merged_map.values())
    (out_dir / "endpoints_merged.json").write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")

    # 7) Burp/Repeater templates
    burp_lines = []
    for ep in merged:
        u = ep["url"]
        host_header = urlparse(u).netloc or (urlparse(args.base).netloc if args.base else "")
        burp = build_burp_http(ep, base=base_hint, host_header=host_header, var_map=var_map)
        sep = "#"*70
        title = f"# {ep.get('method','GET')} {ep.get('url','')}  (src: {ep.get('source','')})"
        burp_lines.append(sep + "\n" + title + "\n" + sep + "\n" + burp + "\n")
    (out_dir / "burp_requests.txt").write_text("\n".join(burp_lines), encoding="utf-8")

    # 8) Optional send probes via proxy
    if args.send:
        probe_results = send_probes(merged, proxy=(args.proxy or None), headers=headers_dict, timeout=max(10, int(args.timeout/1000)), base=(args.base or args.url))
        (out_dir / "send_results.json").write_text(json.dumps(probe_results, ensure_ascii=False, indent=2), encoding="utf-8")

    # 9) Save net log
    with (out_dir / "network.jsonl").open("w", encoding="utf-8") as f:
        for row in net_log:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[+] Scripts collected (runtime/ngsw): {len(all_scripts)}")
    print(f"[+] Downloaded: {len(downloaded)} -> {out_dir/'js_all'}")
    print(f"[+] Static endpoints: {len(endpoints)} -> {out_dir/'endpoints_static.json'}")
    print(f"[+] Runtime endpoints: {len(uniq_runtime)} -> {out_dir/'endpoints_runtime.json'}")
    print(f"[+] Merged endpoints: {len(merged)} -> {out_dir/'endpoints_merged.json'}")
    if args.send: print(f"[+] Probe results -> {out_dir/'send_results.json'}")
    print(f"[i] Burp templates -> {out_dir/'burp_requests.txt'}")

    try:
        t.cancel()
    except Exception:
        pass

if __name__ == "__main__":
    main()
