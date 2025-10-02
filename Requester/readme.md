### Installation

- Dependencies - Python 3.8+, libnss3 / libatk-bridge2.0-0

# For Virtual Env
python3 -m venv venv && source venv/bin/activate

# Python packages used by script
pip install --upgrade pip
pip install playwright requests jsbeautifier

# Playwright browser installation
python -m playwright install chromium

### Usage
<br>
--url                    (required) root page<br>
-o, --out                output directory<br>
--proxy                  http(s) proxy (e.g., http://127.0.0.1:8080)<br>
--headers                repeatable header ("Key: Value")<br>
--user-agent             custom UA<br>
--wait                   extra wait after DOMContentLoaded (ms)<br>
--timeout                page/request timeout (ms)<br>
--save-scripts           save JS seen during crawl<br>
--no-beautify            disable beautify (default: enabled)<br>
--ngsw                   include JS from ngsw.json<br>
--send                   send probe requests to discovered endpoints<br>
--base                   base URL to resolve relative endpoints<br>
--debug                  verbose logging<br>
--max-seconds            overall runtime watchdog<br>
--click-rounds           auto-clicker rounds<br>
--click-max              max clicks per round<br>
--goto-same-origin       navigate same-origin <a href> links<br>
--var key=value          template variable (repeatable)<br>

### Usage Examples

python3 js_request_modeler_v2.py --url https://target/ -o out --proxy http://127.0.0.1:8080 --save-scripts --ngsw --base https://hostname/ --send --debug --var this.configuration.basePath=/api/v1<br>

python3 js_request_modeler_v2.py --url https://app.example.com -o out_v2 --proxy http://127.0.0.1:8080 --headers "Authorization: Bearer <token>" --headers "Cookie: sessionid=abc123; other=xyz" --save-scripts --ngsw --click-rounds 3 --click-max 200 --send --debug<br>

python3 js_request_modeler_v2.py --url https://app.example.com -o out_v2 --goto-same-origin --click-rounds 2 --click-max 120<br>

python3 js_request_modeler_v2.py --url https://app.example.com -o out_v2 --timeout 30000 --wait 8000 --max-seconds 300 --debug<br>

