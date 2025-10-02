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

--url                    (required) root page
-o, --out                output directory
--proxy                  http(s) proxy (e.g., http://127.0.0.1:8080)
--headers                repeatable header ("Key: Value")
--user-agent             custom UA
--wait                   extra wait after DOMContentLoaded (ms)
--timeout                page/request timeout (ms)
--save-scripts           save JS seen during crawl
--no-beautify            disable beautify (default: enabled)
--ngsw                   include JS from ngsw.json
--send                   send probe requests to discovered endpoints
--base                   base URL to resolve relative endpoints
--debug                  verbose logging
--max-seconds            overall runtime watchdog
--click-rounds           auto-clicker rounds
--click-max              max clicks per round
--goto-same-origin       navigate same-origin <a href> links
--var key=value          template variable (repeatable)

### Usage Examples

python3 js_request_modeler_v2.py --url https://target/ -o out --proxy http://127.0.0.1:8080 --save-scripts --ngsw --base https://hostname/ --send --debug --var this.configuration.basePath=/api/v1<br>

python3 js_request_modeler_v2.py --url https://app.example.com -o out_v2 --proxy http://127.0.0.1:8080 --headers "Authorization: Bearer <token>" --headers "Cookie: sessionid=abc123; other=xyz" --save-scripts --ngsw --click-rounds 3 --click-max 200 --send --debug<br>

python3 js_request_modeler_v2.py --url https://app.example.com -o out_v2 --goto-same-origin --click-rounds 2 --click-max 120<br>

python3 js_request_modeler_v2.py --url https://app.example.com -o out_v2 --timeout 30000 --wait 8000 --max-seconds 300 --debug<br>

