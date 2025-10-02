Simple shell script which crawls web sites and anlayzes javascript files for specific keywords such as tokens, api keys, hardcoded passwords. It utilizes httpx and hackrawler tools.

Usage: sh mass_jsscan_v2.sh <url_file> <regex_file> <output_dir>

url_file: File contains URLS that will be crawled
regex_file: File contains Regex patterns that will be used for pattern matching
output_dir: Temporary directory for downloaded script files

js-analyse.yaml - Nuclei template based on https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master/db/rules-stable.yml

Usage: nuclei -t js-analyse.yam -target javascript.js
