# XSSIGHT

XSSIGHT is an XSS vulnerability detection tool that helps identify potential cross-site scripting vulnerabilities in web applications by testing query parameters with various payloads.

## Features
- Injects XSS payloads into query parameters to test for reflected XSS.
- Analyzes dangerous HTML contexts to find potential vulnerabilities.
## Requirements
- Python 3.x
- beautifulsoup4 library
## Usage

```bash
pip install beautifulsoup4
python xssight.py -u "https://example.com/search?query=" -w "/path/to/payloads.txt"
python xssight.py -h 
