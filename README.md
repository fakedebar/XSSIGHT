# XSSIGHT

XSSIGHT is an XSS vulnerability detection tool that helps identify potential cross-site scripting vulnerabilities in web applications by testing query parameters with various payloads.

## Features
- Injects XSS payloads into query parameters to test for reflected XSS.
- Analyzes dangerous HTML contexts to find potential vulnerabilities.

## Usage

```bash
python xss.py -u "https://example.com/search?query=" -w "/path/to/payloads.txt"
