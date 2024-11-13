import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urlparse, parse_qs

def display_banner():
    banner = """
  __   __   _____   _____    _____   _    _   _____   _    _ 
  \ \ / /  / ____| |_   _|  / ____| | |  | | |_   _| | |  | |
   \ V /  | (___     | |   | (___   | |__| |   | |   | |__| |
    > <    \___ \    | |    \___ \  |  __  |   | |   |  __  |
   / . \   ____) |  _| |_   ____) | | |  | |  _| |_  | |  | |
  /_/ \_\ |_____/  |_____| |_____/  |_|  |_| |_____| |_|  |_|
    """
    print(banner)
    print("An XSS vulnerability detection tool")
    print("-" * 55)

# Call the banner at the start of the program
display_banner()

def test_xss(url, param, payload_file):
    try:
        with open(payload_file, 'r') as file:
            payloads = file.readlines()
        
        for payload in payloads:
            payload = payload.strip()  # Clean payload
            params = {param: payload}
            response = requests.get(url, params=params)
            
            # Check if payload is reflected directly in the response
            if payload in response.text:
                # Parse the response content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for dangerous contexts
                found_vulnerability = False
                if soup.find(string=payload):
                    if '<script>' in response.text or 'onerror=' in response.text or 'javascript:' in response.text:
                        print(f"[+] Potential XSS vulnerability with payload in a dangerous context: {payload}")
                        found_vulnerability = True
                    else:
                        # Check if payload is encoded or sanitized
                        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
                        if encoded_payload not in response.text:
                            print(f"[+] Potential XSS vulnerability with payload: {payload}")
                            found_vulnerability = True
                
                if not found_vulnerability:
                    print(f"[-] No vulnerability found with payload: {payload}")
            else:
                print(f"[-] Payload not reflected in response: {payload}")
    
    except FileNotFoundError:
        print("Payload file not found. Please check the file path and try again.")
    except Exception as e:
        print(f"An error occurred: {e}")

def extract_parameter(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    # Check if there are parameters in the query string
    if query_params:
        return list(query_params.keys())[0]  # Return the first parameter found
    elif "=" in parsed_url.query:
        # Handle cases where the parameter has no value (e.g., `?p=`)
        return parsed_url.query.split("=")[0]
    else:
        print("No parameter found in the URL.")
        return None

def main():
    parser = argparse.ArgumentParser(description="XSS Vulnerability Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL with the parameter to test for XSS vulnerabilities")
    parser.add_argument("-w", "--payload-file", required=True, help="Path to the file containing XSS payloads")
    
    args = parser.parse_args()
    
    # Extract the parameter from the URL
    param = extract_parameter(args.url)
    if param:
        test_xss(args.url, param, args.payload_file)
    else:
        print("Please provide a valid URL with a parameter (e.g., 'http://example.com/search?query=')")

if __name__ == "__main__":
    main()
