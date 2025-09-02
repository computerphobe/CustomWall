import re
from flask import Flask, request, Response
import requests
import threading
import urllib.parse


# WAF Configuration & Engine Rules
WAF_RULES = {
    "SQL injection": re.compile(
        r"(?i)(\b(select|union|insert|update|delete|drop|alter|create|exec|execute)\b|\b(or|and)\b\s+\d+=\d+|--|;|'|\")",
        re.IGNORECASE
    ),
    "XSS": re.compile(
        r"(?i)(<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>)",
        re.IGNORECASE
    ),
    "CSRF": re.compile(
        r"(?i)(<form\b[^<]*(?:(?!<\/form>)<[^<]*)*<\/form>)",
        re.IGNORECASE
    )
}

BACKEND_SERVER_URL = "http://127.0.0.1:8081"

def check_request_for_threat(req):
    for param_name, param_value in req.args.items():
        decoded_value = urllib.parse.unquote_plus(param_value)
        for rule_name, pattern in WAF_RULES.items():
            if pattern.search(decoded_value):
                print(f"[-] WAF: Blocked request. Threat detected in query parameter '{param_name}': {decoded_value}")
                return False, rule_name
            
    if req.data:
        try:
            body_str = req.data.decode('utf-8', errors='ignore')
            decoded_body = urllib.parse.unquote_plus(body_str)
            for rule_name, pattern in WAF_RULES.items():
                if pattern.search(decoded_body):
                    print(f"[-] WAF: Blocked request. Threat detected in request body: {decoded_body}")
                    return False, rule_name
        except Exception as e:
            print(f"[-] WAF: Could not process request body: Error: {e}")

    # If no threats were detected
    return True, None


backend_app = Flask('backend')

@backend_app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@backend_app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def backend_server(path):
    """
    This represents the actual application server. It simply acknowledges
    that it received a request.
    """
    return f"""
    <h1>Backend Server Reached!</h1>
    <p>This is the protected application. Your request was deemed safe by the WAF.</p>
    <p>Path: /{path}</p>
    """, 200

def run_backend_app():
    print("[+] Starting Backend Application Server on http://127.0.0.1:8081")
    # Note: We use '127.0.0.1' to ensure it's only accessible locally by the WAF.
    backend_app.run(host='127.0.0.1', port=8081)


# --- 3. The WAF Reverse Proxy Server ---

# This is the main WAF application. It listens on port 8080, inspects traffic,
# and forwards safe requests to the backend server. This is the only server
# that should be exposed to the public internet.
waf_app = Flask('waf')

@waf_app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@waf_app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def waf_proxy(path):
    """
    This function is the core of the WAF. It intercepts all incoming requests.
    """
    print(f"\n[+] WAF: Intercepted request for path: /{path}")
    
    # 1. Analyze the request
    is_safe, rule_violated = check_request_for_threat(request)

    # 2. Block or Forward
    if not is_safe:
        # If a threat is detected, return a 403 Forbidden error.
        return f"<h1>403 Forbidden</h1><p>Your request was blocked by the WAF. Reason: {rule_violated}</p>", 403
    
    # 3. If safe, forward the request to the backend.
    print("[+] WAF: Request is clean. Forwarding to backend application...")
    try:
        # Reconstruct the request to send to the backend
        backend_response = requests.request(
            method=request.method,
            url=f"{BACKEND_SERVER_URL}/{path}",
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            params=request.args
        )
        
        # Create a Flask response from the backend's response to send back to the client
        # This includes headers, content, and status code.
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in backend_response.raw.headers.items()
                   if name.lower() not in excluded_headers]

        response = Response(backend_response.content, backend_response.status_code, headers)
        return response

    except requests.exceptions.RequestException as e:
        print(f"[-] WAF: Could not connect to backend server. Error: {e}")
        return "<h1>503 Service Unavailable</h1><p>Could not connect to the backend application.</p>", 503

# --- Main execution block ---
if __name__ == '__main__':
    # We use threading to run both the backend app and the WAF proxy simultaneously.
    
    # Start the backend server in a separate thread.
    # The 'daemon=True' flag means the thread will exit when the main script exits.
    backend_thread = threading.Thread(target=run_backend_app)
    backend_thread.daemon = True
    backend_thread.start()

    # Start the WAF server in the main thread.
    print("[+] Starting WAF Reverse Proxy on http://0.0.0.0:8080")
    print("[!] All traffic should be sent to the WAF on port 8080.")
    # The WAF listens on '0.0.0.0' to be accessible from outside its container/machine.
    waf_app.run(host='0.0.0.0', port=8080)