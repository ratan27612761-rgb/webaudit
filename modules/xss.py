import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class XSSScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerabilities = []
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ]

    def scan(self, forms, endpoints):
        print("\n[*] Starting XSS scan...")

        # Test GET parameters
        for endpoint in endpoints:
            url = endpoint['url']
            if '?' in url:
                print(f"  [*] Testing GET params: {url}")
                for payload in self.payloads:
                    result = self._test_get(url, payload)
                    if result:
                        self.vulnerabilities.append(result)
                        break

        # Test forms
        for form in forms:
            for payload in self.payloads:
                result = self._test_form(form, payload)
                if result:
                    self.vulnerabilities.append(result)
                    break

        print(f"  → XSS vulnerabilities found: {len(self.vulnerabilities)}")
        for v in self.vulnerabilities:
            print(f"  [!!!] {v['severity']} - {v['type']} at {v['url']}")
            print(f"        Payload  : {v['payload']}")
        return self.vulnerabilities

    def _test_get(self, url, payload):
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        for key in list(params.keys()):
            test_params = params.copy()
            test_params[key] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                response = self.session.get(test_url, timeout=5)
                if payload.lower() in response.text.lower():
                    print(f"  [!!!] XSS FOUND at {url}")
                    print(f"        Parameter: {key}")
                    print(f"        Payload  : {payload}")
                    return {
                        'type': 'Reflected XSS',
                        'url': url,
                        'parameter': key,
                        'payload': payload,
                        'evidence': 'payload reflected in response',
                        'severity': 'HIGH'
                    }
            except Exception as e:
                print(f"  [-] Error: {e}")
        return None

    def _test_form(self, form, payload):
        data = {}
        for inp in form['inputs']:
            if inp['type'] in ['text', 'search', 'email']:
                data[inp['name']] = payload
            elif inp['type'] == 'hidden':
                data[inp['name']] = inp.get('value', '')
            elif inp['name']:
                data[inp['name']] = 'test'
        try:
            if form['method'] == 'POST':
                response = self.session.post(
                    form['action'], data=data, timeout=5)
            else:
                response = self.session.get(
                    form['action'], params=data, timeout=5)
            if payload.lower() in response.text.lower():
                print(f"  [!!!] XSS FOUND at {form['action']}")
                print(f"        Payload  : {payload}")
                return {
                    'type': 'Reflected XSS',
                    'url': form['action'],
                    'payload': payload,
                    'evidence': 'payload reflected in response',
                    'severity': 'HIGH'
                }
        except Exception as e:
            print(f"  [-] Error: {e}")
        return None

    def get_results(self):
        return self.vulnerabilities
