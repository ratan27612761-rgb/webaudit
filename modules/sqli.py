import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SQLiScanner:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.vulnerabilities = []
        self.payloads = [
            "'",
            "' OR '1'='1' --",
            "' OR 1=1 --",
            "1' ORDER BY 1--",
            "' UNION SELECT NULL--",
        ]
        self.error_signatures = [
            "you have an error in your sql syntax",
            "error in your sql syntax",
            "syntax to use near",
            "mariadb server",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "mysql_fetch",
            "pg_exec",
            "sqlite_",
            "ora-",
        ]

    def scan(self, forms, endpoints):
        print("\n[*] Starting SQL Injection scan...")

        for endpoint in endpoints:
            url = endpoint['url']
            if '?' in url:
                print(f"  [*] Testing GET params: {url}")
                for payload in self.payloads:
                    result = self._test_get(url, payload)
                    if result:
                        self.vulnerabilities.append(result)
                        break

        for form in forms:
            for payload in self.payloads:
                result = self._test_form(form, payload)
                if result:
                    self.vulnerabilities.append(result)
                    break

        print(f"  → SQLi vulnerabilities found: {len(self.vulnerabilities)}")
        for v in self.vulnerabilities:
            print(f"  [!!!] {v['severity']} - {v['url']}")
            print(f"        Payload  : {v['payload']}")
            print(f"        Evidence : {v['evidence']}")
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
                body = response.text.lower()
                for sig in self.error_signatures:
                    if sig in body:
                        print(f"  [!!!] SQLi FOUND at {url}")
                        print(f"        Parameter: {key}")
                        print(f"        Payload  : {payload}")
                        return {
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': key,
                            'payload': payload,
                            'evidence': sig,
                            'severity': 'HIGH'
                        }
            except Exception as e:
                print(f"  [-] Error: {e}")
        return None

    def _test_form(self, form, payload):
        data = {}
        for inp in form['inputs']:
            if inp['type'] in ['text', 'search', 'email', 'number']:
                data[inp['name']] = payload
            elif inp['type'] == 'hidden':
                data[inp['name']] = inp.get('value', '')
            else:
                data[inp['name']] = 'test'
        try:
            if form['method'] == 'POST':
                response = self.session.post(
                    form['action'], data=data, timeout=5)
            else:
                response = self.session.get(
                    form['action'], params=data, timeout=5)
            body = response.text.lower()
            for sig in self.error_signatures:
                if sig in body:
                    print(f"  [!!!] SQLi FOUND at {form['action']}")
                    print(f"        Payload  : {payload}")
                    return {
                        'type': 'SQL Injection',
                        'url': form['action'],
                        'payload': payload,
                        'evidence': sig,
                        'severity': 'HIGH'
                    }
        except Exception as e:
            print(f"  [-] Error: {e}")
        return None

    def get_results(self):
        return self.vulnerabilities
