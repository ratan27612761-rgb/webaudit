import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url, session=None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited = set()
        self.endpoints = []
        self.forms = []
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebAudit-Scanner/1.0'
        })
        # URLs to never visit
        self.blacklist = ['logout', 'setup.php']

    def crawl(self, url=None, depth=3):
        if depth == 0:
            return
        url = url or self.base_url
        if url in self.visited:
            return
        # Skip blacklisted URLs
        if any(b in url for b in self.blacklist):
            print(f"  [~] Skipping: {url}")
            return
        self.visited.add(url)
        try:
            response = self.session.get(url, timeout=5)
            print(f"  [+] Found: {url} ({response.status_code})")
            self.endpoints.append({
                'url': url,
                'status': response.status_code,
                'length': len(response.content)
            })
            soup = BeautifulSoup(response.text, 'html.parser')
            self._extract_forms(soup, url)
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                if self.domain in next_url and next_url not in self.visited:
                    self.crawl(next_url, depth - 1)
        except Exception as e:
            print(f"  [-] Error crawling {url}: {e}")

    def _extract_forms(self, soup, url):
        for form in soup.find_all('form'):
            inputs = []
            for inp in form.find_all(['input', 'textarea']):
                inputs.append({
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
            self.forms.append({
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': inputs
            })

    def get_results(self):
        return {
            'endpoints': self.endpoints,
            'forms': self.forms
        }
