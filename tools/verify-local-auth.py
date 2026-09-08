#!/usr/bin/env python3
"""Verify a disposable local appliance's HTTPS and initial-password flow.

Uses the generated CA, never disables TLS validation, and never prints secrets.
Does not change the temporary password. Run before the first manual sign-in.
"""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
from pathlib import Path
import secrets
import ssl
import urllib.parse
import urllib.request

class Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
        self.values = {}
    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form' and values.get('id') == 'kc-form-login':
            self.action = values.get('action')
        if tag == 'input' and values.get('type') == 'hidden' and values.get('name'):
            self.values[values['name']] = values.get('value', '')

parser = argparse.ArgumentParser()
parser.add_argument('--local-dir', type=Path, required=True)
parser.add_argument('--email', required=True)
args = parser.parse_args()
receipt = json.loads((args.local_dir / 'launch-receipt.json').read_text())
origin = receipt['app_url']
ctx = ssl.create_default_context(cafile=str(args.local_dir / 'local-ca.crt'))
client = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def get(url):
    with client.open(url, timeout=30) as response:
        assert response.status == 200
        return response.read().decode()

assert 'thelve' in get(origin).lower()
configuration = json.loads(get(origin + '/api/runtime-config'))
assert configuration['authMode'] == 'oidc', configuration.keys()
with client.open(origin, timeout=30) as response:
    policy = response.headers.get('Content-Security-Policy', '')
connect = next((part.strip().split()[1:] for part in policy.split(';') if part.strip().startswith('connect-src ')), [])
api_origin = urllib.parse.urlsplit(configuration['apiBaseUrl'])
assert f'{api_origin.scheme}://{api_origin.netloc}' in connect or (api_origin.netloc == urllib.parse.urlsplit(origin).netloc and "'self'" in connect), 'Browser CSP blocks the configured API origin'

preflight = urllib.request.Request(configuration['apiBaseUrl'].rstrip('/') + '/api/v1/workspace/bootstrap', method='OPTIONS', headers={
    'Origin': origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,dpop,x-thelve-tenant'})
with client.open(preflight, timeout=30) as response:
    assert response.headers.get('Access-Control-Allow-Origin') == origin
    assert 'authorization' in response.headers.get('Access-Control-Allow-Headers', '').lower().split(','), 'CORS must explicitly allow Authorization; wildcard is insufficient'
verifier = secrets.token_urlsafe(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
query = urllib.parse.urlencode(dict(client_id='thelve-desk', redirect_uri=origin + '/auth/callback', response_type='code', scope='openid profile email', state=secrets.token_urlsafe(24), nonce=secrets.token_urlsafe(24), code_challenge=challenge, code_challenge_method='S256'))
page = get(origin + '/sso/realms/thelve/protocol/openid-connect/auth?' + query)
assert 'Welcome to Thelve' in page, 'Thelve login title missing'
assert '/thelve/css/thelve.css' in page, 'Thelve theme stylesheet missing'
styles = __import__('re').findall(r'href="([^"]*thelve.css)"', page)
assert len(styles) == 1 and 'Thelve' in get(urllib.parse.urljoin(origin, styles[0]))
form = Form()
form.feed(page)
assert form.action, 'Keycloak login form was not served'
assert urllib.parse.urlparse(form.action).netloc == urllib.parse.urlparse(origin).netloc
form.values.update(username=args.email, password=(args.local_dir / 'initial-admin-password').read_text())
with client.open(urllib.request.Request(form.action, data=urllib.parse.urlencode(form.values).encode()), timeout=30) as response:
    result = response.read().decode()
assert 'Choose your Thelve password' in result, 'Thelve password title missing'
assert '/thelve/css/thelve.css' in result, 'Thelve password theme missing'
assert 'password-new' in result, 'Temporary password did not reach the required password-change form'
print('PASS: verified HTTPS, OIDC configuration, bundled sign-in, initial credentials, and mandatory password change')
