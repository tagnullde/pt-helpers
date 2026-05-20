#!/usr/bin/env python3
import http.server, sys, os, urllib.parse, html, mimetypes, json, base64, zipfile, io

def fmt_size(n):
    if n < 1024: return f"{n}B"
    for u in ('K','M','G','T'):
        n /= 1024
        if n < 1024: return f"{n:.1f}{u}"
    return f"{n:.1f}P"

def safe_resolve(rel):
    dest = os.path.realpath(os.path.join(ROOT, rel))
    if dest == ROOT or dest.startswith(ROOT + os.sep):
        return dest
    return None

def make_zip(dest):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(dest):
            for f in files:
                path = os.path.join(root, f)
                arcname = os.path.relpath(path, dest)
                try:
                    zf.write(path, arcname)
                except OSError:
                    pass
    return bio.getvalue()

PAGE = '''<!doctype html><meta charset=utf-8><title>__TITLE__</title>
<style>
:root{--bg:#0d1117;--fg:#c9d1d9;--link:#58a6ff;--border:#30363d;--input-bg:#161b22;--drop-bg:#1a1f2a}
body{background:var(--bg);color:var(--fg);font:14px monospace;margin:2em;max-width:900px}
h2,h3{color:var(--link)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
#drop{border:2px dashed var(--border);padding:2em;text-align:center;margin:1em 0;background:var(--drop-bg);border-radius:4px}
#drop.over{background:#1f2d3a;border-color:var(--link)}
input[type=file],input[type=text]{background:var(--input-bg);color:var(--fg);border:1px solid var(--border);padding:.3em .5em;border-radius:3px}
input[type=text]{margin-right:.3em}
button{background:var(--input-bg);color:var(--fg);border:1px solid var(--border);padding:.3em .8em;border-radius:3px;cursor:pointer}
button:hover{border-color:var(--link);color:var(--link)}
.row{display:flex;gap:1em;align-items:center;margin:.2em 0;font-size:12px}
.name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{width:200px;height:8px;background:var(--input-bg);border-radius:2px}
.bar>div{height:100%;background:#238636;width:0}
.ok{color:#238636}.err{color:#f85149}
table{border-collapse:collapse;width:100%;margin-top:1em}
td{padding:.3em .6em;border-bottom:1px solid var(--border)}
td.size{text-align:right;color:#888;width:6em;white-space:nowrap}
.dir a::before{content:"[D] "}
h3{margin:1.5em 0 .5em;display:flex;justify-content:space-between;align-items:center}
.actions{font-size:12px}
.actions a,.actions button{margin-left:.8em}
</style>
<h2>__TITLE__</h2>
<div id=drop>drop files/folders, or
 <input type=file multiple id=pick>
 <input type=file multiple webkitdirectory id=pickdir>
</div>
<div>queue: <span id=q>0</span> done: <span id=d>0</span> err: <span id=e>0</span></div>
<div id=list></div>
<h3>files
 <span class=actions>
  <input type=text id=newfolder placeholder="folder name" style="width:120px">
  <button onclick="createFolder()">Create</button>
  <a href="?zip=1">📦 ZIP</a>
 </span>
</h3>
<table>__ROWS__</table>
<script>
const BASE=__BASE__;
const drop=document.getElementById('drop'),list=document.getElementById('list');
const qE=document.getElementById('q'),dE=document.getElementById('d'),eE=document.getElementById('e');
let queue=[],active=0,done=0,err=0,MAX=4;
function upd(){qE.textContent=queue.length+active;dE.textContent=done;eE.textContent=err}
function add(files){for(const f of files)queue.push(f);upd();pump()}
function pump(){while(active<MAX&&queue.length){active++;send(queue.shift()).finally(()=>{active--;upd();pump();if(!queue.length&&!active)setTimeout(()=>location.reload(),400)})}upd()}
function send(f){return new Promise(res=>{
 const path=f.webkitRelativePath||f.name;
 const row=document.createElement('div');row.className='row';
 row.innerHTML=`<span class=name>${path}</span><span>${(f.size/1024).toFixed(1)}k</span><div class=bar><div></div></div><span class=status>...</span>`;
 list.prepend(row);
 const bar=row.querySelector('.bar>div'),st=row.querySelector('.status');
 const x=new XMLHttpRequest();
 x.open('PUT',BASE+path.split('/').map(encodeURIComponent).join('/'));
 x.upload.onprogress=e=>{if(e.lengthComputable)bar.style.width=(e.loaded/e.total*100)+'%'};
 x.onload=()=>{if(x.status<300){bar.style.width='100%';st.textContent='ok';st.className='status ok';done++}else{st.textContent='err '+x.status;st.className='status err';err++};res()};
 x.onerror=()=>{st.textContent='err';st.className='status err';err++;res()};
 x.send(f);
})}
function createFolder(){
 const name=document.getElementById('newfolder').value.trim();
 if(!name)return;
 fetch(BASE+encodeURIComponent(name)+'/',{method:'POST'}).then(r=>{if(r.ok)location.reload()});
}
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');add(e.dataTransfer.files)};
document.getElementById('pick').onchange=e=>add(e.target.files);
document.getElementById('pickdir').onchange=e=>add(e.target.files);
document.getElementById('newfolder').onkeypress=e=>{if(e.key==='Enter')createFolder()};
</script>'''

def render(url_path, dest):
    rows = []
    if url_path != '/':
        rows.append('<tr class=dir><td><a href="../">../</a></td><td class=size></td></tr>')
    try:
        entries = sorted(os.scandir(dest), key=lambda e: (not e.is_dir(), e.name.lower()))
    except OSError:
        entries = []
    for e in entries:
        encoded = urllib.parse.quote(e.name)
        esc = html.escape(e.name)
        if e.is_dir():
            rows.append(f'<tr class=dir><td><a href="{encoded}/">{esc}/</a></td><td class=size></td></tr>')
        else:
            try: size = fmt_size(e.stat().st_size)
            except OSError: size = '?'
            rows.append(f'<tr><td><a href="{encoded}">{esc}</a></td><td class=size>{size}</td></tr>')
    body = (PAGE
            .replace('__TITLE__', html.escape(url_path))
            .replace('__ROWS__', '\n'.join(rows))
            .replace('__BASE__', json.dumps(url_path)))
    return body.encode('utf-8')

ROOT = os.path.realpath(sys.argv[2]) if len(sys.argv) > 2 else os.path.realpath(os.getcwd())
AUTH_USER = ''
AUTH_PASS = ''

# Parse CLI flags
for arg in sys.argv[1:]:
    if arg.startswith('--user='):
        AUTH_USER = arg.split('=', 1)[1]
    elif arg.startswith('--pass='):
        AUTH_PASS = arg.split('=', 1)[1]

if bool(AUTH_USER) != bool(AUTH_PASS):
    print("Error: both --user and --pass required together", file=sys.stderr)
    sys.exit(1)

class H(http.server.BaseHTTPRequestHandler):
    def check_auth(self):
        if not AUTH_USER: return True
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Basic '): return False
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            u, p = decoded.split(':', 1)
            return u == AUTH_USER and p == AUTH_PASS
        except:
            return False

    def log_message(self, fmt, *a):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    def do_GET(self):
        if not self.check_auth():
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="upload"')
            self.end_headers()
            return
        
        raw = self.path.split('?', 1)[0]
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        rel = urllib.parse.unquote(raw.lstrip('/'))
        dest = safe_resolve(rel)
        
        if dest is None:
            self.send_response(403); self.end_headers(); return
        if not os.path.exists(dest):
            self.send_response(404); self.end_headers(); return
        
        if os.path.isdir(dest):
            if 'zip' in qs:
                try:
                    zdata = make_zip(dest)
                except Exception as e:
                    self.send_response(500); self.end_headers(); return
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Length', str(len(zdata)))
                self.send_header('Content-Disposition', 'attachment; filename="archive.zip"')
                self.end_headers()
                self.wfile.write(zdata)
            else:
                if not raw.endswith('/'):
                    self.send_response(301)
                    self.send_header('Location', raw + '/')
                    self.end_headers(); return
                body = render(raw, dest)
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            try:
                f = open(dest, 'rb')
            except OSError:
                self.send_response(403); self.end_headers(); return
            try:
                ctype, _ = mimetypes.guess_type(dest)
                self.send_response(200)
                self.send_header('Content-Type', ctype or 'application/octet-stream')
                self.send_header('Content-Length', str(os.path.getsize(dest)))
                self.end_headers()
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    try: self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError): break
            finally:
                f.close()

    def do_PUT(self):
        if not self.check_auth():
            self.send_response(401); self.send_header('WWW-Authenticate', 'Basic realm="upload"'); self.end_headers(); return
        
        raw = self.path.split('?', 1)[0]
        rel = urllib.parse.unquote(raw.lstrip('/'))
        dest = safe_resolve(rel)
        if dest is None or dest == ROOT:
            self.send_response(403); self.end_headers(); return
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        n = int(self.headers.get('Content-Length', '0'))
        with open(dest, 'wb') as f:
            r = n
            while r > 0:
                chunk = self.rfile.read(min(65536, r))
                if not chunk: break
                f.write(chunk); r -= len(chunk)
        self.send_response(201); self.end_headers()

    def do_POST(self):
        if not self.check_auth():
            self.send_response(401); self.send_header('WWW-Authenticate', 'Basic realm="upload"'); self.end_headers(); return
        
        raw = self.path.split('?', 1)[0]
        rel = urllib.parse.unquote(raw.lstrip('/').rstrip('/'))
        dest = safe_resolve(rel)
        if dest is None:
            self.send_response(403); self.end_headers(); return
        
        try:
            os.makedirs(dest, exist_ok=True)
            self.send_response(201); self.end_headers()
        except OSError:
            self.send_response(400); self.end_headers()

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
print(f"serving on :{port}, root {ROOT}" + (f", auth {AUTH_USER}" if AUTH_USER else ""), file=sys.stderr)
http.server.ThreadingHTTPServer(('0.0.0.0', port), H).serve_forever()
