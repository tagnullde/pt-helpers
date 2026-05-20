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

def make_filtered_zip(base_dir, rel_paths):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rel in rel_paths:
            full = os.path.realpath(os.path.join(base_dir, rel))
            if not (full == base_dir or full.startswith(base_dir + os.sep)): continue
            if not os.path.exists(full): continue
            if os.path.isdir(full):
                for root, dirs, files in os.walk(full):
                    for f in files:
                        path = os.path.join(root, f)
                        arcname = os.path.relpath(path, base_dir)
                        try: zf.write(path, arcname)
                        except OSError: pass
            else:
                try: zf.write(full, os.path.relpath(full, base_dir))
                except OSError: pass
    return bio.getvalue()

PAGE = '''<!doctype html><meta charset=utf-8><title>__TITLE__</title>
<style>
:root{--bg:#0f172a;--bg2:#1e293b;--fg:#f1f5f9;--fg-dim:#94a3b8;--accent:#cbd5e1;--accent-dark:#a0aec0;--success:#10b981;--error:#ef4444;--border:#334155;--border-light:#475569}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;margin:0;padding:1.2rem;max-width:1200px;margin:0 auto}
h2{margin:0 0 0.8rem;font-size:1.6rem;font-weight:600;color:var(--accent)}
h3{margin:0.8rem 0 0.6rem;font-size:0.85rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--fg-dim)}
a{color:var(--accent);text-decoration:none;transition:color 0.2s}a:hover{color:var(--accent-dark)}
#drop{border:2px dashed var(--border-light);padding:1.2rem;margin:0.8rem 0;background:rgba(99,102,241,0.03);border-radius:6px;text-align:center;cursor:pointer;transition:all 0.2s}
#drop:hover,#drop.over{border-color:var(--accent);background:rgba(99,102,241,0.06)}
input[type=file],input[type=text]{background:var(--bg2);color:var(--fg);border:1px solid var(--border);padding:0.4rem 0.6rem;border-radius:4px;font-size:13px;transition:border-color 0.2s}
input[type=file]:focus,input[type=text]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(99,102,241,0.1)}
button{background:var(--bg2);color:var(--accent);border:1px solid var(--border-light);padding:0.4rem 0.8rem;border-radius:4px;cursor:pointer;font-weight:500;font-size:13px;transition:all 0.2s}
button:hover{border-color:var(--accent);background:rgba(99,102,241,0.08)}
button:disabled{opacity:0.4;cursor:not-allowed}
.row{display:flex;gap:0.8rem;align-items:center;margin:0.1rem 0;font-size:12px;padding:0.2rem 0}
.name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,monospace}
.bar{width:100px;height:4px;background:var(--bg2);border-radius:2px;overflow:hidden}
.bar>div{height:100%;background:linear-gradient(90deg,var(--accent),var(--success));width:0;transition:width 0.1s}
.ok{color:var(--success)}.err{color:var(--error)}
table{border-collapse:collapse;width:100%;margin-top:0.6rem;font-size:13px}
tbody tr:hover{background:rgba(99,102,241,0.02)}
td{padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)}
td.size{text-align:right;color:var(--fg-dim);width:4.5rem;font-family:ui-monospace,monospace;font-size:12px}
.dir a::before{content:"📁 "}
.actions{display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;font-size:13px}
.stats{font-size:12px;color:var(--fg-dim);margin:0.6rem 0}
.stats strong{color:var(--accent)}
</style>
<h2>__TITLE__</h2>
<div id=drop>drop files/folders, or <input type=file multiple id=pick></div>
<div class=stats>queue: <strong id=q>0</strong> | done: <strong id=d>0</strong> | err: <strong id=e>0</strong></div>
<div id=list></div>
<h3>files <span class=actions>
  <button onclick="createFolder()">+ Create Folder</button>
  <button onclick="zipAll()" title="Zip entire directory">📦 Zip all</button>
  <button id=zipsel onclick="zipSelected()" disabled title="Zip selected files">📦 Zip selected</button>
 </span>
</h3>
<table id=ftable>__ROWS__</table>
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
 const name=prompt("Folder name:");
 if(!name)return;
 fetch(BASE+encodeURIComponent(name)+'/',{method:'POST'}).then(r=>{if(r.ok)location.reload()});
}
function zipAll(){
 location.href='?zip=1';
}
function zipSelected(){
 const paths=Array.from(document.querySelectorAll('.sel:checked')).map(cb=>cb.dataset.path);
 if(!paths.length)return;
 fetch(BASE+'?zip=1',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({files:paths})}).then(r=>r.blob()).then(blob=>{const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='archive.zip';a.click()});
}
function updateZipBtn(){
 document.getElementById('zipsel').disabled=!document.querySelector('.sel:checked');
}
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');add(e.dataTransfer.files)};
document.getElementById('pick').onchange=e=>add(e.target.files);
document.addEventListener('change',e=>{if(e.target.classList.contains('sel'))updateZipBtn()});
</script>'''

def render(url_path, dest):
    rows = []
    if url_path != '/':
        rows.append('<tr class=dir><td style="width:20px"></td><td><a href="../">../</a></td><td class=size></td></tr>')
    try:
        entries = sorted(os.scandir(dest), key=lambda e: (not e.is_dir(), e.name.lower()))
    except OSError:
        entries = []
    for e in entries:
        encoded = urllib.parse.quote(e.name)
        esc = html.escape(e.name)
        if e.is_dir():
            rows.append(f'<tr class=dir><td style="width:20px"><input type=checkbox class=sel data-path="{encoded}/"></td><td><a href="{encoded}/">{esc}/</a></td><td class=size></td></tr>')
        else:
            try: size = fmt_size(e.stat().st_size)
            except OSError: size = '?'
            rows.append(f'<tr><td style="width:20px"><input type=checkbox class=sel data-path="{encoded}"></td><td><a href="{encoded}">{esc}</a></td><td class=size>{size}</td></tr>')
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
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if 'zip' in qs:
            # Selective ZIP download
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body)
                files = data.get('files', [])
            except:
                files = []

            rel = urllib.parse.unquote(raw.lstrip('/').rstrip('/'))
            dest = safe_resolve(rel)
            if dest is None:
                self.send_response(403); self.end_headers(); return

            try:
                zdata = make_filtered_zip(dest, files)
            except:
                self.send_response(500); self.end_headers(); return
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(zdata)))
            self.send_header('Content-Disposition', 'attachment; filename="archive.zip"')
            self.end_headers()
            self.wfile.write(zdata)
        else:
            # Create folder
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
