#!/usr/bin/env python3
import http.server, sys, os, urllib.parse, html, mimetypes, json, base64, zipfile, io, re

def fmt_size(n):
    if n < 1024: return f"{n}B"
    for u in ('K','M','G','T'):
        n /= 1024
        if n < 1024: return f"{n:.1f}{u}"
    return f"{n:.1f}P"

def safe_resolve(path):
    """Resolve an absolute path. In safe mode, restrict to ROOT subtree."""
    dest = os.path.realpath(path)
    if not UNSAFE:
        if dest != ROOT and not dest.startswith(ROOT + os.sep):
            return None
    return dest

def make_zip(dest):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(dest):
            for f in files:
                path = os.path.join(root, f)
                arcname = os.path.relpath(path, dest)
                try: zf.write(path, arcname)
                except OSError: pass
    return bio.getvalue()

def make_filtered_zip(base_dir, rel_paths):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rel in rel_paths:
            full = os.path.realpath(os.path.join(base_dir, rel))
            if not UNSAFE and not (full == base_dir or full.startswith(base_dir + os.sep)):
                continue
            if not os.path.exists(full): continue
            if os.path.isdir(full):
                for root, _dirs, files in os.walk(full):
                    for f in files:
                        path = os.path.join(root, f)
                        arcname = os.path.relpath(path, base_dir)
                        try: zf.write(path, arcname)
                        except OSError: pass
            else:
                try: zf.write(full, os.path.relpath(full, base_dir))
                except OSError: pass
    return bio.getvalue()

PAGE = '''<!doctype html><meta charset=utf-8><title>webcat</title>
<style>
:root{--bg:#0f172a;--bg2:#1e293b;--fg:#f1f5f9;--fg-dim:#94a3b8;--accent:#cbd5e1;--accent-dark:#a0aec0;--success:#10b981;--error:#ef4444;--border:#334155;--border-light:#475569}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;margin:0;padding:1.2rem;max-width:1200px;margin:0 auto}
h3{margin:0.4rem 0 0.4rem;font-size:0.85rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:var(--fg-dim)}
a{color:var(--accent);text-decoration:none;transition:color 0.2s}a:hover{color:var(--accent-dark)}
#drop{display:none;border:2px dashed var(--border-light);padding:1.2rem;margin:0.8rem 0;background:rgba(99,102,241,0.03);border-radius:6px;text-align:center;cursor:pointer;transition:all 0.2s}
#drop:hover,#drop.over{border-color:var(--accent);background:rgba(99,102,241,0.06)}
#upform{margin:0.8rem 0;display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap}
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
.logo{text-align:center;font-family:ui-monospace,monospace;font-size:11px;line-height:1.25;color:var(--border-light);margin:0.4rem 0 0.8rem;user-select:none}
.logo pre{display:inline-block;text-align:left;margin:0;padding:0}
.cwd{font-size:12px;color:var(--fg-dim);font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right;flex:1}
.filesrow{display:flex;align-items:center;justify-content:space-between;gap:1rem}
</style>
<div class=logo><pre>
:::       ::: :::::::::: :::::::::   ::::::::      ::: :::::::::::
:+:       :+: :+:        :+:    :+: :+:    :+:   :+: :+:   :+:
+:+       +:+ +:+        +:+    +:+ +:+         +:+   +:+  +:+
+#+  +:+  +#+ +#++:++#   +#++:++#+  +#+        +#++:++#++: +#+
+#+ +#+#+ +#+ +#+        +#+    +#+ +#+        +#+     +#+ +#+
#+#+# #+#+#  #+#        #+#    #+# #+#    #+# #+#     #+# #+#
###   ###   ########## #########   ########  ###     ### ###
</pre></div>
<form id=upform action="__UPACTION__" method=post enctype="multipart/form-data">
<input type=file name=file multiple id=pick>
<input type=submit value=Upload id=upbtn>
</form>
<div id=drop>drop files/folders here</div>
<div id=list></div>
<h3><span class=filesrow><span class=actions>
<button onclick="createFolder()">+ Create Folder</button>
<button onclick="zipAll()" title="Zip entire directory">📦 Zip all</button>
<button id=zipsel onclick="zipSelected()" disabled title="Zip selected files">📦 Zip selected</button>
</span><span class=cwd>__TITLE__</span></span></h3>
<table id=ftable>__ROWS__</table>
<script>
var CURPATH=__CURPATH__;
var drop=document.getElementById('drop'),list=document.getElementById('list');
var queue=[],active=0,MAX=4;
function add(files){for(var i=0;i<files.length;i++)queue.push(files[i]);pump();}
function pump(){while(active<MAX&&queue.length){active++;send(queue.shift());}}
function send(f){
  var fname=f.webkitRelativePath||f.name;
  var row=document.createElement('div');row.className='row';
  row.innerHTML='<span class="name"></span><span class="sz"></span><div class="bar"><div></div></div><span class="status">...</span>';
  row.getElementsByClassName('name')[0].textContent=fname;
  row.getElementsByClassName('sz')[0].textContent=(f.size/1024).toFixed(1)+'k';
  if(list.firstChild)list.insertBefore(row,list.firstChild);else list.appendChild(row);
  var bar=row.getElementsByClassName('bar')[0].firstChild;
  var st=row.getElementsByClassName('status')[0];
  var x=new XMLHttpRequest();
  x.open('PUT','/?p='+encodeURIComponent(CURPATH+'/'+fname));
  if(x.upload){x.upload.onprogress=function(e){if(e.lengthComputable)bar.style.width=(e.loaded/e.total*100)+'%';};}
  x.onload=function(){
    if(x.status<300){bar.style.width='100%';st.textContent='ok';st.className='status ok';}
    else{st.textContent='err '+x.status;st.className='status err';}
    finish();
  };
  x.onerror=function(){st.textContent='err';st.className='status err';finish();};
  function finish(){active--;pump();if(!queue.length&&!active)setTimeout(function(){location.reload();},400);}
  x.send(f);
}
function createFolder(){
  var name=prompt('Folder name:');
  if(!name)return;
  var x=new XMLHttpRequest();
  x.open('POST','/?mkdir=1&p='+encodeURIComponent(CURPATH+'/'+name));
  x.onload=function(){if(x.status<300)location.reload();};
  x.send();
}
function zipAll(){location.href='/?zip=1&p='+encodeURIComponent(CURPATH);}
function zipSelected(){
  var boxes=document.getElementsByClassName('sel'),paths=[];
  for(var i=0;i<boxes.length;i++)if(boxes[i].checked)paths.push(boxes[i].getAttribute('data-path'));
  if(!paths.length)return;
  var x=new XMLHttpRequest();
  x.open('POST','/?zipsel=1&p='+encodeURIComponent(CURPATH));
  x.setRequestHeader('Content-Type','application/json');
  x.responseType='arraybuffer';
  x.onload=function(){
    if(x.status>=300)return;
    var blob=new Blob([x.response],{type:'application/zip'});
    if(navigator.msSaveBlob){navigator.msSaveBlob(blob,'webcat.zip');return;}
    var a=document.createElement('a');
    a.href=URL.createObjectURL(blob);a.download='webcat.zip';
    document.body.appendChild(a);a.click();document.body.removeChild(a);
  };
  x.send(JSON.stringify({files:paths}));
}
function updateZipBtn(){
  var boxes=document.getElementsByClassName('sel'),any=false;
  for(var i=0;i<boxes.length;i++){if(boxes[i].checked){any=true;break;}}
  document.getElementById('zipsel').disabled=!any;
}
var pick=document.getElementById('pick');
var upform=document.getElementById('upform');
var upbtn=document.getElementById('upbtn');
// Progressive enhancement: only wire the modern path if the File API exists.
// Without it (IE<=9) the plain multipart <form> stays as the working fallback.
if(pick&&window.FileReader&&window.XMLHttpRequest){
  if(drop)drop.style.display='block';
  if(upbtn)upbtn.style.display='none';
  pick.onchange=function(e){add((e.target||e.srcElement).files);};
  if(upform)upform.onsubmit=function(){return false;};
  if(drop){
    drop.ondragover=function(e){e.preventDefault();drop.className='over';};
    drop.ondragleave=function(){drop.className='';};
    drop.ondrop=function(e){e.preventDefault();drop.className='';if(e.dataTransfer)add(e.dataTransfer.files);};
  }
}
document.onchange=function(e){var t=(e||window.event).target||(e||window.event).srcElement;if(t&&t.className&&(''+t.className).indexOf('sel')>=0)updateZipBtn();};
</script>'''

def parse_multipart(body, boundary):
    """Parse multipart/form-data body. Returns list of (filename, data_bytes).
    Handles the old-IE quirk of sending the full local path as filename."""
    delim = b'--' + boundary
    files = []
    for part in body.split(delim):
        if not part or part == b'--' or part.startswith(b'--\r\n') or part.startswith(b'--\n'):
            continue
        if part.startswith(b'\r\n'):
            part = part[2:]
        idx = part.find(b'\r\n\r\n')
        if idx < 0:
            continue
        raw_headers = part[:idx].decode('utf-8', 'replace')
        content = part[idx + 4:]
        if content.endswith(b'\r\n'):
            content = content[:-2]
        filename = None
        for line in raw_headers.split('\r\n'):
            if line.lower().startswith('content-disposition'):
                m = re.search(r'filename="([^"]*)"', line, re.I) \
                    or re.search(r'filename=([^;\r\n]+)', line, re.I)
                if m:
                    filename = m.group(1).strip()
        if filename:
            filename = filename.replace('\\', '/').split('/')[-1]
            if filename:
                files.append((filename, content))
    return files

def nav_url(abspath):
    return '/?p=' + urllib.parse.quote(abspath, safe='')

def render(abspath):
    rows = []
    parent = os.path.dirname(abspath)
    # Show ../ unless we're at filesystem root (or safe mode at ROOT boundary)
    if abspath != parent:  # not at /
        if UNSAFE or (parent == ROOT or parent.startswith(ROOT + os.sep)):
            rows.append(f'<tr class=dir><td style="width:20px"></td><td><a href="{html.escape(nav_url(parent))}">../</a></td><td class=size></td></tr>')
    try:
        entries = sorted(os.scandir(abspath), key=lambda e: (not e.is_dir(), e.name.lower()))
    except OSError:
        entries = []
    for e in entries:
        child_abs = os.path.join(abspath, e.name)
        esc = html.escape(e.name)
        enc_nav = html.escape(nav_url(child_abs))
        enc_path = html.escape(urllib.parse.quote(e.name, safe=''))
        if e.is_dir():
            rows.append(f'<tr class=dir><td style="width:20px"><input type=checkbox class=sel data-path="{enc_path}/"></td><td><a href="{enc_nav}">{esc}/</a></td><td class=size></td></tr>')
        else:
            try: size = fmt_size(e.stat().st_size)
            except OSError: size = '?'
            rows.append(f'<tr><td style="width:20px"><input type=checkbox class=sel data-path="{enc_path}"></td><td><a href="/?dl=1&p={html.escape(urllib.parse.quote(child_abs, safe=""))}">{esc}</a></td><td class=size>{size}</td></tr>')
    body = (PAGE
        .replace('__TITLE__', html.escape(abspath))
        .replace('__UPACTION__', html.escape(nav_url(abspath)))
        .replace('__ROWS__', '\n'.join(rows))
        .replace('__CURPATH__', json.dumps(abspath)))
    return body.encode('utf-8')

# Module-level config (overridden in main())
ROOT = os.path.realpath(os.getcwd())
AUTH_USER = ''
AUTH_PASS = ''
UNSAFE = False

class H(http.server.BaseHTTPRequestHandler):
    def _err(self, code):
        self.send_response(code); self.end_headers()

    def _unauth(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="upload"')
        self.end_headers()

    def check_auth(self):
        if not AUTH_USER: return True
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Basic '): return False
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            u, p = decoded.split(':', 1)
            return u == AUTH_USER and p == AUTH_PASS
        except Exception:
            return False

    def log_message(self, fmt, *a):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    def get_path_param(self, qs):
        """Get and validate the ?p= parameter, defaulting to ROOT."""
        vals = qs.get('p', [])
        raw = vals[0] if vals else ROOT
        return safe_resolve(raw)

    def do_GET(self):
        if not self.check_auth():
            self._unauth(); return

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        # Download file
        if 'dl' in qs:
            dest = self.get_path_param(qs)
            if dest is None:
                self._err(403); return
            if not os.path.isfile(dest):
                self._err(404); return
            try:
                f = open(dest, 'rb')
            except OSError:
                self._err(403); return
            try:
                ctype, _ = mimetypes.guess_type(dest)
                fname = os.path.basename(dest)
                ascii_name = fname.encode('ascii', 'replace').decode('ascii').replace('"', '')
                self.send_response(200)
                self.send_header('Content-Type', ctype or 'application/octet-stream')
                self.send_header('Content-Disposition',
                    "attachment; filename=\"%s\"; filename*=UTF-8''%s"
                    % (ascii_name, urllib.parse.quote(fname)))
                self.send_header('Content-Length', str(os.path.getsize(dest)))
                self.end_headers()
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    try: self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError): break
            finally:
                f.close()
            return

        # Zip entire directory
        if 'zip' in qs:
            dest = self.get_path_param(qs)
            if dest is None or not os.path.isdir(dest):
                self._err(403); return
            try:
                zdata = make_zip(dest)
            except Exception:
                self._err(500); return
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(zdata)))
            self.send_header('Content-Disposition', 'attachment; filename="webcat.zip"')
            self.end_headers()
            self.wfile.write(zdata)
            return

        # Directory listing (default)
        dest = self.get_path_param(qs)
        if dest is None:
            self._err(403); return
        if not os.path.exists(dest):
            self._err(404); return
        if not os.path.isdir(dest):
            # redirect to dl
            self.send_response(302)
            self.send_header('Location', '/?dl=1&p=' + urllib.parse.quote(dest, safe=''))
            self.end_headers(); return

        body = render(dest)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        if not self.check_auth():
            self._unauth(); return

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        dest = self.get_path_param(qs)
        if dest is None:
            self._err(403); return
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
            self._unauth(); return

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        # Multipart form upload (no-JS fallback for old browsers)
        ctype_hdr = self.headers.get('Content-Type', '')
        if ctype_hdr.startswith('multipart/form-data'):
            dest_dir = self.get_path_param(qs)
            if dest_dir is None or not os.path.isdir(dest_dir):
                self._err(403); return
            m = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', ctype_hdr, re.I)
            if not m:
                self._err(400); return
            boundary = (m.group(1) or m.group(2)).strip().encode('utf-8')
            n = int(self.headers.get('Content-Length', '0'))
            body = self.rfile.read(n)
            for filename, data in parse_multipart(body, boundary):
                target = safe_resolve(os.path.join(dest_dir, filename))
                if target is None:
                    continue
                try:
                    with open(target, 'wb') as f:
                        f.write(data)
                except OSError:
                    pass
            # Redirect back to the listing so the browser shows the refreshed dir
            self.send_response(303)
            self.send_header('Location', nav_url(dest_dir))
            self.end_headers()
            return

        # Selective zip
        if 'zipsel' in qs:
            dest = self.get_path_param(qs)
            if dest is None or not os.path.isdir(dest):
                self._err(403); return
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                data = json.loads(body)
                files = data.get('files', [])
            except (ValueError, TypeError):
                files = []
            try:
                zdata = make_filtered_zip(dest, files)
            except Exception:
                self._err(500); return
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(zdata)))
            self.send_header('Content-Disposition', 'attachment; filename="webcat.zip"')
            self.end_headers()
            self.wfile.write(zdata)
            return

        # Create folder
        if 'mkdir' in qs:
            dest = self.get_path_param(qs)
            if dest is None:
                self._err(403); return
            try:
                os.makedirs(dest, exist_ok=True)
                self.send_response(201); self.end_headers()
            except OSError:
                self._err(400)
            return

        self._err(400)

def main():
    global ROOT, AUTH_USER, AUTH_PASS, UNSAFE
    port = 8000

    args = sys.argv[1:]
    positional = []
    for arg in args:
        if arg == '--unsafe':
            UNSAFE = True
        elif arg.startswith('--user='):
            AUTH_USER = arg.split('=', 1)[1]
        elif arg.startswith('--pass='):
            AUTH_PASS = arg.split('=', 1)[1]
        else:
            positional.append(arg)

    if len(positional) > 0:
        port = int(positional[0])
    if len(positional) > 1:
        ROOT = os.path.realpath(positional[1])

    if bool(AUTH_USER) != bool(AUTH_PASS):
        print("Error: both --user and --pass required together", file=sys.stderr)
        sys.exit(1)

    httpd = http.server.ThreadingHTTPServer(('0.0.0.0', port), H)
    print(f"serving on :{port}, root {ROOT}"
          + (f", auth {AUTH_USER}" if AUTH_USER else "")
          + (" [UNSAFE - no chroot]" if UNSAFE else ""), file=sys.stderr)
    httpd.serve_forever()

if __name__ == '__main__':
    main()
