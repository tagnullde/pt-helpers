#!/usr/bin/env python3
import http.server, sys, os, urllib.parse

HTML = '''<!doctype html><meta charset=utf-8><title>upload</title>
<style>
body{font:14px monospace;margin:2em;max-width:900px}
#drop{border:2px dashed #888;padding:3em;text-align:center;margin:1em 0}
#drop.over{background:#eef}
.row{display:flex;gap:1em;align-items:center;margin:.2em 0;font-size:12px}
.name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{width:200px;height:8px;background:#ddd}
.bar>div{height:100%;background:#4a8;width:0}
.ok{color:#4a8}.err{color:#c44}
</style>
<h2>upload</h2>
<div id=drop>drop files/folders, or
 <input type=file multiple id=pick>
 <input type=file multiple webkitdirectory id=pickdir>
</div>
<div>queue: <span id=q>0</span> done: <span id=d>0</span> err: <span id=e>0</span></div>
<div id=list></div>
<script>
const drop=document.getElementById('drop'),list=document.getElementById('list');
const qE=document.getElementById('q'),dE=document.getElementById('d'),eE=document.getElementById('e');
let queue=[],active=0,done=0,err=0,MAX=4;
function upd(){qE.textContent=queue.length+active;dE.textContent=done;eE.textContent=err}
function add(files){for(const f of files)queue.push(f);upd();pump()}
function pump(){while(active<MAX&&queue.length){active++;send(queue.shift()).finally(()=>{active--;upd();pump()})}upd()}
function send(f){return new Promise(res=>{
 const path=f.webkitRelativePath||f.name;
 const row=document.createElement('div');row.className='row';
 row.innerHTML=`<span class=name>${path}</span><span>${(f.size/1024).toFixed(1)}k</span><div class=bar><div></div></div><span class=status>...</span>`;
 list.prepend(row);
 const bar=row.querySelector('.bar>div'),st=row.querySelector('.status');
 const x=new XMLHttpRequest();
 x.open('PUT','/'+path.split('/').map(encodeURIComponent).join('/'));
 x.upload.onprogress=e=>{if(e.lengthComputable)bar.style.width=(e.loaded/e.total*100)+'%'};
 x.onload=()=>{if(x.status<300){bar.style.width='100%';st.textContent='ok';st.className='status ok';done++}else{st.textContent='err '+x.status;st.className='status err';err++}res()};
 x.onerror=()=>{st.textContent='err';st.className='status err';err++;res()};
 x.send(f);
})}
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');add(e.dataTransfer.files)};
document.getElementById('pick').onchange=e=>add(e.target.files);
document.getElementById('pickdir').onchange=e=>add(e.target.files);
</script>'''.encode('utf-8')

ROOT = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.getcwd()

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)
    def do_PUT(self):
        rel = urllib.parse.unquote(self.path.lstrip('/'))
        dest = os.path.abspath(os.path.join(ROOT, rel))
        if not (dest == ROOT or dest.startswith(ROOT + os.sep)):
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

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
print(f"serving on :{port}, writing to {ROOT}", file=sys.stderr)
http.server.ThreadingHTTPServer(('0.0.0.0', port), H).serve_forever()
