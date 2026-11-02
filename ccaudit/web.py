"""Local web UI: `python -m ccaudit serve`. Standard library only, bound to localhost."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import report
from .engine import SnapshotError, load_frameworks, scan, validate_snapshot
from .models import Context

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"
MAX_BODY = 20 * 1024 * 1024
INDIA = ["ap-south-1", "ap-south-2"]

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Cloud Compliance Automator</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2230;--mute:#667085;--line:#e4e7ec;--accent:#2457d6;--err:#b42318}
@media(prefers-color-scheme:dark){:root{--bg:#10131a;--card:#181c26;--ink:#e8ebf2;--mute:#98a2b3;--line:#2a3040;--accent:#7aa2ff;--err:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line);background:var(--card)}
header h1{margin:0;font-size:18px}header p{margin:2px 0 0;color:var(--mute);font-size:13px}
.layout{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:16px;align-items:start}
@media(max-width:800px){.layout{grid-template-columns:1fr}}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
label{display:block;font-weight:600;font-size:13px;margin:14px 0 4px}label:first-child{margin-top:0}
select,input[type=number],input[type=text]{width:100%;padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
.row{display:flex;gap:8px}.row>*{flex:1}.check{display:flex;gap:8px;align-items:center;font-weight:400;margin:4px 0}
.check input{width:auto}button{width:100%;margin-top:18px;padding:10px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}.mute{color:var(--mute);font-size:12px}.err{color:var(--err);font-size:13px;margin-top:10px}
iframe{width:100%;height:calc(100vh - 110px);min-height:500px;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.empty{display:grid;place-items:center;height:300px;color:var(--mute);text-align:center}
</style></head><body>
<header><h1>Cloud Compliance Automator</h1><p>ISO 27001 · SOC 2 · India DPDP Act — runs locally, nothing leaves your machine</p></header>
<div class="layout">
<form class="panel" id="f">
<label for="sample">Sample snapshot</label><select id="sample"><option value="">— choose —</option></select>
<label for="file">…or upload your own snapshot (.json)</label><input type="file" id="file" accept=".json,application/json">
<label>Frameworks</label><div id="fws"></div>
<label for="regions">Allowed regions (residency check)</label>
<select id="regions"><option value="">Off</option><option value="india" selected>India (ap-south-1, ap-south-2)</option><option value="custom">Custom list…</option></select>
<input type="text" id="custom" placeholder="eu-west-1, eu-central-1" style="display:none;margin-top:6px">
<label>Thresholds</label>
<div class="row"><div><span class="mute">Key age (days)</span><input type="number" id="keyage" value="90" min="1"></div>
<div><span class="mute">Password length</span><input type="number" id="pwlen" value="14" min="1"></div></div>
<div class="row" style="margin-top:8px"><div><span class="mute">Backup days</span><input type="number" id="bck" value="7" min="0"></div>
<div><span class="mute">Log retention</span><input type="number" id="logs" value="365" min="1"></div></div>
<button id="go" type="submit">Run scan</button><div class="err" id="err" role="alert"></div>
<p class="mute">Indicative mappings only; not legal advice or an audit opinion.</p>
</form>
<div id="out"><div class="panel empty">Choose a sample or upload a snapshot, then run the scan.</div></div>
</div>
<script>
const $=id=>document.getElementById(id);let uploaded=null;
async function init(){
 const meta=await (await fetch('/api/meta')).json();
 meta.samples.forEach(s=>{const o=document.createElement('option');o.value=s;o.textContent=s;$('sample').appendChild(o)});
 meta.frameworks.forEach(f=>{const l=document.createElement('label');l.className='check';
  l.innerHTML='<input type="checkbox" checked value="'+f.id+'"><span></span>';l.querySelector('span').textContent=f.name;$('fws').appendChild(l)});
 if(meta.samples.length){$('sample').value=meta.samples[0]}
}
$('regions').onchange=()=>{$('custom').style.display=$('regions').value==='custom'?'block':'none'};
$('file').onchange=async e=>{const f=e.target.files[0];uploaded=null;$('err').textContent='';
 if(!f)return;try{uploaded=JSON.parse(await f.text());$('sample').value=''}catch(x){$('err').textContent='That file is not valid JSON.'}};
$('sample').onchange=()=>{if($('sample').value){uploaded=null;$('file').value=''}};
$('f').onsubmit=async e=>{e.preventDefault();$('err').textContent='';
 const fws=[...document.querySelectorAll('#fws input:checked')].map(i=>i.value);
 if(!fws.length){$('err').textContent='Select at least one framework.';return}
 if(!uploaded&&!$('sample').value){$('err').textContent='Choose a sample or upload a snapshot.';return}
 let regions=null;const r=$('regions').value;
 if(r==='india')regions='india';else if(r==='custom')regions=$('custom').value;
 $('go').disabled=true;$('go').textContent='Scanning…';
 try{const res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
  sample:uploaded?null:$('sample').value,snapshot:uploaded,frameworks:fws,allowed_regions:regions,
  max_key_age:+$('keyage').value,min_password_length:+$('pwlen').value,min_backup_days:+$('bck').value,min_log_retention:+$('logs').value})});
  const data=await res.json();if(!res.ok)throw new Error(data.error||'Scan failed');
  $('out').innerHTML='<iframe id="rep" title="Compliance report"></iframe>';$('rep').srcdoc=data.html;
 }catch(x){$('err').textContent=x.message}
 $('go').disabled=false;$('go').textContent='Run scan'};
init();
</script></body></html>"""


def list_samples() -> list[str]:
    if not SAMPLES_DIR.is_dir():
        return []
    return sorted(p.name for p in SAMPLES_DIR.glob("*.json"))


def run_scan_request(body: dict) -> str:
    """Validate a scan request and return the HTML report. Raises ValueError on bad input."""
    if body.get("snapshot") is not None:
        snapshot = validate_snapshot(body["snapshot"])
        source = "uploaded snapshot"
    else:
        name = body.get("sample")
        if name not in list_samples():  # whitelist: blocks path traversal
            raise ValueError("unknown sample")
        snapshot = validate_snapshot(json.loads((SAMPLES_DIR / name).read_text(encoding="utf-8")))
        source = name

    regions = body.get("allowed_regions")
    if regions == "india":
        regions = INDIA
    elif isinstance(regions, str):
        regions = [r.strip() for r in regions.split(",") if r.strip()] or None
    elif regions is not None:
        raise ValueError("allowed_regions must be text")

    def num(key: str, default: int) -> int:
        value = body.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{key} must be a non-negative whole number")
        return value

    ctx = Context(allowed_regions=regions, max_key_age_days=num("max_key_age", 90),
                  min_password_length=num("min_password_length", 14),
                  min_backup_days=num("min_backup_days", 7),
                  min_log_retention_days=num("min_log_retention", 365))
    fws = body.get("frameworks") or None
    if fws is not None and not (isinstance(fws, list) and all(isinstance(f, str) for f in fws)):
        raise ValueError("frameworks must be a list of ids")
    results, framework_results = scan(snapshot, ctx, fws)
    meta = {"account_id": snapshot.get("account_id"), "source": source}
    return report.to_html(results, framework_results, meta)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, data: dict) -> None:
        self._send(code, json.dumps(data).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path == "/api/meta":
            fws = [{"id": f["id"], "name": f["name"]} for f in load_frameworks()]
            self._json(200, {"samples": list_samples(), "frameworks": fws})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/scan":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"error": "bad Content-Length"})
        if length <= 0 or length > MAX_BODY:
            return self._json(413, {"error": "request body missing or too large (limit 20 MB)"})
        try:
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("request must be a JSON object")
            html = run_scan_request(body)
        except (ValueError, SnapshotError) as exc:  # JSONDecodeError is a ValueError
            return self._json(400, {"error": str(exc)})
        self._json(200, {"html": html})

    def log_message(self, fmt: str, *args) -> None:  # keep the terminal quiet
        pass


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{server.server_address[1]}"
    print(f"ccaudit web UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
