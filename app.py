# flask_file_integrity_enhanced.py
from flask import Flask, request, jsonify, render_template_string, send_file
import hashlib
import json
import os
import io
import csv
from datetime import datetime

app = Flask(__name__)
HASH_FILE = "hashes.json"

# ---------- Hash helper ----------
def calculate_hash_fileobj(fileobj, algorithm="sha256"):
    if algorithm == "md5":
        hasher = hashlib.md5()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    else:
        hasher = hashlib.sha256()

    try:
        fileobj.seek(0)
    except Exception:
        pass

    while True:
        chunk = fileobj.read(4096)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        hasher.update(chunk)

    try:
        fileobj.seek(0)
    except Exception:
        pass

    return hasher.hexdigest()

# ---------- Enhanced UI (embedded) ----------
INDEX_HTML = r"""
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>File Integrity Checker</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
  :root { --drop-border: #6c757d; --accent: #0d6efd; }
  body.dark-mode { background:#121212; color:#e6eef8; }
  .drop-area { border: 2px dashed var(--drop-border); padding: 20px; border-radius: 8px; text-align:center; cursor:pointer; transition: background .12s, border-color .12s; }
  .drop-area.dragover { background: rgba(13,110,253,0.04); border-color: var(--accent); }
  .file-row { display:flex; justify-content:space-between; gap:12px; align-items:center; padding:6px 0; border-bottom:1px solid #eee; }
  .badge-status { min-width:100px; }
  .dark-mode .table { color:#eee; }
  .progress { height:16px; }
  code { word-break:break-word; }
  .file-meta { font-size:.9rem; color:#6c757d; }
  body.dark-mode .file-meta { color: rgba(255,255,255,0.6); }
  .small-muted { font-size:.85rem; color:#6c757d; }
  body.dark-mode .small-muted { color: rgba(255,255,255,0.6); }
</style>
</head>
<body class='p-4' id='pageBody'>
<div class='container'>
  <div class='d-flex justify-content-between align-items-center mb-3'>
    <h1 class='h4 mb-0'>🔐 File Integrity Checker</h1>
  </div>

  <div class='row g-3'>
    <div class='col-md-4'>
      <label class='form-label'>Algorithm</label>
      <select id='algorithm' class='form-select mb-3'>
        <option value='md5'>MD5</option>
        <option value='sha1'>SHA1</option>
        <option value='sha256' selected>SHA256</option>
      </select>

      <div id='dropArea' class='drop-area mb-2'>
        <div id='dropText'>Drag & drop files here or click to select</div>
        <input id='fileInput' type='file' multiple style='display:none'>
      </div>

      <div id='fileList' class='mb-3 small-muted'>No files selected</div>

      <div class='d-flex gap-2'>
        <button id='saveBtn' class='btn btn-primary flex-fill'>Save File Hashes</button>
        <button id='checkBtn' class='btn btn-success flex-fill'>Check File Integrity</button>
      </div>
      <div class='d-flex gap-2 mt-2'>
        <button id='resetBtn' class='btn btn-warning flex-fill'>Reset Baseline</button>
        <button id='exportBtn' class='btn btn-outline-secondary flex-fill'>Export CSV</button>
      </div>

      <div class='mt-3'>
        <div class='small-muted' id='lastAction'>No actions yet.</div>
        <div class='mt-2'>
          <div class='progress' style='display:none' id='uploadProgress'>
            <div id='uploadBar' class='progress-bar' role='progressbar' style='width:0%'>0%</div>
          </div>
        </div>
      </div>
    </div>

    <div class='col-md-8'>
      <h6>Results</h6>
      <div class='table-responsive'>
        <table id='resultsTable' class='table table-striped'>
          <thead><tr><th>Filename</th><th>Status</th><th>Hash</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
const fileInput = document.getElementById('fileInput');
const dropArea = document.getElementById('dropArea');
const fileList = document.getElementById('fileList');
const saveBtn = document.getElementById('saveBtn');
const checkBtn = document.getElementById('checkBtn');
const resetBtn = document.getElementById('resetBtn');
const exportBtn = document.getElementById('exportBtn');
const algoSelect = document.getElementById('algorithm');
const resultsTableBody = document.querySelector('#resultsTable tbody');
const lastAction = document.getElementById('lastAction');
const uploadProgress = document.getElementById('uploadProgress');
const uploadBar = document.getElementById('uploadBar');
const pageBody = document.getElementById('pageBody');

let selectedFiles = [];


dropArea.addEventListener('click', ()=>fileInput.click());
fileInput.addEventListener('change', (e)=>handleFiles(e.target.files));

// drag events
['dragenter','dragover'].forEach(evt=>{
  dropArea.addEventListener(evt, (e)=>{ e.preventDefault(); e.stopPropagation(); dropArea.classList.add('dragover'); });
});
['dragleave','drop'].forEach(evt=>{
  dropArea.addEventListener(evt, (e)=>{ e.preventDefault(); e.stopPropagation(); dropArea.classList.remove('dragover'); });
});
dropArea.addEventListener('drop', (e)=>{
  const dt = e.dataTransfer; if(dt && dt.files) handleFiles(dt.files);
});

function handleFiles(fileListObj){
  selectedFiles = Array.from(fileListObj);
  renderFileList();
}

function renderFileList(){
  if(!selectedFiles.length){ fileList.innerHTML='<div class="text-muted">No files selected</div>'; return }
  fileList.innerHTML='';
  for(const f of selectedFiles){
    const row = document.createElement('div'); row.className='file-row';
    const left = document.createElement('div'); left.innerHTML=`<strong>${f.name}</strong><div class='file-meta'>${(f.size/1024).toFixed(1)} KB</div>`;
    const right = document.createElement('div');
    const removeBtn = document.createElement('button'); removeBtn.className='btn btn-sm btn-outline-danger'; removeBtn.textContent='Remove';
    removeBtn.onclick = ()=>{ selectedFiles = selectedFiles.filter(x=>x!==f); renderFileList(); }
    right.appendChild(removeBtn);
    row.appendChild(left); row.appendChild(right);
    fileList.appendChild(row);
  }
}

function setProgress(percent){ uploadProgress.style.display = percent>=0 && percent<100 ? 'block' : 'none'; uploadBar.style.width = percent+'%'; uploadBar.textContent = percent+'%'; }

function xhrUpload(url){
  return new Promise((resolve, reject)=>{
    if(!selectedFiles.length) return reject({error:'No files selected'});
    const form = new FormData();
    for(const f of selectedFiles) form.append('files', f);
    form.append('algorithm', algoSelect.value);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    xhr.upload.onprogress = (e)=>{ if(e.lengthComputable) setProgress(Math.round(e.loaded / e.total * 100)); };
    xhr.onload = ()=>{
      setProgress(100);
      try{ const data = JSON.parse(xhr.responseText); if(xhr.status>=200 && xhr.status<300) resolve(data); else reject(data); }catch(err){ reject({error:'Invalid response'}); }
    };
    xhr.onerror = ()=>reject({error:'Network error'});
    xhr.send(form);
  });
}

saveBtn.onclick = async ()=>{
  try{
    lastAction.textContent = 'Saving hashes...';
    setProgress(0);
    const res = await xhrUpload('/save_hashes');
    alert(res.message || 'Saved');
    lastAction.textContent = 'Saved baseline at ' + new Date().toLocaleString();
    setProgress(-1);
  }catch(err){
    alert(err.error || JSON.stringify(err));
    setProgress(-1);
    lastAction.textContent = 'Save failed';
  }
};

checkBtn.onclick = async ()=>{
  try{
    lastAction.textContent = 'Checking integrity...'; setProgress(0);
    const res = await xhrUpload('/check_integrity');
    if(res.results){
      resultsTableBody.innerHTML='';
      for(const row of res.results){
        const tr = document.createElement('tr');
        const statusBadge = row.status === 'Unchanged' ? '<span class="badge bg-success badge-status">Unchanged</span>' : row.status==='Modified' ? '<span class="badge bg-warning text-dark badge-status">Modified</span>' : '<span class="badge bg-primary badge-status">New File</span>';
        tr.innerHTML = `<td>${row.filename}</td><td>${statusBadge}</td><td><code style='word-break:break-all'>${row.hash}</code></td>`;
        resultsTableBody.appendChild(tr);
      }
    }
    lastAction.textContent = 'Checked at ' + new Date().toLocaleString(); setProgress(-1);
  }catch(err){
    alert(err.error || JSON.stringify(err)); setProgress(-1); lastAction.textContent = 'Check failed';
  }
};

resetBtn.onclick = async ()=>{
  if(!confirm('Delete saved baseline?')) return;
  const res = await fetch('/reset', { method:'POST' });
  const data = await res.json();
  alert(data.message || data.error);
  lastAction.textContent = data.message || 'Reset';
};

exportBtn.onclick = async ()=>{
  const rows=[];
  for(const tr of resultsTableBody.querySelectorAll('tr')){ const tds = tr.querySelectorAll('td'); rows.push({filename:tds[0].textContent, status: tds[1].innerText.trim(), hash: tds[2].textContent.trim()}); }
  if(!rows.length) return alert('No results to export');
  try{
    const res = await fetch('/export_csv',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({rows}) });
    if(!res.ok){ const t = await res.text(); throw new Error(t || 'Export failed'); }
    const blob = await res.blob(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'integrity_results_' + new Date().toISOString().replace(/[:.]/g,'-') + '.csv'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }catch(e){ alert(e.message || 'Export failed'); }
};

// initialize
renderFileList();
</script>
</body>
</html>
"""

# ---------- API endpoints ----------
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/save_hashes", methods=["POST"])
def save_hashes():
    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400
    files = request.files.getlist("files")
    algorithm = request.form.get("algorithm", "sha256")

    hashes = {}
    for f in files:
        filename = f.filename or "unnamed"
        file_hash = calculate_hash_fileobj(f.stream if hasattr(f, "stream") else f, algorithm)
        hashes[filename] = file_hash

    doc = {"algorithm": algorithm, "saved_at": datetime.utcnow().isoformat() + "Z", "hashes": hashes}
    with open(HASH_FILE, "w") as fh:
        json.dump(doc, fh, indent=4)

    return jsonify({"message": f"File hashes saved successfully using {algorithm.upper()}."})

@app.route("/check_integrity", methods=["POST"])
def check_integrity():
    if not os.path.exists(HASH_FILE):
        return jsonify({"error": "No hash file found. Please save hashes first."}), 400
    try:
        with open(HASH_FILE, "r") as fh:
            data = json.load(fh)
    except Exception:
        return jsonify({"error": "Unable to read hash file."}), 500

    old_hashes = data.get("hashes", {})
    algorithm = request.form.get("algorithm", data.get("algorithm", "sha256"))

    if "files" not in request.files:
        return jsonify({"error": "No files provided"}), 400
    files = request.files.getlist("files")

    results = []
    for f in files:
        filename = f.filename or "unnamed"
        new_hash = calculate_hash_fileobj(f.stream if hasattr(f, "stream") else f, algorithm)
        old_hash = old_hashes.get(filename)

        if not old_hash:
            status = "New File"
        elif new_hash != old_hash:
            status = "Modified"
        else:
            status = "Unchanged"

        results.append({"filename": filename, "status": status, "hash": new_hash})

    return jsonify({"results": results})

@app.route("/reset", methods=["POST"])
def reset():
    if os.path.exists(HASH_FILE):
        os.remove(HASH_FILE)
        return jsonify({"message": "Hash file deleted successfully."})
    return jsonify({"message": "No hash file to delete."})

@app.route("/export_csv", methods=["POST"])
def export_csv():
    data = request.get_json(silent=True)
    if not data or "rows" not in data:
        return jsonify({"error": "No rows provided"}), 400

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Filename", "Status", "Hash"])
    for r in data["rows"]:
        writer.writerow([r.get("filename", ""), r.get("status", ""), r.get("hash", "")])
    buf.seek(0)

    mem = io.BytesIO()
    mem.write(buf.getvalue().encode("utf-8"))
    mem.seek(0)

    filename = f"integrity_results_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
