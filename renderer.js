const { ipcRenderer } = require('electron');
const { spawn }     = require('child_process');
const path          = require('path');
const extractFileIcon = require('extract-file-icon');

const dropZone      = document.getElementById('drop-zone');
const fileCountElem = document.getElementById('file-count');
const fileListElem  = document.getElementById('file-list');
const deselectBtn   = document.getElementById('deselect-btn');
const analyzeBtn    = document.getElementById('analyze-btn');
const loading       = document.getElementById('loading');
const resultsDiv    = document.getElementById('results');

const defaultIcon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0...'; // same as before

const toast = document.getElementById('toast');
function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add('show');
}
function hideToast() {
  toast.classList.remove('show');
}


// Theme toggle
const themeToggle = document.getElementById('theme-toggle');
// Load saved theme or default to light
const savedTheme = localStorage.getItem('theme') || 'light';
document.documentElement.setAttribute('data-theme', savedTheme);
themeToggle.textContent = savedTheme === 'light' ? '🌙' : '☀️';

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  themeToggle.textContent = next === 'light' ? '🌙' : '☀️';
});

let filesList = [];

// Extract or fallback icon
function getIcon(p) {
  try {
    const buf = extractFileIcon(p, 32);
    if (buf && buf.length) return 'data:image/png;base64,' + buf.toString('base64');
  } catch (e) { console.error('Icon error', e); }
  return defaultIcon;
}

function updateFilesDisplay() {
  fileCountElem.textContent = filesList.length
    ? `${filesList.length} file${filesList.length>1?'s':''} chosen`
    : 'No files chosen';
  fileListElem.innerHTML = '';
  filesList.forEach((f,i) => {
    const e = document.createElement('div'); e.classList.add('file-entry');
    const rm = document.createElement('span'); rm.textContent='✖'; rm.classList.add('remove-btn');
    rm.onclick = ()=>{ filesList.splice(i,1); updateFilesDisplay(); };
    e.appendChild(rm);
    const img = document.createElement('img'); img.src = f.icon; e.appendChild(img);
    const nm = document.createElement('span'); nm.textContent = f.name; e.appendChild(nm);
    fileListElem.appendChild(e);
  });
}

// Called when you have an array of full paths
function addPaths(paths) {
  paths.forEach(p => {
    const name = path.basename(p);
    filesList.push({ path: p, name, icon: getIcon(p) });
  });
  updateFilesDisplay();
}

// Drag & drop
dropZone.addEventListener('dragover', e=>{ e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', e=>{ e.preventDefault(); dropZone.classList.remove('dragover'); });
dropZone.addEventListener('drop', e=> {
  e.preventDefault(); dropZone.classList.remove('dragover');
  const paths = Array.from(e.dataTransfer.files)
                     .map(f=>f.path)
                     .filter(Boolean);
  if (paths.length) addPaths(paths);
});

// Click => native file dialog
dropZone.addEventListener('click', async () => {
  const paths = await ipcRenderer.invoke('open-file-dialog');
  if (paths.length) addPaths(paths);
});

// Deselect all
deselectBtn.addEventListener('click', () => {
  filesList = [];
  updateFilesDisplay();
});

// Analyze with single Python process + progress
analyzeBtn.addEventListener('click', () => {
  if (!filesList.length) return alert('Add files first!');
  resultsDiv.innerHTML = '';

  const startTime = performance.now(); // ⏱️ Start timer

  showToast(`Analyzing files 0/${filesList.length}, please wait…`);

  //const py = spawn('python', ['analyze.py']);
  //const py = spawn(path.join(__dirname, 'analyze.exe'));
  const exePath = process.env.NODE_ENV === 'development'
  ? path.join(__dirname, 'analyze.exe')
  : path.join(path.dirname(process.execPath), 'analyze.exe');

  const py = spawn(exePath);




  const inputPayload = filesList.map(f => ({ path: f.path, name: f.name }));
  py.stdin.write(JSON.stringify(inputPayload));
  py.stdin.end();

  let buffer = '';
  let analyzedCount = 0;

  py.stdout.on('data', chunk => {
    buffer += chunk.toString();
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);

      if (line.startsWith('PROGRESS')) {
        const [_, cur, tot] = line.match(/^PROGRESS (\d+)\/(\d+)/);
        showToast(`Analyzing files ${cur}/${filesList.length}, please wait…`);

      } else if (line.startsWith('DONE')) {
        const [_, cur, tot] = line.match(/^DONE (\d+)\/(\d+)/);
        analyzedCount = parseInt(cur);

        const endTime = performance.now(); // ⏱️ Stop timer
        const elapsed = ((endTime - startTime) / 1000).toFixed(2);
        console.log(`[DEBUG] Analyzed ${analyzedCount} file(s) in ${elapsed} seconds`);
        showToast(`Analysis complete! ${analyzedCount}/${filesList.length}`);
        setTimeout(hideToast, 3000);

      } else if (line.startsWith('{')) {
        try {
          const obj = JSON.parse(line);
          const [name, result] = Object.entries(obj)[0];
          displaySingleResult(name, result);
        } catch (e) {
          console.error('JSON parse error', e, line);
        }
      }
    }
  });

  py.stderr.on('data', data => console.error('py err', data.toString()));
});




function displaySingleResult(name, r) {
  // Find the file entry in filesList
  const file = filesList.find(f => f.name === name);
  if (!file) return;

  // Container for this result
  const entry = document.createElement('div');
  entry.classList.add('result-entry');

  // Icon
  const img = document.createElement('img');
  img.src = file.icon;
  entry.appendChild(img);

  // Content wrapper
  const content = document.createElement('div');
  content.classList.add('result-content');

  // Title
  const title = document.createElement('h3');
  title.textContent = name;
  content.appendChild(title);

  // Info‐table helper
  const infoTable = document.createElement('table');
  infoTable.classList.add('info-table');
  function addRow(key, val) {
    const tr = document.createElement('tr');
    const tdK = document.createElement('td');
    tdK.classList.add('info-key');
    tdK.textContent = key;
    const tdV = document.createElement('td');
    tdV.classList.add('info-val');
    if (val instanceof Node) tdV.appendChild(val);
    else tdV.textContent = val != null ? val : '';
    tr.append(tdK, tdV);
    infoTable.appendChild(tr);
  }

  // Common fields
  addRow('File Path',   r.file_path);
  addRow('Description', r.description);
  addRow('MIME',        r.mime);
  addRow('Type',        r.type);

  content.appendChild(infoTable);

  // Type‐specific
  try {
    if (r.type === 'pe') {
      const hdr = r.pe_header || {};

      addRow('Architecture',      hdr.architecture);
      addRow('File Size (bytes)', hdr.file_size_bytes);

      // General entropy
      const ge = document.createElement('span');
      ge.textContent = hdr.general_entropy;
      ge.style.color = entropyColor(hdr.general_entropy);
      addRow('General Entropy', ge);

      addRow('Number of Sections', hdr.number_of_sections);
      addRow('Compilation Date',    hdr.compilation_date);

      // Sections
      const secTitle = document.createElement('h4');
      secTitle.textContent = 'Sections';
      content.appendChild(secTitle);

      const secTable = document.createElement('table');
      secTable.classList.add('sections-table');
      secTable.innerHTML = `
        <thead>
          <tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th></tr>
        </thead>`;
      const secBody = document.createElement('tbody');
      (hdr.sections || []).forEach(sec => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.textContent = sec.name;
        if (!GENERIC_SECTIONS.has(sec.name.toLowerCase())) {
          tdName.style.color = '#b200ff';
        }
        tr.appendChild(tdName);

        const tdVS = document.createElement('td');
        tdVS.textContent = sec.virtual_size;
        tr.appendChild(tdVS);

        const tdRS = document.createElement('td');
        tdRS.textContent = sec.raw_size;
        tr.appendChild(tdRS);

        const tdE = document.createElement('td');
        tdE.textContent = sec.entropy;
        const ev = parseFloat(sec.entropy);
        if (!isNaN(ev)) tdE.style.color = entropyColor(ev);
        tr.appendChild(tdE);

        secBody.appendChild(tr);
      });
      secTable.appendChild(secBody);
      content.appendChild(secTable);

      // PE details collapsibles
      const det = r.pe_details || {};
      ['urls','domains','ips'].forEach(key => {
        const items = det[key] || [];
        content.appendChild(makeCollapsible(key.toUpperCase(), items));
      });

      // Packing detection
      const pd = r.packing_detection || {};
      const pdTitle = document.createElement('h4');
      pdTitle.textContent = 'Packing Detection';
      content.appendChild(pdTitle);

      const pdTable = document.createElement('table');
      pdTable.classList.add('info-table');
      function addPDRow(k, v) {
        const tr = document.createElement('tr');
        const tdK = document.createElement('td');
        tdK.classList.add('info-key');
        tdK.textContent = k;
        const tdV = document.createElement('td');
        tdV.classList.add('info-val');
        if (v instanceof Node) tdV.appendChild(v);
        else tdV.textContent = v != null ? v : '';
        tr.append(tdK, tdV);
        pdTable.appendChild(tr);
      }

      // Packed in red if true
      const packedSpan = document.createElement('span');
      packedSpan.textContent = String(pd.packed);
      if (pd.packed) packedSpan.style.color = 'red';
      addPDRow('Packed', packedSpan);

      // Packer name in default text color
      addPDRow('Packer', pd.packer || '');

      content.appendChild(pdTable);

      // Raw packing output
      const pre = document.createElement('pre');
      pre.textContent = pd.output || '';
      content.appendChild(pre);

    } else if (r.type === 'pdf') {
      const d = r.pdf_details || {};
      addRow('Encrypted', d.encrypted);
      ['urls','ips','domains'].forEach(key => {
        const items = d[key] || [];
        content.appendChild(makeCollapsible(key.toUpperCase(), items));
      });

    } else if (r.type === 'archive') {
      addRow('Archive Protected', r.archive_protected);

    } else if (r.type === 'office') {
      const o = r.office_details || {};
      addRow('Encrypted',  o.encrypted);
      addRow('Has Macros', o.has_macros);
      addRow('Language',   o.language);
      addRow('Page Count', o.page_count);

    } else {
      const pre = document.createElement('pre');
      pre.textContent = JSON.stringify(r, null, 2);
      content.appendChild(pre);
    }
  } catch (err) {
    console.error('Render error', err);
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(r, null, 2);
    content.appendChild(pre);
  }

  entry.appendChild(content);
  resultsDiv.appendChild(entry);
}



// helper to color entropy
function entropyColor(val) {
  const ratio = Math.min(val/8,1);
  const r = Math.round(255*ratio), g = Math.round(255*(1-ratio));
  return `rgb(${r},${g},0)`;
}

function makeCollapsible(titleText, items) {
  const wrapper = document.createElement('div');
  wrapper.classList.add('collapsible');

  const header = document.createElement('div');
  header.classList.add('collapsible-header');

  const arrow = document.createElement('span');
  arrow.classList.add('arrow');

  // Show ✖ if list is empty, otherwise >
  if (!items.length) {
    arrow.textContent = '✖';
    arrow.style.cursor = 'default';
  } else {
    arrow.textContent = '>';
    arrow.style.cursor = 'pointer';
  }

  header.appendChild(arrow);

  const title = document.createElement('span');
  title.textContent = titleText;
  header.appendChild(title);

  wrapper.appendChild(header);

  const content = document.createElement('div');
  content.classList.add('collapsible-content');
  content.style.display = 'none';

  const ul = document.createElement('ul');
  ul.classList.add('info-list');

  items.forEach(it => {
    const li = document.createElement('li');
    li.textContent = it;
    ul.appendChild(li);
  });

  content.appendChild(ul);
  wrapper.appendChild(content);

  if (items.length) {
    header.addEventListener('click', () => {
      const open = wrapper.classList.toggle('open');
      content.style.display = open ? 'block' : 'none';
    });
  }

  return wrapper;
}



// Known PE section names (lowercase) that we treat as “generic”
const GENERIC_SECTIONS = new Set([
  '.text', '.rdata', '.data', '.idata', '.edata',
  '.rsrc', '.reloc', '.tls', '.pdata'
]);

// init
updateFilesDisplay();