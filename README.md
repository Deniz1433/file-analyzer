# 🧠 File Analyzer (Electron + Python)

A cross-platform desktop application built with **Electron** and **Python** for interactive file analysis.  
It allows drag-and-drop or multi-select file input and uses a Python backend to inspect executables, archives, documents, and PDFs.

---

## 🚀 Features

- Drag-and-drop or dialog-based file input
- Native file icon extraction
- Dark/light mode toggle with persistent theme
- Type-specific analysis for:
  - PE (Windows executables)
  - PDFs
  - Office documents (Word, Excel, PowerPoint)
  - Archives (ZIP, RAR, 7z)
- Entropy calculation, macro detection, packing analysis
- Visual results with collapsible sections and file-type-specific data
- Fully portable build with compiled Python backend

---

## 🛠 Technologies

- **Electron** (Frontend GUI)
- **Node.js** (IPC and shell integration)
- **Python (Nuitka-compiled)** for backend analysis logic

---

## 🐍 Python Backend: Used Libraries

The following Python packages are used inside `analyze.py`:

| Module                      | Purpose                                       |
|----------------------------|-----------------------------------------------|
| `os`, `sys`, `time`, `re`, `math`, `json` | Core system utilities              |
| `magic`                    | File type detection via magic headers         |
| `zipfile`, `rarfile`, `py7zr` | Archive handling (ZIP, RAR, 7z)           |
| `xml.etree.ElementTree`    | XML parsing for Office file metadata          |
| `msoffcrypto`              | Office file encryption detection              |
| `oletools.olevba`          | VBA macro detection in Office files           |
| `PyPDF2`                   | PDF parsing and metadata extraction           |
| `openpyxl`                 | Excel workbook parsing                        |
| `pefile`                   | Portable Executable structure inspection      |
| `subprocess`               | Invoking external tools like packer detection |
| `pypackerdetect`           | Detects common packers in executable files    |
| `concurrent.futures`       | Parallel processing (for future scaling)      |

---

## 👤 Author

[Deniz1433](https://github.com/Deniz1433)
