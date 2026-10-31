# Serves the harmless demo APK as a ~3 MB file at ~300 KB/s, so Download Guard can be shown pausing a
# download in real Chrome. (A tiny file arrives in one packet and finishes before any extension can pause it.)
# The extra bytes are random padding; the file contains no code. Usage (from the project root):
#   python scripts/demo-download-server.py
# then open http://127.0.0.1:8098/RTO_E-Challan_2026.apk in Chrome with PhishShield loaded.
import io
import os
import sys
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join('demo', 'files', 'SBI_YONO_KYC_Update.apk')
PORT = 8098

buf = io.BytesIO()
with zipfile.ZipFile(SRC) as zin, zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zout:
    for info in zin.infolist():
        zout.writestr(info.filename, zin.read(info.filename))
    zout.writestr('assets/padding.bin', os.urandom(3 * 1024 * 1024))
DATA = buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.android.package-archive')
        self.send_header('Content-Length', str(len(DATA)))
        self.end_headers()
        try:
            for i in range(0, len(DATA), 30 * 1024):
                self.wfile.write(DATA[i:i + 30 * 1024])
                self.wfile.flush()
                time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # the download was paused or cancelled

    def log_message(self, fmt, *args):
        pass


print(f'Demo APK ({len(DATA) // 1024} KB, slow) at http://127.0.0.1:{PORT}/RTO_E-Challan_2026.apk  (Ctrl+C to stop)', flush=True)
HTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
