# PhishShield AI — local demo server (the "Test Range").
#
# Serves the whole demo/ folder on 127.0.0.1:8098 so every extension feature can be shown from one
# place, plus a slow, padded APK download so Download Guard can be seen pausing a real transfer.
# Everything is local; no page sends anything anywhere. Usage (from the project root):
#
#   python scripts/demo-server.py
#
# then open http://127.0.0.1:8098/  in Chrome with the PhishShield extension loaded.
import io
import os
import sys
import time
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlsplit

PORT = 8098
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'demo'))
FILES = os.path.join(ROOT, 'files')

MIME = {
    '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8',
    '.pdf': 'application/pdf', '.apk': 'application/vnd.android.package-archive',
    '.docm': 'application/vnd.ms-word.document.macroEnabled.12',
}
ATTACH = {
    'apk': ('RTO_E-Challan_2026.apk', 'SBI_YONO_KYC_Update.apk'),
    'pdf': ('Electricity_Bill_Disconnection.pdf', 'Electricity_Bill_Disconnection.pdf'),
    'docm': ('Salary_Revision_2026.docm', 'Salary_Revision_2026.docm'),
    'html': ('Secure_Message_HDFC.html', 'Secure_Message_HDFC.html'),
    'txt': ('My_Notes.txt', 'normal_notes.txt'),
}

# A ~3 MB padded copy of the APK: big enough to still be downloading when Download Guard pauses it.
# The padding is random bytes in a separate archive entry; the file contains no runnable code.
with zipfile.ZipFile(os.path.join(FILES, 'SBI_YONO_KYC_Update.apk')) as zin:
    _buf = io.BytesIO()
    with zipfile.ZipFile(_buf, 'w', zipfile.ZIP_STORED) as zout:
        for info in zin.infolist():
            zout.writestr(info.filename, zin.read(info.filename))
        zout.writestr('assets/padding.bin', os.urandom(3 * 1024 * 1024))
APK_SLOW = _buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == '/' or path == '':
            return self.redirect('/site/index.html')
        if path.startswith('/dl/'):
            return self.download(path[4:].strip('/').lower())
        return self.static(path)

    def redirect(self, to):
        self.send_response(302)
        self.send_header('Location', to)
        self.end_headers()

    def download(self, kind):
        meta = ATTACH.get(kind)
        if not meta:
            return self.send_error(404)
        shown, source = meta
        self.send_response(200)
        self.send_header('Content-Type', MIME.get(os.path.splitext(shown)[1], 'application/octet-stream'))
        self.send_header('Content-Disposition', f'attachment; filename="{shown}"')
        if kind == 'apk':  # slow + padded so the pause is visible
            self.send_header('Content-Length', str(len(APK_SLOW)))
            self.end_headers()
            try:
                for i in range(0, len(APK_SLOW), 30 * 1024):
                    self.wfile.write(APK_SLOW[i:i + 30 * 1024])
                    self.wfile.flush()
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass  # paused or cancelled
            return
        with open(os.path.join(FILES, source), 'rb') as fh:
            data = fh.read()
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def static(self, path):
        full = os.path.abspath(os.path.join(ROOT, path.lstrip('/')))
        if not full.startswith(ROOT) or not os.path.isfile(full):  # no path traversal
            return self.send_error(404)
        with open(full, 'rb') as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header('Content-Type', MIME.get(os.path.splitext(full)[1], 'application/octet-stream'))
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    print(f'PhishShield Test Range -> http://127.0.0.1:{PORT}/   (Ctrl+C to stop)', flush=True)
    try:
        HTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
