#!/usr/bin/env python3
"""Serve the production frontend build (frontend/out) on a port.

Why this exists: `npm run dev` compiles each route on first visit, which is
what makes pages take 5-10s the first time. Serving the pre-built static
export is instant. This needs only Python (already required), so the Windows
launcher can serve a real production build without extra dependencies.

Usage:  python scripts/serve_frontend.py [port] [out_dir]
"""
import os
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class ExportHandler(SimpleHTTPRequestHandler):
    """Static handler for a Next.js `output: export` build.

    The export uses trailingSlash routing, so each route lives at
    `<route>/index.html`. SimpleHTTPRequestHandler already serves
    directory/index.html; we add a `<path>.html` fallback and a custom
    404 page, and disable HTML caching so a fresh rebuild is picked up.
    """

    def send_head(self):
        path = self.translate_path(self.path)
        # Directory or known file → default behaviour (serves index.html).
        if os.path.isdir(path) or os.path.exists(path):
            return super().send_head()
        # `/foo` → `/foo.html` (some routes export this way).
        html = path.rstrip("/") + ".html"
        if os.path.isfile(html):
            self.path = self.path.rstrip("/") + ".html"
            return super().send_head()
        # Unknown → the export's 404 page with a real 404 status.
        not_found = os.path.join(self.directory, "404.html")
        if os.path.isfile(not_found):
            try:
                f = open(not_found, "rb")
            except OSError:
                return self._plain_404()
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            fs = os.fstat(f.fileno())
            self.send_header("Content-Length", str(fs.st_size))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return f
        return self._plain_404()

    def _plain_404(self):
        body = b"404 Not Found"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return None

    def end_headers(self):
        # Never cache HTML so a rebuilt page shows immediately; hashed
        # assets under /_next/static are safe to cache hard.
        if self.path.endswith((".html", "/")) or "." not in os.path.basename(self.path):
            self.send_header("Cache-Control", "no-cache")
        elif "/_next/static/" in self.path:
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        super().end_headers()

    def log_message(self, *args):
        pass  # quiet


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    here = os.path.dirname(os.path.abspath(__file__))
    default_out = os.path.join(os.path.dirname(here), "frontend", "out")
    out_dir = sys.argv[2] if len(sys.argv) > 2 else default_out

    if not os.path.isdir(out_dir):
        print(f"[serve_frontend] build folder not found: {out_dir}")
        print("[serve_frontend] run `npm run build` in the frontend folder first.")
        sys.exit(1)

    handler = partial(ExportHandler, directory=out_dir)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler)
    print(f"[serve_frontend] serving {out_dir} on http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
