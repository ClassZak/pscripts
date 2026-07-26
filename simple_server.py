#!/bin/python3

import http.server
import socketserver
import email
import email.policy
import os
import urllib.parse

PORT = 8001
UPLOAD_DIR = "."

class DebugUploadHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_type = self.headers.get('Content-Type', '')
        print(f"=== POST request ===")
        print(f"Content-Type: {content_type}")
        print(f"Headers: {self.headers}")

        if not content_type.startswith('multipart/form-data'):
            self.send_error(400, "Expected multipart/form-data")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        print(f"Content-Length: {content_length}")
        body = self.rfile.read(content_length)
        print(f"Read {len(body)} bytes")

        # Сохраняем сырое тело для анализа (опционально)
        with open("/tmp/post_body.bin", "wb") as f:
            f.write(body)
        print("Raw body saved to /tmp/post_body.bin")

        try:
            msg = email.message_from_bytes(body, policy=email.policy.default)
        except Exception as e:
            self.send_error(400, f"Invalid multipart data: {e}")
            return

        saved_files = []
        for part in msg.walk():
            print(f"Part: maintype={part.get_content_maintype()}, subtype={part.get_content_subtype()}, filename={part.get_filename()}")
            if part.get_content_maintype() == 'multipart':
                continue
            filename = part.get_filename()
            if filename:
                filename = os.path.basename(filename)
                filepath = os.path.join(UPLOAD_DIR, filename)
                with open(filepath, 'wb') as f:
                    f.write(part.get_payload(decode=True))
                saved_files.append(filename)
                print(f"Saved file: {filename}")

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        response = f"Uploaded: {', '.join(saved_files)}" if saved_files else "No files uploaded"
        self.wfile.write(response.encode('utf-8'))


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), DebugUploadHandler) as httpd:
        print(f"Serving on http://localhost:{PORT}")
        httpd.serve_forever()
