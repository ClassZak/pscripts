#!/bin/python3

"""
Simple HTTP server to receive file uploads via multipart/form-data POST requests.

It extracts file parts, saves them to the current working directory, and
supports overriding the saved filename using the request URL path.

Rules:
- Only Content-Type: multipart/form-data is accepted; returns 400 otherwise.
- If the request path ends with a filename (e.g., /newname.bin), the first
uploaded file is saved with that name instead of the original filename.
- If the path ends with a slash or has no filename, the original filename
from the Content-Disposition header is used.
- All filenames are sanitized with os.path.basename to prevent directory
traversal.
- The raw request body is saved to a temporary file for debugging purposes.
- The server listens on all interfaces on port 8000 by default.

Usage examples (curl):
# Upload a file, keep its original name
curl -F "file=@document.pdf" http://localhost:8000/

# Upload a file, save as 'renamed.bin' on the server
curl -F "file=@data.bin" http://localhost:8000/renamed.bin

# Upload multiple files (the first one can be renamed via URL)
curl -F "file1=@a.txt" -F "file2=@b.txt" http://localhost:8000/only_first_renamed.txt
"""

import email
import email.policy
import http.server
import os
import socketserver
import tempfile
import urllib.parse

PORT = 8000
UPLOAD_DIR = '.'  # Directory where uploaded files are stored


class DebugUploadHandler(http.server.SimpleHTTPRequestHandler):
	"""
	HTTP request handler for uploading files via POST.

	Extends SimpleHTTPRequestHandler to add multipart/form-data upload
	support with debug logging and optional filename override from URL.
	"""

	def do_POST(self):
		"""
		Handle a POST request: parse multipart body, save uploaded files,
		and return a plain text response listing the saved filenames.
		"""
		content_type = self.headers.get('Content-Type', '')
		print('=== POST request ===')
		print(f'Content-Type: {content_type}')
		print(f'Headers: {self.headers}')

		# Extract filename from URL path (if present)
		parsed_path = urllib.parse.urlparse(self.path).path
		# Treat the path as having a target filename only if it does not end with '/'
		url_filename = os.path.basename(parsed_path) if not parsed_path.endswith('/') else ''
		if url_filename == '':
			url_filename = None

		if not content_type.startswith('multipart/form-data'):
			self.send_error(400, 'Expected multipart/form-data')
			return

		content_length = int(self.headers.get('Content-Length', 0))
		print(f'Content-Length: {content_length}')
		body = self.rfile.read(content_length)
		print(f'Read {len(body)} bytes')

		# Save raw request body for debugging
		with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
			temp_file.write(body)
			print(f'Raw body saved to {temp_file.name}')

		# Parse multipart MIME message from the request body
		try:
			msg = email.message_from_bytes(body, policy=email.policy.default)
		except Exception as e:
			self.send_error(400, f'Invalid multipart data: {e}')
			return

		saved_files = []
		for part in msg.walk():
			print(f'Part: maintype={part.get_content_maintype()}, '
				f'subtype={part.get_content_subtype()}, '
				f'filename={part.get_filename()}')
			if part.get_content_maintype() == 'multipart':
				continue

			original_filename = part.get_filename()
			if not original_filename:
				continue  # Skip non-file fields

			# Decide which name to use for saving
			if url_filename and len(saved_files) == 0:
				# Override the first file's name with the one from the URL
				save_filename = url_filename
				print(f'Using URL filename: {save_filename}')
			else:
				# Use the original filename, sanitized
				save_filename = os.path.basename(original_filename)

			filepath = os.path.join(UPLOAD_DIR, save_filename)
			with open(filepath, 'wb') as f:
				f.write(part.get_payload(decode=True))
			saved_files.append(save_filename)
			print(f'Saved file: {save_filename}')

		self.send_response(200)
		self.send_header('Content-Type', 'text/plain; charset=utf-8')
		self.end_headers()
		response = f"Uploaded: {', '.join(saved_files)}" if saved_files else 'No files uploaded'
		self.wfile.write(response.encode('utf-8'))


if __name__ == '__main__':
	with socketserver.TCPServer(('', PORT), DebugUploadHandler) as httpd:
		print(f'Serving on http://localhost:{PORT}')
		httpd.serve_forever()