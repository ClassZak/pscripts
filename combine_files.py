#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to recursively combine all files from a directory into one text file.
For each file, a line with its relative path is written, followed by its content.
All files are treated as text encoded in UTF-8 (unreadable bytes are replaced).
The output file is saved in UTF-8 without BOM.
Works on Windows, Linux, and macOS.

Optional filters:
  --include PATTERN   Only include files whose relative path matches the regex.
  --exclude PATTERN   Exclude files whose relative path matches the regex.
"""

import os
import sys
import re
import argparse
from typing import Optional

CHUNK_SIZE = 8192


def process_directory(input_dir: str, output_file: str,
					  include_pattern: Optional[str] = None,
					  exclude_pattern: Optional[str] = None) -> None:
	"""
	Recursively walks through input_dir and writes all files into output_file,
	optionally filtered by include/exclude regular expressions.
	"""
	input_dir = os.path.normpath(input_dir)
	file_count = 0

	# Pre‑compile regexps if provided
	include_re = re.compile(include_pattern) if include_pattern else None
	exclude_re = re.compile(exclude_pattern) if exclude_pattern else None

	with open(output_file, 'w', encoding='utf-8') as out:
		for root, dirs, files in os.walk(input_dir):
			for filename in files:
				full_path = os.path.join(root, filename)
				rel_path = os.path.relpath(full_path, input_dir)

				# Apply filters
				if include_re and not include_re.search(rel_path):
					continue
				if exclude_re and exclude_re.search(rel_path):
					continue

				try:
					out.write(f'```{rel_path}\n')
					with open(full_path, 'rb') as f:
						while True:
							chunk = f.read(CHUNK_SIZE)
							if not chunk:
								break
							out.write(chunk.decode('utf-8', errors='replace'))
					out.write('\n```\n')
					file_count += 1
				except Exception as e:
					print(f"Warning: could not process file {full_path}: {e}",
						  file=sys.stderr)

	print(f"Processed files: {file_count}")
	print(f"Result saved to: {output_file}")


def main() -> None:
	parser = argparse.ArgumentParser(
		description="Combine all files from a directory into one text file, "
					"optionally filtering by regular expressions."
	)
	parser.add_argument(
		"input_dir",
		nargs='?',
		default=os.getcwd(),
		help="Input directory (default: current directory)"
	)
	parser.add_argument(
		"output_file",
		nargs='?',
		default="combined.txt",
		help="Output file name (default: combined.txt)"
	)
	parser.add_argument(
		"--include", "-i",
		help="Regular expression – only files with matching relative path are included"
	)
	parser.add_argument(
		"--exclude", "-e",
		help="Regular expression – files with matching relative path are excluded"
	)

	args = parser.parse_args()

	# Check that input directory exists
	if not os.path.isdir(args.input_dir):
		print(f"Error: directory '{args.input_dir}' does not exist or is not a folder.",
			  file=sys.stderr)
		sys.exit(1)

	process_directory(
		args.input_dir,
		args.output_file,
		include_pattern=args.include,
		exclude_pattern=args.exclude
	)


if __name__ == "__main__":
	main()
