#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to recursively combine all files from a directory into one text file.
For each file, a line with its relative path is written, followed by its content.
All files are treated as text encoded in UTF-8 (unreadable bytes are replaced).
The output file is saved in UTF-8 without BOM.
Works on Windows, Linux, and macOS.
"""

import os
import sys

# Buffer size for reading files (8 KB)
CHUNK_SIZE = 8192


def process_directory(input_dir: str, output_file: str) -> None:
	"""
	Recursively walks through input_dir and writes all files into output_file.
	"""
	# Normalize the input path to remove any trailing separator
	input_dir = os.path.normpath(input_dir)
	# Counter for processed files
	file_count = 0

	# Open the output file in text mode with UTF-8 (no BOM)
	with open(output_file, 'w', encoding='utf-8') as out:
		# Recursive walk
		for root, dirs, files in os.walk(input_dir):
			for filename in files:
				full_path = os.path.join(root, filename)
				# Relative path from the input directory
				rel_path = os.path.relpath(full_path, input_dir)
				# Optionally replace backslashes with forward slashes for consistency
				# rel_path = rel_path.replace(os.sep, '/')

				try:
					# Write the header line with the file name
					out.write(f'```{rel_path}\n')

					# Open the file in binary mode
					with open(full_path, 'rb') as f:
						while True:
							chunk = f.read(CHUNK_SIZE)
							if not chunk:
								break
							# Decode as UTF-8, replacing errors
							out.write(chunk.decode('utf-8', errors='replace'))
					# Add a newline after the file content
					out.write('\n```\n')
					file_count += 1

				except Exception as e:
					# On access errors or other issues, skip the file with a warning
					print(f"Warning: could not process file {full_path}: {e}", file=sys.stderr)

	print(f"Processed files: {file_count}")
	print(f"Result saved to: {output_file}")


def main() -> None:
	"""
	Entry point: parse command-line arguments.
	"""
	# If one argument is given — it's the input directory, output file defaults.
	# If two arguments — first input directory, second output file.
	# Otherwise use current directory and default output name.
	if len(sys.argv) == 1:
		input_dir = os.getcwd()
		output_file = "combined.txt"
	elif len(sys.argv) == 2:
		if sys.argv[1] == '-h' or sys.argv[1] == '--help':
			print("Usage: python combine_files.py [input_directory] [output_file]")
			sys.exit(0)
		input_dir = sys.argv[1]
		output_file = "combined.txt"
	elif len(sys.argv) == 3:
		input_dir = sys.argv[1]
		output_file = sys.argv[2]
	else:
		print("Usage: python combine_files.py [input_directory] [output_file]")
		sys.exit(1)

	# Check that the input directory exists
	if not os.path.isdir(input_dir):
		print(f"Error: directory '{input_dir}' does not exist or is not a folder.", file=sys.stderr)
		sys.exit(1)

	process_directory(input_dir, output_file)


if __name__ == "__main__":
	main()

