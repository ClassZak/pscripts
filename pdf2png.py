#!/usr/bin/env python3
"""
PDF to PNG converter using PyMuPDF (fitz).
Usage: pdf2png input.pdf [output] [--dpi DPI] [--first-page N] [--last-page N]
"""

import argparse
import os
import sys
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    sys.exit("Error: PyMuPDF is required. Install it with: pip install PyMuPDF")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Convert PDF pages to PNG images."
    )
    parser.add_argument("input", help="Path to input PDF file")
    parser.add_argument(
        "output",
        nargs="?",
        default=None,
        help="Output directory or file name pattern (default: current directory)",
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=150,
        help="Resolution in DPI (default: 150)",
    )
    parser.add_argument(
        "--first-page",
        type=int,
        default=1,
        help="First page to convert (1-based, default: 1)",
    )
    parser.add_argument(
        "--last-page",
        type=int,
        default=None,
        help="Last page to convert (default: last page of PDF)",
    )
    parser.add_argument(
        "--single-file",
        action="store_true",
        help="Save only the first specified page to the exact output file name (no numbering)",
    )
    return parser.parse_args()


def get_output_pattern(output_arg, input_path, single_file):
    """
    Determine output directory and file name pattern based on output argument.
    Returns (output_dir, base_name, suffix_pattern).
    """
    input_path = Path(input_path).resolve()
    base_stem = input_path.stem  # filename without extension

    if output_arg is None:
        # Default: current working directory
        out_dir = Path.cwd()
        base_name = base_stem
        suffix_pattern = "_page_{:d}.png"
        return out_dir, base_name, suffix_pattern

    out_path = Path(output_arg)

    # If output path has a .png extension (case-insensitive) and --single-file is set
    if single_file or out_path.suffix.lower() == ".png":
        # Treat as exact file path for single page output
        out_dir = out_path.parent
        base_name = out_path.stem
        suffix_pattern = ".png"  # No numbering, will overwrite for multiple pages if not single
        return out_dir, base_name, suffix_pattern

    # If output is an existing directory or ends with path separator, treat as directory
    if out_path.is_dir() or output_arg.endswith(os.sep):
        out_dir = out_path
        base_name = base_stem
        suffix_pattern = "_page_{:d}.png"
        return out_dir, base_name, suffix_pattern

    # Otherwise, assume it's a prefix/pattern (e.g., "out" or "img")
    out_dir = out_path.parent
    base_name = out_path.name
    suffix_pattern = "_page_{:d}.png"
    return out_dir, base_name, suffix_pattern


def main():
    args = parse_arguments()

    input_path = Path(args.input)
    if not input_path.is_file():
        sys.exit(f"Error: Input file not found: {input_path}")

    # Open PDF
    try:
        doc = fitz.open(input_path)
    except Exception as e:
        sys.exit(f"Error: Cannot open PDF file: {e}")

    total_pages = len(doc)
    first = max(1, args.first_page)
    last = args.last_page if args.last_page is not None else total_pages
    last = min(last, total_pages)

    if first > last:
        sys.exit(f"Error: Invalid page range ({first}-{last})")

    # Determine output location and naming
    out_dir, base_name, suffix_pattern = get_output_pattern(
        args.output, input_path, args.single_file
    )

    # Create output directory if it doesn't exist
    out_dir.mkdir(parents=True, exist_ok=True)

    # Conversion factor: PDF points to pixels at given DPI
    zoom = args.dpi / 72.0
    matrix = fitz.Matrix(zoom, zoom)

    print(f"Converting {input_path} (pages {first}-{last}) to PNG at {args.dpi} DPI...")
    print(f"Output directory: {out_dir}")

    for page_num in range(first, last + 1):
        page = doc[page_num - 1]  # zero-based index
        pix = page.get_pixmap(matrix=matrix)

        # Build output filename
        if args.single_file and page_num == first:
            # Single file mode: use exact name from output argument or derived
            if args.output and Path(args.output).suffix.lower() == ".png":
                out_file = out_dir / Path(args.output).name
            else:
                out_file = out_dir / f"{base_name}.png"
        else:
            if suffix_pattern == ".png":
                # No numbering pattern; avoid overwriting by adding number anyway
                out_file = out_dir / f"{base_name}_page_{page_num}.png"
            else:
                out_file = out_dir / f"{base_name}{suffix_pattern.format(page_num)}"

        pix.save(out_file)
        print(f"  Saved: {out_file}")

    doc.close()
    print("Done.")


if __name__ == "__main__":
    main()
