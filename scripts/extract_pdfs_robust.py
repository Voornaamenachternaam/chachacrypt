#!/usr/bin/env python3
"""
Robust multi-engine PDF extractor.
Streams output directly to the final file and flushes after every page
to ensure no data is lost if the process crashes or is killed.
MuPDF -> pdfplumber -> OCR (Tesseract) -> pdfminer fallback.
"""

from pathlib import Path
import argparse
import sys
import io
import traceback
import json

# third-party imports
import fitz  # pymupdf
import pdfplumber
import pdfminer.high_level
from PIL import Image
import pytesseract

# Minimum characters per page to be considered "non-empty"
PAGE_CONTENT_THRESHOLD = 3


def extract_with_mupdf_page(page):
    try:
        return page.get_text("text") or ""
    except Exception:
        return ""


def extract_with_pdfminer_path(path):
    try:
        return pdfminer.high_level.extract_text(str(path)) or ""
    except Exception:
        return ""


def render_page_to_image(page, dpi):
    """
    Render a fitz.Page to a PIL.Image at the requested DPI.
    """
    mat = fitz.Matrix(dpi / 72.0, dpi / 72.0)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    png_bytes = pix.tobytes("png")
    return Image.open(io.BytesIO(png_bytes))


def ocr_image_to_text(img, lang):
    try:
        return pytesseract.image_to_string(img, lang=lang) or ""
    except Exception:
        return ""


def process_pdf(path: Path, out_stream, ocr_dpi: int, tesseract_lang: str):
    """
    Process a single PDF file and write directly to the output stream.
    Flushes the stream after every page to prevent data loss on crash.
    """
    details = {"path": str(path), "pages": 0, "failed_pages": []}
    try:
        doc = fitz.open(path)
        page_count = doc.page_count
        details["pages"] = page_count

        # Write header directly to output stream
        out_stream.write(f"===== FILE: {path.name} (pages={page_count}) =====\n\n")

        for pno in range(page_count):
            page = doc.load_page(pno)
            out_stream.write(f"\n--- PAGE {pno+1}/{page_count} ---\n")
            page_had_text = False

            # 1) MuPDF extraction (fast, first choice)
            try:
                mupdf_text = extract_with_mupdf_page(page)
            except Exception:
                mupdf_text = ""
            if mupdf_text and len(mupdf_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                out_stream.write("\n[MuPDF TEXT]\n")
                out_stream.write(mupdf_text)
                page_had_text = True
            else:
                # 2) pdfplumber page-level text
                try:
                    with pdfplumber.open(path) as docp:
                        pdfpl_text = docp.pages[pno].extract_text() or ""
                except Exception:
                    pdfpl_text = ""
                if pdfpl_text and len(pdfpl_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                    out_stream.write("\n[PDFPlumber TEXT]\n")
                    out_stream.write(pdfpl_text)
                    page_had_text = True
                else:
                    # 3) OCR fallback (render page -> OCR)
                    try:
                        img = render_page_to_image(page, dpi=ocr_dpi)
                        ocr_text = ocr_image_to_text(img, lang=tesseract_lang) or ""
                    except Exception:
                        ocr_text = ""
                    if ocr_text and len(ocr_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                        out_stream.write("\n[OCR TEXT]\n")
                        out_stream.write(ocr_text)
                        page_had_text = True

            # Always attempt to extract tables (TSV rows) via pdfplumber and append
            try:
                with pdfplumber.open(path) as docp:
                    page_obj = docp.pages[pno]
                    tables = page_obj.extract_tables()
                    if tables:
                        out_stream.write("\n[TABLES - TSV rows]\n")
                        for t in tables:
                            for row in t:
                                out_stream.write("\t".join([("" if c is None else str(c)) for c in row]) + "\n")
                        if not page_had_text:
                            page_had_text = True
            except Exception:
                pass

            if not page_had_text:
                details["failed_pages"].append(pno + 1)
                out_stream.write("\n[NO TEXT EXTRACTED FOR THIS PAGE AFTER ALL ENGINES]\n")

            # FLUSH THE STREAM AFTER EVERY PAGE
            # This ensures that if the process is killed, the data up to this point is saved.
            out_stream.flush()

        success = len(details["failed_pages"]) == 0
        return success, details

    except Exception as e:
        details["error"] = str(e)
        details["traceback"] = traceback.format_exc()
        # Write error to output stream so the user sees it in the file
        out_stream.write(f"\n[FATAL ERROR PROCESSING FILE: {e}]\n")
        out_stream.flush()
        return False, details


def main():
    parser = argparse.ArgumentParser(description="Robust PDF extractor (multi-engine).")
    parser.add_argument("--input-dir", required=True, help="Directory containing extracted files (PDFs).")
    parser.add_argument("--output-file", required=True, help="Path to combined output text file.")
    parser.add_argument("--ocr-dpi", type=int, default=300, help="DPI for OCR rendering (default: 300).")
    parser.add_argument("--tesseract-lang", type=str, default="eng", help="Tesseract language codes (e.g., 'eng' or 'eng+deu').")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output_file)
    ocr_dpi = args.ocr_dpi
    tesseract_lang = args.tesseract_lang

    pdf_paths = sorted([p for p in input_dir.rglob("*.pdf")])
    if not pdf_paths:
        print("ERROR: No PDF files found in input directory.", file=sys.stderr)
        sys.exit(2)

    overall_failed = []
    processed_count = 0
    manifest = {"total_pdfs": len(pdf_paths), "processed": [], "failed": []}

    # Open the output file ONCE in write mode.
    # We will stream all content directly into this file.
    try:
        # Using buffering=1 for line buffering, or 0 for unbuffered binary, 
        # but standard text buffering is fine as we flush explicitly.
        with output_file.open("w", encoding="utf-8") as out_f:
            
            for pdf_path in pdf_paths:
                print(f"\n--- Processing: {pdf_path} ---")
                success, details = process_pdf(pdf_path, out_f, ocr_dpi=ocr_dpi, tesseract_lang=tesseract_lang)

                manifest_entry = {"file": str(pdf_path), "pages": details.get("pages", 0), "success": success}
                if not success:
                    print(f"FAILED to fully extract {pdf_path}; details: {details}", file=sys.stderr)
                    overall_failed.append((str(pdf_path), details))
                    manifest["failed"].append(manifest_entry)
                else:
                    processed_count += 1
                    manifest["processed"].append(manifest_entry)
                
                # Add spacing between files
                out_f.write("\n\n")

    except Exception as e:
        print(f"CRITICAL ERROR opening or writing to output file: {e}", file=sys.stderr)
        sys.exit(5)

    # write manifest
    try:
        with open("extraction-manifest.json", "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)
    except Exception as e:
        print(f"Warning: failed to write extraction manifest: {e}", file=sys.stderr)

    # final validation
    if overall_failed:
        print("\n\nExtraction finished with ERRORS. Summary of failures:", file=sys.stderr)
        for p, d in overall_failed:
            print(f"- {p} -> {d}", file=sys.stderr)
        sys.exit(3)

    if not output_file.exists() or output_file.stat().st_size < 10:
        print("ERROR: Combined output file missing or too small.", file=sys.stderr)
        sys.exit(4)

    print(f"\nALL PDFs processed successfully. Combined output: {output_file} (bytes={output_file.stat().st_size})")
    sys.exit(0)


if __name__ == "__main__":
    main() 
