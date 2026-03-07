#!/usr/bin/env python3
"""
Robust multi-engine PDF extractor (separate file).
MuPDF -> pdfplumber -> OCR (Tesseract) -> pdfminer fallback.
Writes per-file text to tmp dir then appends to combined output.txt.
Exits non-zero if any page of any PDF is left without extracted content.
Run with:
  python3 scripts/extract_pdfs_robust.py --input-dir data/extracted --output-file output.txt --tmp-dir tmp_extraction --ocr-dpi 300 --tesseract-lang "eng"
"""

from pathlib import Path
import argparse
import sys
import io
import traceback
import json

# third-party imports (installed via requirements.txt / pip)
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


def process_pdf(path: Path, out_txt_path: Path, ocr_dpi: int, tesseract_lang: str):
    """
    Process a single PDF file:
    - write per-file extracted content to out_txt_path
    - returns (success: bool, details: dict)
    details contains page count and any failed pages (1-based).
    """
    details = {"path": str(path), "pages": 0, "failed_pages": []}
    try:
        doc = fitz.open(path)
        page_count = doc.page_count
        details["pages"] = page_count

        with out_txt_path.open("w", encoding="utf-8") as out_f:
            out_f.write(f"===== FILE: {path.name} (pages={page_count}) =====\n\n")

            for pno in range(page_count):
                page = doc.load_page(pno)
                out_f.write(f"\n--- PAGE {pno+1}/{page_count} ---\n")
                page_had_text = False

                # 1) MuPDF extraction (fast, first choice)
                try:
                    mupdf_text = extract_with_mupdf_page(page)
                except Exception:
                    mupdf_text = ""
                if mupdf_text and len(mupdf_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                    out_f.write("\n[MuPDF TEXT]\n")
                    out_f.write(mupdf_text)
                    page_had_text = True
                else:
                    # 2) pdfplumber page-level text (sometimes better for weird PDFs)
                    try:
                        with pdfplumber.open(path) as docp:
                            pdfpl_text = docp.pages[pno].extract_text() or ""
                    except Exception:
                        pdfpl_text = ""
                    if pdfpl_text and len(pdfpl_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                        out_f.write("\n[PDFPlumber TEXT]\n")
                        out_f.write(pdfpl_text)
                        page_had_text = True
                    else:
                        # 3) OCR fallback (render page -> OCR)
                        try:
                            img = render_page_to_image(page, dpi=ocr_dpi)
                            ocr_text = ocr_image_to_text(img, lang=tesseract_lang) or ""
                        except Exception:
                            ocr_text = ""
                        if ocr_text and len(ocr_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                            out_f.write("\n[OCR TEXT]\n")
                            out_f.write(ocr_text)
                            page_had_text = True

                # Always attempt to extract tables (TSV rows) via pdfplumber and append
                try:
                    with pdfplumber.open(path) as docp:
                        page_obj = docp.pages[pno]
                        tables = page_obj.extract_tables()
                        if tables:
                            out_f.write("\n[TABLES - TSV rows]\n")
                            for t in tables:
                                for row in t:
                                    out_f.write("\t".join([("" if c is None else str(c)) for c in row]) + "\n")
                            # If tables were present and text wasn't, still count it as content
                            if not page_had_text:
                                page_had_text = True
                except Exception:
                    # ignore table-extraction failure for this page
                    pass

                if not page_had_text:
                    # Mark failed page (1-based)
                    details["failed_pages"].append(pno + 1)
                    out_f.write("\n[NO TEXT EXTRACTED FOR THIS PAGE AFTER ALL ENGINES]\n")

            out_f.flush()

        # If every page failed, try whole-document pdfminer fallback (can sometimes recover)
        if len(details["failed_pages"]) == details["pages"]:
            whole_text = extract_with_pdfminer_path(path)
            if whole_text and len(whole_text.strip()) >= PAGE_CONTENT_THRESHOLD:
                with out_txt_path.open("a", encoding="utf-8") as out_f:
                    out_f.write("\n[PDFMiner whole-document fallback]\n")
                    out_f.write(whole_text)
                # cleared failed pages if fallback found content
                details["failed_pages"] = []

        success = len(details["failed_pages"]) == 0
        return success, details

    except Exception as e:
        details["error"] = str(e)
        details["traceback"] = traceback.format_exc()
        return False, details


def main():
    parser = argparse.ArgumentParser(description="Robust PDF extractor (multi-engine).")
    parser.add_argument("--input-dir", required=True, help="Directory containing extracted files (PDFs).")
    parser.add_argument("--output-file", required=True, help="Path to combined output text file.")
    parser.add_argument("--tmp-dir", required=True, help="Temporary directory to write per-file text.")
    parser.add_argument("--ocr-dpi", type=int, default=300, help="DPI for OCR rendering (default: 300).")
    parser.add_argument("--tesseract-lang", type=str, default="eng", help="Tesseract language codes (e.g., 'eng' or 'eng+deu').")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_file = Path(args.output_file)
    tmp_dir = Path(args.tmp_dir)
    ocr_dpi = args.ocr_dpi
    tesseract_lang = args.tesseract_lang

    tmp_dir.mkdir(parents=True, exist_ok=True)
    # remove stale combined output if present
    if output_file.exists():
        try:
            output_file.unlink()
        except Exception:
            print("Warning: couldn't remove existing output file; continuing and will append.", file=sys.stderr)

    pdf_paths = sorted([p for p in input_dir.rglob("*.pdf")])
    if not pdf_paths:
        print("ERROR: No PDF files found in input directory.", file=sys.stderr)
        sys.exit(2)

    overall_failed = []
    processed_count = 0
    manifest = {"total_pdfs": len(pdf_paths), "processed": [], "failed": []}

    for pdf_path in pdf_paths:
        print(f"\n--- Processing: {pdf_path} ---")
        per_txt = tmp_dir / (pdf_path.stem + ".txt")
        success, details = process_pdf(pdf_path, per_txt, ocr_dpi=ocr_dpi, tesseract_lang=tesseract_lang)

        manifest_entry = {"file": str(pdf_path), "pages": details.get("pages", 0), "success": success}
        if not success:
            print(f"FAILED to fully extract {pdf_path}; details: {details}", file=sys.stderr)
            overall_failed.append((str(pdf_path), details))
            manifest_entry["details"] = details
            manifest["failed"].append(manifest_entry)
        else:
            size = per_txt.stat().st_size if per_txt.exists() else 0
            if size < 10:
                print(f"Per-file output too small for {pdf_path}: {size} bytes", file=sys.stderr)
                overall_failed.append((str(pdf_path), {"reason": "per-file output too small", "size": size}))
                manifest_entry["details"] = {"reason": "per-file output too small", "size": size}
                manifest["failed"].append(manifest_entry)
            else:
                # append to combined output (streaming)
                with per_txt.open("r", encoding="utf-8") as pf, output_file.open("a", encoding="utf-8") as of:
                    of.write(pf.read())
                    of.write("\n\n")
                processed_count += 1
                manifest["processed"].append(manifest_entry)

    # write manifest to file next to output (useful to upload alongside output.txt)
    try:
        with open("extraction-manifest.json", "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)
    except Exception as e:
        print(f"Warning: failed to write extraction manifest: {e}", file=sys.stderr)

    # final validation and exit codes per strict requirement
    if overall_failed:
        print("\n\nExtraction finished with ERRORS. Summary of failures:", file=sys.stderr)
        for p, d in overall_failed:
            print(f"- {p} -> {d}", file=sys.stderr)
        # non-zero exit to make CI job fail
        sys.exit(3)

    if not output_file.exists() or output_file.stat().st_size < 10:
        print("ERROR: Combined output file missing or too small.", file=sys.stderr)
        sys.exit(4)

    print(f"\nALL PDFs processed successfully. Combined output: {output_file} (bytes={output_file.stat().st_size})")
    sys.exit(0)


if __name__ == "__main__":
    main()
