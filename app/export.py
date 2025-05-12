from fpdf import FPDF
from docx import Document
import os

def export_to_pdf(text: str, output_path: str):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", size=12)
    for line in text.splitlines():
        pdf.multi_cell(0, 10, line)
    pdf.output(output_path)

def export_to_docx(text: str, output_path: str):
    doc = Document()
    doc.add_paragraph(text)
    doc.save(output_path)
