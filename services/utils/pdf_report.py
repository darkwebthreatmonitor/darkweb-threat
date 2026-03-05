from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
import tempfile


def generate_pdf(report_text, severity_chart=None, type_chart=None):
    styles = getSampleStyleSheet()

    tmp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdf_path = tmp_pdf.name

    story = []

    story.append(Paragraph("Dark Web Threat Intelligence Report", styles["Title"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph(report_text.replace("\n", "<br/>"), styles["BodyText"]))
    story.append(Spacer(1, 20))

    if severity_chart:
        story.append(Paragraph("Threat Severity Distribution", styles["Heading2"]))
        story.append(Image(severity_chart, width=400, height=250))
        story.append(Spacer(1, 20))

    if type_chart:
        story.append(Paragraph("Threat Type Distribution", styles["Heading2"]))
        story.append(Image(type_chart, width=400, height=250))

    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    doc.build(story)

    return pdf_path