
import pypdf

reader = pypdf.PdfReader("/home/kali/Projeto_SIC/project.pdf")
text = ""
for page in reader.pages:
    text += page.extract_text() + "\n"

print(text)
