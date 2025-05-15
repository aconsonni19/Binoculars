from flask import Flask, render_template, request, url_for, redirect, session, jsonify
from werkzeug.utils import secure_filename
from elftools.elf.elffile import ELFFile
from capstone import *
import os
import tempfile
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# TODO: Ha bisogno di un serio e profondo refactoring del codice

app = Flask(__name__)

TEMP_UPLOAD_FOLDER = "./tmp/"
app.config['TEMP_UPLOAD_FOLDER'] = TEMP_UPLOAD_FOLDER
app.secret_key = os.urandom(256)



# TODO: This function can surely be improved to avoid XSS attacks, but for now it will do
def valid_file(file):
    magic_bytes = b"\x7fELF" # Magic bytes at the start of every 
    return ".elf" in file.filename or file.read(4) == magic_bytes


def save_file(file):
    filename = secure_filename(file.filename)
    os.makedirs(app.config['TEMP_UPLOAD_FOLDER'], exist_ok=True)
    filepath = os.path.join(app.config["TEMP_UPLOAD_FOLDER"], filename)
    session["FILEPATH"] = filepath
    file.save(filepath)

def file_cleanup(file):
    return null # TODO

@app.route("/", methods = ["GET", "POST"])
def main():
    if request.method == "POST":
        file = request.files.get('file')
        if valid_file(file):
            file.seek(0) # TODO: This resets the file pointer; it is here now to test it, but it should be 
            save_file(file)
            return redirect(url_for("code_analysis"))
        else:
            return render_template("index.html", error = "Invalid file format!")
    return render_template("index.html")


@app.route("/analysis")
def code_analysis():
    filepath = session.get("FILEPATH")
    
    if not filepath or not os.path.exists(filepath):
        abort(404, description="File not found")
    
    try:
        with open(filepath, 'rb') as file:
            # Parsing del file ELF con pyelftools
            elf = ELFFile(file)
            text_section = elf.get_section_by_name('.text')  # Sezione del codice
            if not text_section:
                return "No .text section found in the ELF file."

            # Disassembly con Capstone
            md = Cs(CS_ARCH_X86, CS_MODE_64)  # Modifica l'architettura se necessario
            disassembly = []
            for section in elf.iter_sections():
                disassembly_section = [section.name] # Dissasembly for this section with the section name at the head
                code = section.data()
                addr = section['sh_addr']
                for i in md.disasm(code, addr):
                    # Save address, instruction and registers/memory section involved 
                    # as a tuple so that the it can be formatted and styled indipendently:
                    disassembly_section.append((f"0x{i.address:x}", i.mnemonic, i.op_str))
                disassembly.append(disassembly_section)
            # Mostra il risultato del disassembly
            return render_template("code_analysis.html", disassembly=disassembly)

    except Exception as e:
        return str(e)
    