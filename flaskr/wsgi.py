from flask import Flask, render_template, request, url_for, redirect, session, jsonify
from werkzeug.utils import secure_filename
from elftools.elf.elffile import ELFFile
from capstone import *
import os
import pyghidra
import re

# TODO: Ha bisogno di un serio e profondo refactoring del codice

app = Flask(__name__)

TEMP_UPLOAD_FOLDER = "./tmp/"
app.config['TEMP_UPLOAD_FOLDER'] = TEMP_UPLOAD_FOLDER
app.secret_key = os.urandom(256)

# TODO: Move to a setup function, so that the imports can be done at the start of the program
# Initialize jython enviorment with PyGhidra

pyghidra.start(install_dir = "../ghidra/")
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI


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
    
    return render_template("code_analysis.html", disassembly=disassemble(filepath), decompiled = highlight_keywords(decompile(filepath)))   


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


def disassemble(filepath):
    try:
        with open(filepath, "rb") as file:
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
            return disassembly
    except Exception as e:
        return str(e)

def decompile(filepath):
    try:
        decompiled_functions = []
        with pyghidra.open_program(filepath) as flat_api: # Get a FlatAPI reference to Ghidra
            program = flat_api.getCurrentProgram() # Get the program being analyzed
            listing = program.getListing() # Get the program listing of the symbols
            decompiler = FlatDecompilerAPI(flat_api) # Get a FlatDecompilerAPI reference to the Ghidra decompiler
            for name in listing.getFunctions(True):
                decompiled_code = decompiler.decompile(name)
                decompiled_functions.append(decompiled_code) # Decompile the function
        return "\n".join(decompiled_functions)  # Ensure proper spacing
    except Exception as e:
        return str(e)
    
def highlight_keywords(decompiled_code):
    keywords = {
        r"\bint\b": "keyword-int",
        r"\breturn\b": "keyword-return",
        r"\bif\b": "keyword-if",
        r"\belse\b": "keyword-else",
        r"\bfor\b": "keyword-for",
        r"\bwhile\b": "keyword-while",
        r"\bprintf\b": "keyword-function",
        r"\bmain\b": "keyword-function",
        r"\bvoid\b": "keyword-int",
        r"\bchar\b": "keyword-int",
        r"\bfloat\b": "keyword-int",
        r"\bdouble\b": "keyword-int",
        r"\bbyte\b": "keyword-int",
        r"\bWARNING\b": "keyword-warning",
        r"\bvoid\b": "keyword-void",
        r"\bstruct\b": "keyword-struct",
        # Aggiungi altre parole chiave qui
    }

    for keyword, css_class in keywords.items():
        #decompiled_code = decompiled_code.replace(
        #    keyword, f'<span class="{css_class}">{keyword}</span>'
        #decompiled_code = re.sub(
        #    keyword, f'<span class="{css_class}">{keyword}</span>', decompiled_code
        #)
        decompiled_code = re.sub(
            keyword,
            rf'<span class="{css_class}">\g<0></span>',
            decompiled_code
        )
    return decompiled_code