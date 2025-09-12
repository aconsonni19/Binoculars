# TODO: Poi da mettere dietro ad un reverse proxy
from flask import Flask, request, redirect, make_response, session, jsonify
from werkzeug.utils import secure_filename
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFParseError
from capstone import *
import os
import json
import subprocess
import sys
from analyses.VulnDetection.VulnDetection import VulnDetection

app = Flask(__name__)

app.config.from_file("config.json", load = json.load)
app.secret_key = os.urandom(1024)

tag = "[Binoculars]:"

@app.route("/upload", methods = ["POST"])
def upload():
    file = request.files.get("file")
    try:
        ELFFile(file)
        file.seek(0)
        save_file(file)
        return make_response("Created", 201)
    except ELFParseError as err:
        print(err)
        return make_response("The uploaded file is not a valid ELF!", 422)
    
    
@app.route("/disassemble", methods = ["GET"])
def disassemble():
    filepath = session.get("FILEPATH")
    try:
        with open(filepath, "rb") as file:
            elf_object = ELFFile(file)
            text_section = elf_object.get_section_by_name(".text")
            if not text_section:
                return make_response(".text section is missing in the ELF file!", 422)
            
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembly = []
            
            for section in elf_object.iter_sections():
                
                if section.name and section.data():
                    disassembly_section = {
                        "section": section.name,
                        "instructions": []
                    }
                    
                    code = section.data()
                    addr = section["sh_addr"]
                    for i in md.disasm(code, addr):
                        disassembly_section["instructions"].append({
                            "address": f"0x{i.address:x}",
                            "mnemonic": i.mnemonic,
                            "op_str": i.op_str
                        })
                    disassembly.append(disassembly_section)
            json_response = jsonify({"disassembly": disassembly})
            return json_response, 200

    except Exception as e:
        print(e)
        return f"{tag}Something went wrong!", 500;
    

@app.route("/decompile", methods = ["GET"])
def decompile():
    filepath = session.get("FILEPATH")
    ghidra_install_folder = app.config["GHIDRA_INSTALL_FOLDER"]
        
    proc = subprocess.run(
        [sys.executable, "./ghidra_decompile.py", filepath, ghidra_install_folder],
        capture_output = True,
        text = True
    )
        
    if(proc.returncode != 0):
        print(proc.stderr)
        return make_response(f"{tag} Something went wrong", 500)
    
    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        print(f"{tag} Failed to decode Ghidra output!")
        return make_response(f"{tag} Failed to decode Ghidra output!", 500)
    return jsonify(results)
    
    
@app.route("/analyses/vulndetect", methods = ["POST"])
def vuln_detect_analysis():
            
    detector = VulnDetection(session.get("FILEPATH"))
    
    param_len_list_raw = request.form.get("param_lengths");
    
    param_len_list = json.loads(param_len_list_raw)
    
    if not isinstance(param_len_list, list) or not all(isinstance(n, int) for n in param_len_list):
        return jsonify({"error": "param_lengths must be a list of integers"}), 400
    
    results = detector.analyze(
        stdin_input_len = int(request.form.get("stdin_input_length")),
        max_depth = app.config["ANGR_MAX_DEPTH"],
        length_of_argv_inputs = param_len_list
    )
    return jsonify(results)

def save_file(file):
    filename = secure_filename(file.filename)
    os.makedirs(app.config['BIN_UPLOAD_FOLDER'], exist_ok=True)
    filepath = os.path.join(app.config["BIN_UPLOAD_FOLDER"], filename)
    session["FILEPATH"] = filepath
    file.save(filepath)
    
    

