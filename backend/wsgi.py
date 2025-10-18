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
import re
from analyses.VulnDetection.VulnDetection import VulnDetection
from analyses.arbiter.ArbiterAnalysis import ArbiterAnalysis
import uuid

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


@app.route("/analyses/arbiter", methods = ["POST"])
def arbiter_analysis():
    # Get the filepath from the session
    filename = session.get("FILENAME")
    filepath = session.get("FILEPATH")
    
    # Get the arbiter VD directory and regex:
    vd_dir = app.config["ARBITER_VD_FOLDER"]
    regex = app.config["ARBITER_CWE_VD_REGEX"]

    analysis = ArbiterAnalysis(
        os.path.join(app.config["ARBITER_LOGS_FOLDER"], filename),
        os.path.join(app.config["ARBITER_JSON_RESULTS_FOLDER"], filename),
        BLACKLIST = app.config["ARBITER_FUNCTIONS_BLACKLIST"]
    )
    vds = find_vd_files(vd_dir, regex)

    print(f"Found VDs: {vds}")
        
    results = {}
    
    for vd in vds:
        try:
            print(f"Analyzing for {vd}")
            analysis.analyze(os.path.join(vd_dir, vd), filepath)
            results[vd.replace(".py", "")] = True
        except Exception:
            print(f"This file does not present vulnerability {vd}")
            results[vd.replace(".py", "")] = False  
    return results
    
    
    
def find_vd_files(directory, regex):
    matched_files = []
    try:
        regex = re.compile(regex)
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if regex.match(filename):
                    matched_files.append(filename)
    except Exception as e:
        print(e)
    finally:
        return matched_files
    
    


def save_file(file):
    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    os.makedirs(app.config['BIN_UPLOAD_FOLDER'], exist_ok=True) # TODO: Magari farlo in avvio del server
    filepath = os.path.join(app.config["BIN_UPLOAD_FOLDER"], filename)
    session["FILEPATH"] = filepath
    session["FILENAME"] = filename
    file.save(filepath)
    
    

    
    

