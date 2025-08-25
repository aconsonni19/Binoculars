import sys
import json
import jpype
import pyghidra
from pyghidra.launcher import HeadlessPyGhidraLauncher
import os
import tempfile


filepath = sys.argv[1]
install_dir = sys.argv[2]

project_dir = tempfile.mkdtemp(prefix = "ghidra_proj_")

pyghidra.start(install_dir = install_dir)

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

results = []

with pyghidra.open_program(filepath, project_location = project_dir) as flat_api:
    program = flat_api.getCurrentProgram() # Get the program being analyzed
    listing = program.getListing() # Get the program listing of the symbols
    decompiler = FlatDecompilerAPI(flat_api) # Get a FlatDecompilerAPI reference to the Ghidra decompiler
    
    for functions in listing.getFunctions(True):
        decompiled_code = decompiler.decompile(functions) # Decompile the function
        
        if decompiled_code:
            # Cleanup the empty lines
            filtered_lines = [line for line in decompiled_code.splitlines() if line.strip() != ""]
        
            results.append({
                "functions": functions.getName(),
                "code": "\n".join(filtered_lines)
            })
            
print(json.dumps(results))    
