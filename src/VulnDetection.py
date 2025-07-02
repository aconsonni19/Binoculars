import angr
import claripy
from enum import Enum

"""
This module implements the technique "VulnDetection" specified in paper "Buffer Overflow Vulnerability Detection Besd
on Static Analysis-assisted Symbolic Execution
(https://ieeexplore.ieee.org/document/10271194)
"""

class InputMethod(Enum):
    STDIN = 1,
    ARGV = 2,
    STDIN_AND_ARGV = 3

class VulnDetection:
    def __init__(self, binary_path: str, input_method: InputMethod):
        self.project = angr.Project(binary_path, auto_load_libs = False)

        self.input_method = input_method

        self.CFG = self.project.analyses.CFGEmulated(keep_state = True)

        self.CDG = self.project.analyses.CDG(cfg = self.CFG)

        self.DDG = self.project.analyses.DDG(cfg = self.CFG)

        self.dangerous_functions = [
            # Input functions
            "gets", "getchar", "getwd", "fgets", "read",
            "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",

            # String copying functions (no bounds checking)
            "strcpy", "stpcpy", "wcscpy", "memcpy", "wmemcpy", "strncpy", "wcsncpy",

            # String concatenation functions
            "strcat", "wcscat", "strncat", "wcsncat",

            # Output functions (can be format string vulnerable)
            "sprintf", "vsprintf", "snprintf", "vsnprintf", "fprintf", "vfprintf", "printf",

            # Memory handling
            "memmove", "bcopy", "alloca",

            # Path handling
            "realpath", "tempnam", "tmpnam", "mktemp", "mkstemp",

            # System/command execution (RCE risk)
            "system", "popen", "execv", "execl", "execvp", "execve", "execlp", "execle",

            # Network or file IO (depending on context)
            "recv", "recvfrom", "readlink", "open",

            # Misc
            "gets_s",  # not always dangerous, but needs care
            "strtok",  # not thread-safe
            "setenv", "putenv",  # can be abused in some contexts
            "__builtin___sprintf_chk", "__builtin___memcpy_chk",  # GCC builtins with overflow potential
        ]

        self.unsafe_call_points = []

        self.backward_slicing_results = []

    def __static_analysis(self):
        plt = self.project.loader.main_object.plt

        for function in self.dangerous_functions:
            try:
                unsafe_function_addr = plt[function]
                unsafe_nodes = self.CFG.model.get_all_nodes(unsafe_function_addr)
                for node in unsafe_nodes:
                    for predecessor in node.predecessors:
                        if predecessor is not None and isinstance(predecessor, angr.analyses.cfg.cfg_base.CFGNode):
                            code_location = angr.code_location.CodeLocation(predecessor.addr, None)
                            self.unsafe_call_points.append(code_location)
            except KeyError:
                continue

        print(f"Found dangerous functions: {self.dangerous_functions}")

        if not self.unsafe_call_points:
            print("No unsafe call points found — nothing to slice.")
            return

        for location in self.unsafe_call_points:
            # Perform backward slicing
            bs = self.project.analyses.BackwardSlice(
                self.CFG,
                self.CDG,
                self.DDG,
                [location]
            )

            result = {
                "target": hex(location.block_addr),
                "slice": bs
            }
            self.backward_slicing_results.append(result)


    def __vulnerability_detection(self, input_len: int, max_depth: int):

        for program_slice in self.backward_slicing_results:
            sym_input = claripy.BVS("argv_input", input_len * 8)

            init_state = self.project.factory.entry_state(stdin = sym_input)

            target = program_slice["target"]

            simgr = self.project.factory.simulation_manager(init_state)

            simgr.explore(find = int(target, 16))

            if simgr.found is not None:
                simgr.drop(stash = "active")
                simgr.move(from_stash = "found", to_stash = "active")

            counter = 0
            while len(simgr.unconstrained) == 0 and counter <= max_depth:
                counter += 1
                simgr.step()
            vul_states = simgr.unconstrained
            return  vul_states
        return None


    def __is_pc_hyjackable(self, state: angr.SimState):
        # Get the instruction pointer
        ip = state.regs.ip
        # Create a junk address the size of the IP
        target_junk_addr = b"A" * (ip.size() // 8)

        # Check if the program counter can point to the junk address
        return True if state.satisfiable(extra_constraints = [state.regs.ip == target_junk_addr]) else False


    def analyze(self):
        self.__static_analysis()
        vuln_states = self.__vulnerability_detection(2000, 1000)

        for vuln_state in vuln_states:
            if self.__is_pc_hyjackable(vuln_state):
                return vuln_state
        return None




v = VulnDetection("/home/spitfire/Scrivania/University/Tesi/Binoculars/flaskr/tmp/primality_test", InputMethod.STDIN)

v.analyze()









