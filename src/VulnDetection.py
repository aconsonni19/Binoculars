import angr
import claripy
from enum import Enum
from angr import SimValueError

# A list of potentially dangerous functions
dangerous_functions = [
    # Input functions
    "gets", "getc", "getchar", "getwd", "fgets", "read",
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

    # Network or file IO (depending on context)
    "recv", "recvfrom", "readlink", "open",

    # Misc
    "gets_s",
    "strtok",
    "setenv", "putenv",
    "__builtin___sprintf_chk", "__builtin___memcpy_chk",  # GCC builtins with overflow potential
]


class VulnDetection:
    """
    This class implements the "VulnDetect" detection of buffer overflows that can overwrite the istruction pointer .
    A detailed description of the analysis method can be found in the associated paper:
    (https://ieeexplore.ieee.org/document/10271194)
    """

    def __init__(self, binary_path: str):
        """
        Constructor for the VulnDetection class
        :param binary_path: the path of the binary to analyze
        """
        # TAG for debugging purposes
        self.TAG = "[VulnDetect]"
        # Initialize the project
        self.project = angr.Project(binary_path, auto_load_libs = False)

        # Create the Control Flow Graph (CFG) for the binary
        self.CFG = self.project.analyses.CFGEmulated(keep_state = True)
        # Create the Control Dependence Graph (CDG) for the binary
        self.CDG = self.project.analyses.CDG(cfg = self.CFG)
        # Create the Data Dependence Graph (DDG) for the binary
        self.DDG = self.project.analyses.DDG(cfg = self.CFG)
        # List to hold the points where the vulnerable functions are called
        self.unsafe_call_points = []
        # List to hold the backward slicing results
        self.backward_slicing_results = []

    def __static_analysis(self):
        """
        This function implements the static analysis module of VulnDetect
        """
        # Get the Procedure-Linkage-Table (PLT)
        plt = self.project.loader.main_object.plt

        for function in dangerous_functions:
            try:
                # Get the function address from the PLT
                unsafe_function_addr = plt[function]
                # Get all the nodes whose address matches the unsafe function one
                unsafe_nodes = self.CFG.model.get_all_nodes(unsafe_function_addr)
                for node in unsafe_nodes:
                    # Get the list of dangerous functions call point address from the precursors nodes
                    for predecessor in node.predecessors:
                        if predecessor is not None and isinstance(predecessor, angr.analyses.cfg.cfg_base.CFGNode):
                            code_location = angr.code_location.CodeLocation(predecessor.addr, None)
                            self.unsafe_call_points.append(code_location)
            except KeyError:
                continue

        if not self.unsafe_call_points:
            print(f"{self.TAG} No unsafe call points found — nothing to slice.")
            return

        print(f"{self.TAG} Found dangerous function call points: {self.unsafe_call_points}")

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

    def __vulnerability_detection(self, stdin_input_len: int, max_depth: int, num_of_argv_inputs: int, length_of_argv_inputs: list, ):
        """
        This function implements the vulnerability detection module of VulnDetect
        :param stdin_input_len The length of the symbolic input that will be passed to the binary via stdin
        :param max_depth Maximum depth of the exploration
        :param num_of_argv_inputs The number of command line arguments to pass to the binary
        :param length_of_argv_inputs The length of the various command line arguments
        """

        vulnerable_states = []
        for program_slice in self.backward_slicing_results:
            # Create a symbolic input of stdin_input_len bytes
            stdin_sym_input = claripy.BVS("stdin_input", stdin_input_len * 8)

            # Initialize symbolic command line arguments
            argv_inputs = [self.project.filename]
            for i in range(num_of_argv_inputs):
                argv_inputs.append(claripy.BVS(f"argv_input_{i+1}", length_of_argv_inputs[i]))

            # Create the initial state of the binary
            init_state = self.project.factory.entry_state(stdin = stdin_sym_input, args = argv_inputs)
            # Get the sensitive point address
            target = program_slice["target"]
            # Create a simulation manager instance
            simgr = self.project.factory.simulation_manager(init_state, save_unconstrained = True)

            # Start symbolic execution in order targeting the sensitive point:
            simgr.explore(find = int(target, 16))

            # If the relevant state is found, make active only that state
            if simgr.found is not None:
                simgr.drop(stash = "active")
                simgr.move(from_stash = "found", to_stash = "active")

            counter = 0
            while len(simgr.unconstrained) == 0 and counter <= max_depth:
                counter += 1
                simgr.step() # Execute one step of symbolic execution

            if len(simgr.unconstrained) > 0:
                vulnerable_states.append((simgr.unconstrained[0], target))
        return vulnerable_states


    def analyze(self, stdin_input_len: int, max_depth: int, num_of_argv_inputs: int, length_of_argv_inputs: list):
        """
        This function starts the analysis and returns its results
        """
        # Execute static analysis on the binary
        self.__static_analysis()
        # Get the vulnerable states using symbolic execution
        vulnerable_states = self.__vulnerability_detection(stdin_input_len, max_depth, num_of_argv_inputs, length_of_argv_inputs)

        response = dict()
        for state_tuple in vulnerable_states:
            state = state_tuple[0]
            addr = state_tuple[1]
            # Get the instruction pointer
            ip = state.regs.ip
            # Create a junk address the size of the IP
            target_junk_addr = b"A" * (ip.size() // 8)

            # Check if the program counter can point to the junk address
            if state.satisfiable(extra_constraints = [state.regs.ip == target_junk_addr]):
                response[f"{addr}"] = {
                    "Vulnerability_found": "CWE-121: Stack-based buffer overflow",
                    "Description": "A potential instruction pointer hijack by user input was detected",
                }
        return response

#v = VulnDetection("/home/spitfire/Scrivania/University/Tesi/Binoculars/flaskr/tmp/primality_test")
#v = VulnDetection("/home/spitfire/Scrivania/University/Tesi/Binoculars/flaskr/tmp/ahgets1-bad")

# print(v.analyze(2000, 1000, 0, []))
