import angr
import claripy
from claripy import ClaripyOperationError


class FgetsBufferOverflowHook(angr.SimProcedure):
    def __init__(self, input_size: int):
        super().__init__()
        self.TAG = "[Hooks: fgets]: "
        self.input_size = input_size

    # Strategy:
    # 1) Create a symbolic input of length size
    # 2) Create a copy of the state
    # 3) Simulate symbolic inputs of different lengths; if one of those create a symbolic IP or overwrite, we win
    def run(self, buffer_addr, bytes_to_read, stream):
        # Get a concrete or symbolic value for the buffer_addr
        buffer_addr_val = self.state.solver.eval(buffer_addr)
        # Get a concrete value for the "bytes_to_read"
        bytes_to_read_val = self.state.solver.eval(bytes_to_read)

        # Get stack pointer and base pointer address
        sp_addr = self.state.solver.eval(self.state.regs.sp)
        bp_addr = self.state.solver.eval(self.state.regs.bp)

        # Check if the buffer is on the stack with an heuristic approach
        # TODO: Implement a more robust check; this is pretty loose
        if sp_addr <= buffer_addr_val <= bp_addr:
            print(f"{self.TAG}Buffer is on the stack; saving symbolic input at the stack address...")
            sym_input = claripy.BVS("input", self.input_size)
            self.state.memory.store(buffer_addr_val, sym_input)
        else:
            print(f"{self.TAG}The buffer is not on the stack; skipping analysis")
        return buffer_addr