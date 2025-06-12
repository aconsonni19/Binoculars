These are notes taken from the angr documentation
# Introduction:

- The first action to perform in angr is to load the binary:
```python
import angr
proj = angr.Project("<Binary path>")
```
- A project is like the "entry point" of the angr framework; almost every
  analysis and object depends on its existence

- A project has the following basic properties:
    - **arch**: it's an istance of an `archinfo.Arch` object for wichever architecture the binary is compiled for.
    - **entry**: it's the entry point of the binary (as an address)
    - **filename**: it's the absolute filename of the binary (basically, it's path)

- To get from a binary to its represetantion, angr uses a module calle **CLE**; which result, calle the **loader**, is available in the `.loader` property of a prject. We can use it to see the shared libraries that angr loaded alongside the program and to perform basic queries about the loaded address space

## Factories
- Most of the classes in angr require a project to be instantiated. To avoid passing the project every time, angr provides `project.factory`, which has several convenient constructors for common objects 

- First, we have `project.factory.block()`, which is used to extract a basic block of code from a given address. angr analysis code in units of basic blocks. The method returns a `Block` object

- The project object only represents an "initialization image" for the program. When performing an execution with angr, we're working with a "simulated program state" - a `SimState` object; wich can be obtained with `state = project.factory.entry_state()`. A simstate contain a program's memory, registers, filesystem data... any "live data" that can be changed by execution. We can, for example see the contents of a register using `state.regs.<register>` or the memory using `state.mem[<address>].int.resolved` (this prints out the memory at the entry point as a C integer)
- It is important to note that in angr the values of the CPU and the memory aren't representend by python ints but by **bitvectors**, which can be tought of as integers represented by a series of bits. Each bitvector has a .length property describing how wide it is in bit. We can convert bitvectors to ints and viceversa:
```python
bv = claripy.BVV(0x1234, 32) # BVV = BitVector Value; this converts int to bitvector
state.solver.eval(bv) # This converts bitvectors to int
```
- The `mem` interface should be used as follows:
    - Use `array[index]` notation to specify an address
    - Use `.<type>` to speicify that the memory should be interpreted as `type` (es. char, int, long, ...)
    - From there, we can either:
        - Store a value to it, either a bitvector or a python int
        - Use `.resolved` to get the value as bitvectors
        - Use `.concrete" to get the value as a python int

## Simulation managers
- A state lets us represent a program at a given point in time
- A **simulation manager** is the primary interface in angr for performing execution and simulation.
- We have fist to create a simulation manager; the constructor can take a single state or a list of states
```python
simgr = proj.factory.simulation_manager(state)
```
- A simulation manager can contain several "stashes" of states: the **default stash**, `active`, is initialized with the state we passed in.
- We can get to the next state with `simgr.step()`; with this, we executed symbolically a single basic block. After this call, the `active` stash is updated to the next basic blox. The `step` does not modify the original state, `SimState` objects are treated as immutable by execution.

# CLE Loads Everything (CLE)
- The component that allow angr to load a binary is **CLE**, which stands for
"**CLE Loads Everything**".
- The CLE loader `cle.Loader` represents an entire conglomerate of loaded `binary objects`, loaded and mapped into a single memory space. Each binary
object is loaded by a loader backend that can handle its filetype (ELF ecc...)
- There are also objects in memory that don't correspond to any loaded binary; for example an object used to provide thread local storage support.
- With `loader.all_objects` we can get the full list of objects that CLE has loaded. We can interact directly with these objects to extract metadata from them (like min address or max address, entry point ecc...)

## Symbols and Relocations
- A **symbol** maps a name to an address
- We can get a symbol from CLE using `loader.find_symbol("<symbol_to_search>")`; wich takes either a name or an address a returns a `Symbol` object
- The most useful atributes on a symbol are its name, its owner and its address; altough the "address" of a symbol can be ambigous. The `Symbol` object has three ways of reporting its address:
  - .`rebased_addr`: address in the global address space
  - `.linked_addr`: its address relative to the prelinked base of the binary. This is the address shown in `readelf(1)`
  - `.relative_addr`: is its address relative to the object base
- Symbols also support the notion of dynamic linking. `libc` provides the strcmp symbol, for example, as an `export`; so, if we ask CLE to give us a `strcmp` symbol from the main object directly, it'll tellus that is an `import symbol`; which do not have meaningful addresses associated with them, but they do provide a reference to the symbol that was used to resolve them through the property `.resolvedby`
- The specific way that the links between imports and exports should be registered in memory are handled by another notion called `relocation`. Essentially, a reolcation says "**when you match an import up with an export symbol, please write the export's address to [location], formatted as [format]**"
- We can see the full list of relocations for an object (as `Relocation` instances) as `obj.relocs`, or just a mapping from symbol to relocation with `obj.imports`
- A relocation's corresponding import symbol can be accessed as `.symbol`. The address the relocation will write to is accessibile through any of the address identifiers you can use for `Symbol` and we can get a reference to the object requesting the relocation with `.owner`
- If an import cannot be resolved by an export, CLE will automatically update the `externs` object (`loader.externs_obj`) to claim it provides the symbol as an export
## Loading options
- `Project()` creates implicitly an instance of `cle.Loader`
- We can pass directly as arguments the options with wich we want to load the binary:
  - `auto_load_libs`: if shared libraries (like `libc`) should be loader
  - `except_missing_libs`: causes an exception wheneaver a binary has shared libraries that cannot be resolved
  - `force_load_libs`: everything contained in this list will be treated as an unresolved shared library dependency
  - `skip_libs`: prevents any library in the list from being resolved as a dependency
  - `ld_path`: The string/s passed to this argument will be treated as additional search paths for shared libraris
  - We can specify options that apply only to a single binary object with `main_opts` and `lib_opts`, which take dictionaries of options:
    - `backend`: which backend to use, as either a class or a name
    - `base_addr`: a base address to use
    - `entry_point`: an entry point to use
    - `arch`: the name of the architecture to use

## Symbolic Functions Summaries
- `Project` tries to replace external calls to library functions
with symbolic summaries calld `SimProcedures`: python functions that imitate
the library function's effect on the state.
- Built-in `SimProcedures` are available in the `angr:SIM_PROCEDURES` dictonary wich is two-leveled, keyed first on
the packane name (libc, posix, win32, stubs) and then on the name of the function.
The execution of `SimProcedures` makes the analysis faster but more inaccurate.
- When no such summary is available:
  - If `auto_load_libs` is `True`, then the real library function is executed instead. This could cause an explosion in the number of states to be explored
  - If `auto_load_libs` is `False` then external functions are **unresolved** and `Project` will resolve them with **generic stubs** `SimProcedures` called `ReturnUncostrained`: a unique
  uncostrained value
  - If `use_sim_procedures` (a parameter to `angr.Project`) is `False` then only symbols provided by the extern object will be replaced with `SimProcedures` by a stub `ReturnUncostrained`
  - `exclude_sim_procedures_list` lets us exclude specific symbols from being replace with `SimProcedures`
- The mechanism by which angr replaces library code with a python summary is called **hooking**
- When performing a simulation, at every step angr check if the current address has benn hooked, and if so, runs the hook instead of the binary code of the addres.

# Symbolic Expressions and Constraint Solving
- angr is able to execute programs with **symbolic variables**. Instead of saying that a variable has a concrete numerical value, we can say
that it holds a **symbol**, which is just a name. Performing arithmetic operations with that variable will yield a **tree of operations** called an **Abstract Syntax Tree (AST)**.
ASTs can be translated into **constrains** for an SMT solver.

## Working with Bitvectors
- A bitvector is just a sequence of bits, interpreted with the semantics of a **bounded integer** for arithmetic. We can perform mathematical operations on bitvectors.
- It is a type error to perform an operation on bitvectors with different lengths. We can however extend one of the bitvectors so it has an approprieate number of bits with `.zero_extend()`; which will
pad the bitvectors on the left with the given number of zero bits. We can also use `.sign_extend()` to pad with a duplicate of the highest bit, preserving the value of the bitvector under two's complement signed integer semantics.
- We can create symbolic variables like this:
```python
claripy.BVS("x", 64)
claripy.BVS("y", 64)
```
- `x` and `y` are now symbolic variables. We can do arithmetic with them, but we'll get an AST as a result.
- Any bitvector is a **tree of operations**
- Each AST has a `.op` and a `.args`. The op is a string naming the operation being performed, and the args are the values the operation takes as input. Unless the op is `BVV` or `BVS` (or a few others), the args are **all other ASTs**.
The tree eventually terminates with `BVV` or `BVS`

## Symbolic Constraints
- Performing comparison operations between any two similary-typed ASTs will yield another AST: a **symbolic boolean**
- The comparisons are unsigned by default; they can be coarced, however, to be signed
- Never directly use a comparison between symbolic variables in the condition for an if or while statement: the answer might not have a concrete truth value.
Use `solver.is_true` and `solver_is_false`, which test for conrete truthness/falseness without performing a constraint solve

## Constraint Solving
- We can treat any symbolic boolean as an assertion about the valid values of a symbolic variable by adding it as a **constraint to the state**.
We can then query for a valid value of a symbolic variable by asking for an evaluation of a symbolic expression.
```python
state.solver.add(x > y)
state.solver.add(y > 2)
state.solver.add(10 > x)
state.solver.eval(x)
```
- Adding these constrains to the state, we've force the constraint solver to consider them as
assertions that must be satisfied about any values it returns.
- If we add conflicting or contradictory constraints, such that there are no values that can be assigned
to the variables such that the constraints are satisfiable, the state becomes **unstatisfiable** and queries against it
will raise an exception. We can check the satisfiability of the state with `state.satisfiable()`.
- We can evaluate more complex expressions, not only single variables.

## Floating point numbers
- z3 has support for the theory of IEEE754 floating point numbers, and so angr can use them as well.
- The main difference is that instead of a width, a floating point number has a sort.
- We can create floating point numbers with `FPV` and `FPS`:
```python
a = claripy.FPV(3.2, claripy.fp.FSORT_DOUBLE)
```
- Most operations with floating point numbers have an implicit third argument: the **rounding mode**. We can specify
a rounding mode in any operation with `claripy.fp.RM_<mode>` as the first argument
- Constraint and solving work in the same way for floating point numbers
- We can interpret floating point as bitvectors and viceversa with `raw_to_bv` and `raw_to_fp`. These conversions preserve the bit pattern
- To have a more accurate conversion, we can use `val_to_fp` and `val_to_bv`; these method require the size or sort of the target value as a parameter. These method can also take a `signed` parameter
- `solver` provides several methods for common solving patterns:
  - `solver.eval(expressions)`: gives one possible solution
  - `solver.eval_one(expressions)`: gives the solution or throws an exception if there are more than one solution
  - `solver.eval_upto(expressions, n)`: given `n` solutions; throws an error if fewer than `n` solutions exists
  - `solver.eval_atleast(expressions, n)`: gives `n` solutions; throws an error if fewer than `n` are possible
  - `solver.eval_exact(expressions, n)`: gives `n` solutions; throws an error if there aren't exactly `n` solutions
  - `solver.min(expressions)`: gives the minimum possible solution to the given expression
  - `solver.max(expressions)`: gives the maximum possible solution to the given expression

- The methods above can take the following keyword arguments:
  - `extra_constraints`: a tuple of constraints; they will be taken into account for this evaluation but will not be added to the state
  - `cast_to`: casts the result to the given data type. Can only be `int` and `bytes`

# Machine state, memory, registers
- `state.regs` provides read and write access to the registers through attributes with the name of each register
- `state.mem` provides typed read and write acesss to memory with index-access notation to specify the address followed by an attribute access to specify the type with wich to interpret the memory as
- Any bitvector-typed AST can be stored in registers or memory

## Basic execution
- `state.step()` will perform one step of symbolic execution and return an objcet called `angr.engines.successors.SimSuccessors`.
- Symbolic execution can produce several successor states that can be classified in a number of ways. The `.successors` property of this object is a list containing all the "normal" successors of a given step
- Generation of successor states is perfomed whenever there's a branch in the execution of the program
- angr treats the standard input as an infinite stream of symbolic data
- We can use `state.posix.stdin.load()` to get a bitvector representing all the contend read from stdin so far

## State Presets
 - The project factory exposes seveeal state constructors:










