import os

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface

execfile("scripts/RemoveEmptyFunctions.py")


decomp = DecompInterface()


decomp.openProgram(currentProgram)


fn = getFirstFunction()

prog = FlatProgramAPI(currentProgram, monitor)
output_dir = os.environ.get("MALWHERE_ANALYSIS_PATH", os.path.dirname(os.path.realpath(__file__)))
prog_name = prog.getProgramFile().getName() if prog.getProgramFile() else "ast"
with open(os.path.join(output_dir, "{}_decompiled_code.txt".format(prog_name)), "w") as file:
    while (not fn is None) and (not fn.isExternal()) and (not fn.isGlobal()):
        # print(fn.isGlobal())

        decomp_results = decomp.decompileFunction(fn, 30, monitor)

        if decomp_results.decompileCompleted():

            n = decomp_results.getDecompiledFunction().getC()

            
            file.write(n)
            file.write("\n--------------------------------------------------------------------------\n")
            
            # print(n)
        else:
            print("There was an error in decompilation!")

        fn = getFunctionAfter(fn)
