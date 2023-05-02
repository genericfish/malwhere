
from ghidra.app.decompiler import DecompInterface

execfile("scripts/RemoveEmptyFunctions.py")


decomp = DecompInterface()


decomp.openProgram(currentProgram)


fn = getFirstFunction()


file = open("ghidra/output/decompiled_code.txt", "w")

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
file.close()