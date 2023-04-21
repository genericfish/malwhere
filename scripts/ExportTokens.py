# Exports tokens into "ast.json"

# @category: C3
# @author: Team 7.1

import os
import json
import re

# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

#https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html
from ghidra.program.model.pcode import PcodeOp


class ASTNode(object):
    def __init__(self, clang_token):
        self.type = re.search(r'\.Clang(\w+)\'', str(type(clang_token))).groups()[0]

        self.value = str(clang_token)

        min_address = clang_token.getMinAddress()
        max_address = clang_token.getMaxAddress()

        if min_address:
            self.min_address = str(min_address)

        if max_address:
            self.max_address = str(max_address)

        if type(clang_token) == ClangVariableToken:
            high = clang_token.getHighVariable()

            if high:
                high_symbol = high.getSymbol()

                if high_symbol:
                    self.var_address = str(high_symbol.getPCAddress())

        if isinstance(clang_token, ClangToken):
            pcode = clang_token.getPcodeOp()

            if pcode:
                self.pcode = str(pcode)


class Function(object):
    def __init__(self, func, flat_ast):
        self.simpleName = func.getName()
        self.namespace = func.getParentNamespace().getName(True)
        self.entry = func.getEntryPoint().toString()

        self.tokens = [ASTNode(node) for node in flat_ast]

if __name__ == "__main__":
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)

    decomp.initialize()
    decompIfc = decomp.getDecompiler()

    functions = {}

    currentFunction = prog.getFirstFunction()
    while currentFunction:
        res = decompIfc.decompileFunction(currentFunction, 30, monitor)

        if res.decompileCompleted():
            clangAST = res.getCCodeMarkup()
            fname = currentFunction.getName()
            tokens = []
            clangAST.flatten(tokens)
            print("[C3] Decompiled {}".format(fname))

            functions[fname] = Function(currentFunction, tokens)

        currentFunction = prog.getFunctionAfter(currentFunction)

    output_dir = os.environ.get("MALWHERE_ANALYSIS_PATH", os.path.dirname(os.path.realpath(__file__)))
    print("[C3] Output directory {}".format(output_dir))

    with open(os.path.join(output_dir, "{}.json".format(prog.getProgramFile().getName())), 'w') as funcFile:
        funcFile.write(json.dumps(functions, default=lambda o: o.__dict__, sort_keys=True))

    decomp.dispose()