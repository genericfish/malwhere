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
        tokenType = re.search(r'\.Clang(\w+)\'', str(type(clang_token))).groups()[0]
        tokenType = tokenType.replace("Token", "")

        self.type = tokenType
        self.value = str(clang_token)

        if (type(clang_token) == ClangCommentToken):
            return

        self.props = {}

        min_address = clang_token.getMinAddress()
        if min_address:
            self.props["min-address"] = str(min_address)

        max_address = clang_token.getMaxAddress()
        if max_address:
            self.props["max-address"] = str(max_address)

        if type(clang_token) == ClangVariableToken:
            varnode = clang_token.getVarnode()
            high = clang_token.getHighVariable()

            if varnode:
                if varnode.isConstant():
                    self.props["const"] = True

                address = varnode.getPCAddress()
                if address:
                    self.props["var-address"] = str(address)

                if high and high.getSymbol():
                    storage = high.getSymbol().getStorage()
                    self.props["var-storage"] = str(storage)

            if high:
                self.data_type = high.getDataType().getDisplayName()


        if type(clang_token) == ClangFuncNameToken:
            # "ClangFuncNameToken unused field hfunc"
            # https://github.com/NationalSecurityAgency/ghidra/issues/1983
            # Alternative: Get address via pcode
            pcode = clang_token.getPcodeOp()

            if pcode and pcode.getOpcode() == PcodeOp.CALL:
                func_ptr = pcode.getInput(0).getAddress()
                self.props["func-address"] = str(func_ptr)

        if isinstance(clang_token, ClangToken):
            pcode = clang_token.getPcodeOp()

            if pcode:
                self.pcode = str(pcode)

        if not self.props:
            del(self.props)


class Function(object):
    def __init__(self, func, flat_ast):
        self.name = func.getName()
        self.namespace = func.getParentNamespace().getName(True)

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
            entry = currentFunction.getEntryPoint()
            tokens = []
            clangAST.flatten(tokens)
            print("[C3] Decompiled {}".format(currentFunction.getName()))

            functions[str(entry)] = Function(currentFunction, tokens)

        currentFunction = prog.getFunctionAfter(currentFunction)

    output_dir = os.environ.get("MALWHERE_ANALYSIS_PATH", os.path.dirname(os.path.realpath(__file__)))
    print("[C3] Output directory {}".format(output_dir))

    prog_name = prog.getProgramFile().getName() if prog.getProgramFile() else "ast"

    with open(os.path.join(output_dir, "{}.json".format(prog_name)), 'w') as funcFile:
        funcFile.write(json.dumps(functions, default=lambda o: o.__dict__, sort_keys=False))

    decomp.dispose()
