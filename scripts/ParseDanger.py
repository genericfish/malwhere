import os
import re
import sys
import subprocess
import time
import json



# Make the nodes in the BFS control flow algorithm have a visited option
# That way it will be resistant to recursion
# https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
from ghidra.program.flatapi import FlatProgramAPI

# # https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

# # https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/package-summary.html
from ghidra.app.decompiler import *

# #https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html
from ghidra.program.model.pcode import PcodeOp

def getListOfFunctions():
    listofFuncs =[]
    function = getFirstFunction()
    while function is not None:
        listofFuncs.append(str(function.getName()))
        function_address = function.getEntryPoint()
        function = getFunctionAfter(function)
        
    return listofFuncs

def FunctionsAddressDict():
    funcDict = {}
    function = getFirstFunction()
    while function is not None:
        functionName = str(function.getName())
        functionAddress = function.getEntryPoint()
        funcDict[functionName] = functionAddress
        function = getFunctionAfter(function)
    return funcDict

def FunctionsVisitedDict():
    funcDict = {}
    function = getFirstFunction()
    while function is not None:
        functionName = str(function.getName())
        funcDict[functionName] = 0 # Where zero represents not visited 
        function = getFunctionAfter(function)
    return funcDict

def decompiledCurrentFunctionString(funcString="", currentFunctionArg=""):
    prog = FlatProgramAPI(currentProgram, monitor)
    decomp = FlatDecompilerAPI(prog)

    currentFunction = prog.getFunctionContaining(currentAddress)
    if currentFunctionArg != "":
        currentFunction = currentFunctionArg

    
    if funcString != "":
        funcAddressDict = FunctionsAddressDict()
        funcAddress = funcAddressDict[funcString]
        currentFunction = prog.getFunctionContaining(funcAddress)
        
    if currentFunction is None:
        print("Error: No function found at address " + str(currentAddress))
        exit()
        
    decomp.initialize()
    decompIfc = decomp.getDecompiler()

    DecompiledFunction = decompIfc.decompileFunction(currentFunction, 30, monitor)
    
    if DecompiledFunction.decompileCompleted():
        DecompiledString = str(DecompiledFunction.getCCodeMarkup())
        decomp.dispose()
        return DecompiledString
    else:
        decomp.dispose()
        return "ERROR"

def getCalledFuncsNamesInDecompiledCode(funcStr):
    patternFull = r'\b\w+\s*\([^)]*\);'
    matchesFull = re.findall(patternFull, funcStr)
    patternName = r'\b(\w+)\s*\([^)]*\);'
    matchesName = re.findall(patternName, funcStr)
    
    verifiedMatchesName = []
    listOfFunctions = getListOfFunctions()
    
    cominedList = zip(matchesFull, matchesName)
    VerfiedCombined = []
    for funcNames in cominedList:
        if funcNames[1] in listOfFunctions:
            verifiedMatchesName.append(funcNames[1])
            VerfiedCombined.append(funcNames)

    return [VerfiedCombined, verifiedMatchesName]
    

def getFunctionFlow(DecompiledFuncStr, depth, visitedDict, FuncData, functionsDict):
    while len(getCalledFuncsNamesInDecompiledCode(DecompiledFuncStr)[1]) > 0:
        for calledFuncName in getCalledFuncsNamesInDecompiledCode(DecompiledFuncStr)[0]:
            
            DecompiledFuncStr = decompiledCurrentFunctionString(calledFuncName[1])
            if visitedDict[calledFuncName[1]] == 0:
                visitedDict[calledFuncName[1]] = 1
                
                for key in functionsDict.keys():
                    for value in functionsDict[key]:
                        if value in DecompiledFuncStr:
                            FuncData[key].append(str(calledFuncName[1]) + ":" + value)
                
                getFunctionFlow(DecompiledFuncStr,depth+1, visitedDict, FuncData, functionsDict)
                
            else:
                return

#Print my control Flow, Will prob use this in conjunction with the write decompiled file above for a
#clickable HTML map that will display the program when clicked
print("test:\n\n\n\n\n\n")
# print(getListOfFunctions())
print(FunctionsAddressDict())
programAddress = FunctionsAddressDict()["main"]
print(programAddress)
# currentAddress = programAddress

prog = FlatProgramAPI(currentProgram, monitor)
decomp = FlatDecompilerAPI(prog)
currentFunction = prog.getFunctionContaining(programAddress)

output_dir = os.environ.get("MALWHERE_ANALYSIS_PATH", os.path.dirname(os.path.realpath(__file__)))
prog_name = prog.getProgramFile().getName() if prog.getProgramFile() else "ast"

functions_file = os.environ.get("MALWHERE_FUNCTIONS", os.path.join(os.path.dirname(os.path.realpath(__file__)), "functions.json"))

FuncData = {"Network": [], "Privileges Escalation": [], "Configuration Changes": [], "Download, Compile, or Execute": [], "Encryption": []}
with open(functions_file, "r") as file:
    functionsDict = json.load(file)
    print(functionsDict)
    
DecompiledFuncStr = decompiledCurrentFunctionString(currentFunctionArg=currentFunction)
depth = 2
visitedDict = FunctionsVisitedDict()
getFunctionFlow(DecompiledFuncStr, depth, visitedDict, FuncData, functionsDict)
with open(os.path.join(output_dir, "{}_danger.json".format(prog_name)), "w") as file:
    json_object = json.dumps(FuncData, indent=4)
    file.write(json_object)

