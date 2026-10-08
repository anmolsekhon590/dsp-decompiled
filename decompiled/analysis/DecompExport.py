# Ghidra headless post-script: decompile exported functions by name list.
# @category Analysis
# @runtime Jython
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

TARGETS = os.environ.get("GHIDRA_TARGETS","ExtractLZMAFiles,FindEXE,ExpandExtractionPath,DeleteExtractionPath,DeleteLZMAFiles")
targets = set(TARGETS.split(","))
outpath = os.environ.get("GHIDRA_OUT","/tmp/lzma_decomp.txt")

di = DecompInterface()
di.openProgram(currentProgram)
mon = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()
out = []
for fn in fm.getFunctions(True):
    n = fn.getName()
    if n in targets:
        r = di.decompileFunction(fn, 120, mon)
        if r.decompileCompleted():
            out.append("===== %s @ %s =====" % (n, str(fn.getEntryPoint())))
            out.append(r.getDecompiledFunction().getC())
        else:
            out.append("===== %s (decompile failed) =====" % n)
open(outpath, "w").write("\n".join(out))
print("WROTE %s len=%d" % (outpath, len("\n".join(out))))
