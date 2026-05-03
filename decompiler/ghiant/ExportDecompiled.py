# Decompile every function and write each to a .c file under the given output dir.
# @category Export
# @runtime Jython

import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def safe(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def main():
    args = getScriptArgs()
    if len(args) < 1:
        print("ExportDecompiled: missing output directory argument")
        return

    out_dir = args[0]
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    total = len(funcs)
    print("ExportDecompiled: %d functions to process" % total)

    written = 0
    skipped = 0
    for func in funcs:
        if func.isThunk() or func.isExternal():
            skipped += 1
            continue

        addr = func.getEntryPoint().toString()
        fname = "{}_{}.c".format(safe(func.getName()), addr)
        path = os.path.join(out_dir, fname)

        result = decomp.decompileFunction(func, 60, monitor)
        if result is None or not result.decompileCompleted():
            skipped += 1
            continue

        code = result.getDecompiledFunction().getC()
        f = open(path, "w")
        try:
            f.write(code)
        finally:
            f.close()
        written += 1

    decomp.dispose()
    print("ExportDecompiled: wrote %d, skipped %d" % (written, skipped))


main()
