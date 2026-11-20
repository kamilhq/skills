// Headless Ghidra script: remove functions whose entry point lies in a non-executable memory block and clear
// the instructions there back to undefined bytes. Ghidra's own analysis can follow a data pointer into
// .rdata and disassemble embedded data as code (SDL2.dll: a pointer in .data to a compiled D3D11 shader
// blob, "DXBC", in .rdata became FUN_10112600, which then failed to decompile).
// Log: one "NONEXEC_REMOVED 0x<addr> <name> <block>" line per function, then "NONEXEC removed=N cleared=M".
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class RemoveNonExecFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> bad = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (f.isExternal() || f.isThunk() && f.getEntryPoint().isExternalAddress()) continue;
            MemoryBlock b = mem.getBlock(f.getEntryPoint());
            if (b != null && !b.isExecute()) bad.add(f);
        }
        int removed = 0; long cleared = 0;
        for (Function f : bad) {
            AddressSetView body = f.getBody();
            String name = f.getName(), blk = mem.getBlock(f.getEntryPoint()).getName();
            Address entry = f.getEntryPoint();
            fm.removeFunction(entry);
            for (AddressRange r : body) {
                MemoryBlock b = mem.getBlock(r.getMinAddress());
                if (b != null && !b.isExecute()) {
                    l.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
                    cleared += r.getLength();
                }
            }
            removed++;
            println("NONEXEC_REMOVED 0x" + entry + " " + name + " " + blk);
        }
        println("NONEXEC removed=" + removed + " cleared=" + cleared);
    }
}
