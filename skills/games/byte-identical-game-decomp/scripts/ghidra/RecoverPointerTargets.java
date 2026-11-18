// Headless Ghidra script: scan initialized non-executable memory for runs of >= 2 aligned dwords that point
// into executable memory (C++ vtables, callback tables), and create a function at every target that is not
// already inside a function or defined data. Targets inside an existing function body are left alone (they
// are SEH funclets or jump-table cases).
// In a PE with relocations only dwords at relocation sites count: a real pointer is always relocated, while
// text is not - UTF-16 strings ("M\0C\0" = 0x0043004D) and other data look like addresses inside a large
// .text (joan.exe: 91 one-byte "functions" on int3 filler). Without relocations every dword counts, but a
// target on an int3 (CC) filler byte is never a function start.
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class RecoverPointerTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        FunctionManager fm = currentProgram.getFunctionManager();
        Listing l = currentProgram.getListing();
        List<MemoryBlock> exec = new ArrayList<>();
        for (MemoryBlock b : mem.getBlocks()) if (b.isExecute() && b.isInitialized()) exec.add(b);
        Set<Address> targets = new TreeSet<>();
        int tables = 0;
        Set<Long> sites = new HashSet<>();
        java.util.Iterator<ghidra.program.model.reloc.Relocation> ri = currentProgram.getRelocationTable().getRelocations();
        while (ri.hasNext()) {
            ghidra.program.model.reloc.Relocation r = ri.next();
            if (r.getType() == 3) sites.add(r.getAddress().getOffset());   // HIGHLOW; type 0 is block padding
        }
        boolean relocated = !sites.isEmpty();
        for (MemoryBlock b : mem.getBlocks()) {
            if (b.isExecute() || !b.isInitialized()) continue;
            long n = b.getSize() / 4;
            Address base = b.getStart();
            List<Address> run = new ArrayList<>();
            for (long i = 0; i <= n; i++) {
                Address t = null;
                if (i < n && (!relocated || sites.contains(base.add(i * 4).getOffset()))) {
                    long v = mem.getInt(base.add(i * 4)) & 0xffffffffL;
                    for (MemoryBlock e : exec) if (v >= e.getStart().getOffset() && v <= e.getEnd().getOffset()) { t = toAddr(v); break; }
                }
                if (t != null) { run.add(t); continue; }
                if (run.size() >= 2) { tables++; targets.addAll(run); }
                run.clear();
            }
        }
        int created = 0, inside = 0, failed = 0, existed = 0, filler = 0;
        for (Address t : targets) {
            if (fm.getFunctionAt(t) != null) { existed++; continue; }
            if (fm.getFunctionContaining(t) != null || l.getDefinedDataContaining(t) != null) { inside++; continue; }
            if (mem.getByte(t) == (byte) 0xCC) { filler++; continue; }
            if (l.getInstructionAt(t) == null) new DisassembleCommand(t, null, true).applyTo(currentProgram, monitor);
            if (l.getInstructionAt(t) == null) { failed++; continue; }
            if (new CreateFunctionCmd(t).applyTo(currentProgram, monitor)) created++; else failed++;
        }
        analyzeChanges(currentProgram);
        println("PTRTARGETS relocations=" + sites.size() + " tables=" + tables + " targets=" + targets.size() + " existed=" + existed
                + " created=" + created + " inside_or_data=" + inside + " filler=" + filler + " failed=" + failed);
    }
}
