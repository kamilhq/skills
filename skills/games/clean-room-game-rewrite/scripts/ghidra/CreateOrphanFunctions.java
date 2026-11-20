// Headless Ghidra script: create functions for disassembled code that belongs to no function.
// Ghidra disassembles code reached through operand/data references (callbacks, function-pointer tables)
// but only makes functions for call targets. A "head" is an orphan instruction that is referenced, or
// that no previous instruction falls through into. Repeats until a round creates nothing.
// Filler is never a function: orphan filler in front of a function is cleared, and so is a function made only of
// filler that nothing calls, jumps to or points to (references from the PE header do not count).
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class CreateOrphanFunctions extends GhidraScript {
    // MSVC/assembler alignment filler: int3, nop, mov edi,edi, mov eax,eax, xchg ax,ax, lea r,[r+0] in its
    // 3/4/6/7-byte forms (any register), and the 0F 1F multi-byte NOPs. Returns the filler length at a, or 0.
    static int padLen(ghidra.program.model.mem.Memory mem, ghidra.program.model.address.Address a) {
        try {
            int[] b = new int[9];
            for (int i = 0; i < 9; i++) b[i] = mem.getByte(a.add(i)) & 0xff;
            if (b[0] == 0xCC || b[0] == 0x90) return 1;
            if (b[0] == 0x8B && (b[1] == 0xFF || b[1] == 0xC0 || b[1] == 0xC9 || b[1] == 0xD2 || b[1] == 0xDB
                    || b[1] == 0xF6)) return 2;
            if (b[0] == 0x66 && b[1] == 0x90) return 2;
            if (b[0] == 0x8D) {
                int mod = b[1] >> 6, reg = (b[1] >> 3) & 7, rm = b[1] & 7;
                if (reg == rm && rm != 4 && rm != 5 && mod == 1 && b[2] == 0) return 3;
                if (reg == 5 && rm == 5 && mod == 1 && b[2] == 0) return 3;
                if (reg == rm && rm != 4 && mod == 2 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0) return 6;
                if (b[1] == 0x64 && b[2] == 0x24 && b[3] == 0) return 4;
                if (b[1] == 0xA4 && b[2] == 0x24 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0) return 7;
            }
            int o = b[0] == 0x66 ? 1 : 0;
            if (b[o] == 0x0F && b[o + 1] == 0x1F) {
                int m = b[o + 2];
                if (m == 0x00) return o + 3;
                if (m == 0x40 && b[o + 3] == 0) return o + 4;
                if (m == 0x44 && b[o + 3] == 0 && b[o + 4] == 0) return o + 5;
                if (m == 0x80 && b[o + 3] == 0 && b[o + 4] == 0 && b[o + 5] == 0 && b[o + 6] == 0) return o + 7;
                if (m == 0x84 && b[o + 3] == 0 && b[o + 4] == 0 && b[o + 5] == 0 && b[o + 6] == 0 && b[o + 7] == 0)
                    return o + 8;
            }
        } catch (Exception e) { }
        return 0;
    }

    @Override
    public void run() throws Exception {
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (int round = 1; round <= 10; round++) {
            int created = 0, failed = 0, orphans = 0, padCleared = 0;
            // Orphan alignment filler directly in front of code that already belongs to a function (MSVC pads
            // loop heads inside a function and jumps over the filler): clear it back to undefined bytes rather
            // than making it a function that would run on into its parent's loop.
            ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
            java.util.List<Instruction> padIns = new java.util.ArrayList<>();
            InstructionIterator pit = l.getInstructions(true);
            while (pit.hasNext()) {
                Instruction ins = pit.next();
                Address a = ins.getMinAddress();
                if (fm.getFunctionContaining(a) != null || rm.hasReferencesTo(a)) continue;
                if (padLen(mem, a) != ins.getLength()) continue;
                Address next = a.add(ins.getLength());
                while (padLen(mem, next) > 0 && l.getInstructionAt(next) != null
                        && fm.getFunctionContaining(next) == null) next = next.add(padLen(mem, next));
                if (fm.getFunctionContaining(next) != null) padIns.add(ins);
            }
            for (Instruction ins : padIns) {
                l.clearCodeUnits(ins.getMinAddress(), ins.getMaxAddress(), false);
                padCleared++;
            }
            // Functions that are nothing but filler (a lone int3 at the start of .text, named by Function ID and
            // referenced only from the PE header's BaseOfCode) and that no instruction calls or jumps to, and no
            // relocated pointer or data outside the header points to: remove them and clear the filler.
            java.util.List<Function> fillerFns = new java.util.ArrayList<>();
            for (Function f : fm.getFunctions(true)) {
                if (f.isExternal() || f.isThunk()) continue;
                boolean allPad = true;
                for (Instruction ins : l.getInstructions(f.getBody(), true))
                    if (padLen(mem, ins.getMinAddress()) != ins.getLength()) { allPad = false; break; }
                if (!allPad) continue;
                boolean refd = false;
                for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
                    ghidra.program.model.mem.MemoryBlock fb = mem.getBlock(r.getFromAddress());
                    if (r.getReferenceType().isFlow() || fb != null && !fb.getName().equals("Headers")) { refd = true; break; }
                }
                if (!refd) fillerFns.add(f);
            }
            for (Function f : fillerFns) {
                AddressSetView body = f.getBody();
                fm.removeFunction(f.getEntryPoint());
                for (AddressRange r : body) l.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
                padCleared++;
            }
            InstructionIterator it = l.getInstructions(true);
            java.util.List<Address> heads = new java.util.ArrayList<>();
            while (it.hasNext()) {
                Instruction ins = it.next();
                if (fm.getFunctionContaining(ins.getMinAddress()) != null) continue;
                orphans++;
                Address a = ins.getMinAddress();
                Instruction prev = l.getInstructionBefore(a);
                boolean fallsIn = prev != null && prev.getMaxAddress().next() != null
                        && prev.getMaxAddress().next().equals(a) && prev.getFallThrough() != null
                        && prev.getFallThrough().equals(a) && fm.getFunctionContaining(prev.getMinAddress()) == null;
                if (rm.hasReferencesTo(a) || !fallsIn) heads.add(a);
            }
            for (Address a : heads) {
                if (fm.getFunctionContaining(a) != null) continue;
                CreateFunctionCmd cmd = new CreateFunctionCmd(a);
                if (cmd.applyTo(currentProgram, monitor)) created++; else failed++;
            }
            analyzeChanges(currentProgram);
            println("ORPHANS round " + round + ": orphan_instructions=" + orphans + " heads=" + heads.size()
                    + " created=" + created + " failed=" + failed + " padding_cleared=" + padCleared);
            if (created == 0 && padCleared == 0) break;
        }
    }
}
