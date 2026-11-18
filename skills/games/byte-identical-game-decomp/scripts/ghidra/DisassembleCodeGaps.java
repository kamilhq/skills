// Headless Ghidra script: find code that is not yet disassembled at all (undefined bytes in executable
// blocks, outside any function, instruction or defined data), and create functions there.
// For each undefined run: skip alignment filler (padLen: CC/90, 8B FF, lea r,[r+0] in all its MSVC forms incl.
// 8D 9B 00000000 and 8D 64 24 00, 0F 1F NOPs; the original list missed the 4/6-byte forms, which turned
// in-function loop-alignment filler into false functions); if what follows is >= 2 dwords pointing into an executable block it
// is an undecoded switch jump table (left as data); otherwise disassemble, check that the decoded code is
// plausible (implausible(): every flow lands on an instruction start inside the executable image; if not, the
// decode is cleared and logged as CODEGAPS_REJECT) and create a function; then continue with the rest of the gap.
// Optional arg: a file of gap start addresses (one 0x... per line) to restrict the scan.
// Log: one "CODEGAPS_FAIL 0x<addr> <reason>" line per gap it could not turn into a function (run_recovery.sh
// collects them into codegaps_failures.txt), then the "CODEGAPS ..." summary line.
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import java.nio.file.*;
import java.util.*;

public class DisassembleCodeGaps extends GhidraScript {
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

    Memory mem; Listing l; FunctionManager fm; List<MemoryBlock> exec = new ArrayList<>();

    boolean inExec(long v) {
        for (MemoryBlock e : exec) if (v >= e.getStart().getOffset() && v <= e.getEnd().getOffset()) return true;
        return false;
    }


    boolean readAsData(ghidra.program.model.symbol.ReferenceManager rm, Address from, Address to) {
        for (Address x = from; x.compareTo(to) <= 0; x = x.next()) {
            for (ghidra.program.model.symbol.Reference r : rm.getReferencesTo(x)) {
                // Only a memory read (movzx r, byte [r + table]) marks a table. An address used as an immediate
                // (push offset fn / mov eax, offset continuation) is a DATA reference too, but to code:
                // atexit-registered destructors and C++ catch continuations look exactly like that.
                ghidra.program.model.symbol.RefType t = r.getReferenceType();
                if (t.isRead()) return true;
            }
            if (x.equals(to)) break;
        }
        return false;
    }

    boolean followsPointerTable(Address g0) throws Exception {
        Address p = g0.subtract(4);
        Data d = l.getDefinedDataContaining(p);
        if (d != null) {
            Data leaf = d.getPrimitiveAt((int) p.subtract(d.getMinAddress()));
            if (leaf != null && leaf.isPointer()) return true;
            if (d.isPointer()) return true;
        }
        long v0 = mem.getInt(p) & 0xffffffffL, v1 = mem.getInt(g0.subtract(8)) & 0xffffffffL;
        return inExec(v0) && inExec(v1) && l.getInstructionContaining(p) == null && fm.getFunctionContaining(p) == null;
    }

    List<Address> discover() throws Exception {
        List<Address> starts = new ArrayList<>();
        for (MemoryBlock b : exec) {
            Address cur = b.getStart(); boolean inGap = false;
            while (cur != null && cur.compareTo(b.getEnd()) <= 0) {
                CodeUnit cu = l.getCodeUnitContaining(cur);
                boolean undef = fm.getFunctionContaining(cur) == null && l.getInstructionContaining(cur) == null
                        && l.getDefinedDataContaining(cur) == null;
                if (undef && !inGap) { starts.add(cur); inGap = true; }
                if (!undef) inGap = false;
                cur = (cu != null && cu.getMaxAddress().compareTo(cur) > 0) ? cu.getMaxAddress().next() : cur.next();
            }
        }
        return starts;
    }

    boolean undef(Address a) {
        return fm.getFunctionContaining(a) == null && l.getInstructionContaining(a) == null
                && l.getDefinedDataContaining(a) == null;
    }

    // Why freshly decoded code cannot be compiled code, or null. Every flow (branch target or fall-through) of
    // real code lands on an instruction start inside the image: a flow outside the image, into a
    // non-executable block, onto bytes that do not decode, or into the middle of another instruction proves
    // the bytes are data (DirectInput c_dfDIKeyboard records in a VC6 exe decode as "call 0x017b16f0").
    String implausible(AddressSetView set) {
        InstructionIterator ii = l.getInstructions(set, true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            List<Address> outs = new ArrayList<>(Arrays.asList(ins.getFlows()));
            if (ins.getFallThrough() != null) outs.add(ins.getFallThrough());
            for (Address t : outs) {
                if (t == null || !t.isMemoryAddress()) continue;
                MemoryBlock b = mem.getBlock(t);
                if (b == null || !b.isInitialized()) return "flow from 0x" + ins.getMinAddress() + " to 0x" + t + " outside the image";
                if (!b.isExecute()) return "flow from 0x" + ins.getMinAddress() + " into non-executable 0x" + t;
                Instruction ti = l.getInstructionContaining(t);
                if (ti == null) return "flow from 0x" + ins.getMinAddress() + " to 0x" + t + " that does not decode";
                if (!ti.getMinAddress().equals(t)) return "flow from 0x" + ins.getMinAddress() + " into the middle of the instruction at 0x" + ti.getMinAddress();
            }
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        mem = currentProgram.getMemory(); l = currentProgram.getListing(); fm = currentProgram.getFunctionManager();
        for (MemoryBlock b : mem.getBlocks()) if (b.isExecute() && b.isInitialized()) exec.add(b);
        String[] args = getScriptArgs();
        boolean fixedList = args.length > 0 && Files.exists(Paths.get(args[0]));
        Set<Address> rejectedStarts = new HashSet<>();
        // Repeat until a round creates nothing. Within a round, after a function is created in a gap the rest of
        // that same gap is processed at once (an import thunk table "jmp [IAT]" x N, or a run of small
        // unreferenced methods, is one gap with N functions; one per round never finished them). A new round
        // picks up gaps exposed elsewhere (e.g. by the analysis of the functions just created).
        for (int round = 1; round <= 20; round++) {
        List<Address> gaps = new ArrayList<>();
        if (fixedList) {
            for (String s : Files.readAllLines(Paths.get(args[0]))) if (!s.trim().isEmpty()) gaps.add(toAddr(s.trim()));
        } else gaps = discover();
        int jt = 0, created = 0, failed = 0, padOnly = 0, rejected = 0;
        int dataSkipped = 0;
        ghidra.program.model.symbol.ReferenceManager rm = currentProgram.getReferenceManager();
        for (int gi = 0; gi < gaps.size(); gi++) {
          Address a = gaps.get(gi);
          Address limit = gi + 1 < gaps.size() ? gaps.get(gi + 1) : null;   // the next listed gap
          for (int cont = 0; cont < 100000 && a != null; cont++) {
            Address g0 = a;
            Address next = null;                      // where to continue in this gap after a function is made
            Address end = null;
            for (MemoryBlock e : exec) if (e.contains(a)) end = e.getEnd();
            if (end == null) break;
            while (a.compareTo(end) < 0) {
                int pl = padLen(mem, a);
                if (pl > 0) { a = a.add(pl); continue; }
                if (mem.getByte(a) == 0) { a = a.add(1); continue; }
                break;
            }
            if (rejectedStarts.contains(a)) break;
            if (l.getInstructionContaining(a) != null || l.getDefinedDataContaining(a) != null || fm.getFunctionContaining(a) != null) { padOnly++; break; }
            long p0 = mem.getInt(a) & 0xffffffffL, p1 = mem.getInt(a.add(4)) & 0xffffffffL;
            if (inExec(p0) && inExec(p1)) { jt++; break; }
            // Switch index byte tables (movzx r, byte [r + table]) follow the jump table and are read as data.
            // A gap whose start (or filler before it) an instruction reads as data, or that directly follows
            // defined pointer data / an undecoded pointer run, is data: leave it.
            // A table may be split into several gaps: walk back over small byte values (index tables hold
            // case numbers) outside any function to the table's start, and test that too.
            Address ts = g0;
            for (int k = 0; k < 4096; k++) {
                Address q = ts.subtract(1);
                if (fm.getFunctionContaining(q) != null || (mem.getByte(q) & 0xff) >= 0x40) break;
                ts = q;
            }
            if (readAsData(rm, g0, a) || followsPointerTable(g0)
                    || (!ts.equals(g0) && (readAsData(rm, ts, g0) || followsPointerTable(ts)))) {
                dataSkipped++; println("CODEGAPS_DATA 0x" + g0 + " left as data (switch index table)"); break;
            }
            DisassembleCommand dc = new DisassembleCommand(a, null, true);
            dc.applyTo(currentProgram, monitor);
            if (l.getInstructionAt(a) == null) { failed++; println("CODEGAPS_FAIL 0x" + a + " does not disassemble (data?)"); break; }
            AddressSetView done = dc.getDisassembledAddressSet();
            String why = done == null ? null : implausible(done);
            if (why != null) {
                for (AddressRange r : done) l.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
                rejectedStarts.add(a); rejected++;
                println("CODEGAPS_REJECT 0x" + a + " not code: " + why);
                break;
            }
            CreateFunctionCmd cf = new CreateFunctionCmd(a);
            if (cf.applyTo(currentProgram, monitor)) {
                created++;
                // continue after the code just decoded, if more undefined bytes of this gap follow - unless the new
                // function has a computed jump not resolved yet (a switch: its cases follow and belong to it once
                // the analysis between rounds has read the jump table). "jmp [abs32]" (FF 25: import thunk, jump
                // through a pointer variable) is not a switch.
                Function nf = fm.getFunctionAt(a);
                boolean pendingSwitch = false;
                if (nf != null) for (Instruction ins : l.getInstructions(nf.getBody(), true)) {
                    if (!ins.getFlowType().isJump() || !ins.getFlowType().isComputed() || ins.getFlows().length > 0) continue;
                    byte[] ib = ins.getBytes();
                    if (ib.length == 6 && ib[0] == (byte) 0xFF && ib[1] == (byte) 0x25) continue;
                    pendingSwitch = true; break;
                }
                Address x = pendingSwitch ? null : a;
                while (x != null && x.compareTo(end) <= 0 && !undef(x)) {
                    CodeUnit cu = l.getCodeUnitContaining(x);
                    x = cu != null ? cu.getMaxAddress().next() : x.next();
                }
                if (x != null && x.compareTo(end) <= 0 && (limit == null || x.compareTo(limit) < 0)) next = x;
            }
            else { failed++; println("CODEGAPS_FAIL 0x" + a + " create function failed: " + cf.getStatusMsg()); }
            a = next;
          }
        }
        analyzeChanges(currentProgram);
        println("CODEGAPS round " + round + ": gaps=" + gaps.size() + " jumptables_skipped=" + jt + " datatables_skipped=" + dataSkipped
                + " padding_only=" + padOnly + " rejected_not_code=" + rejected
                + " created=" + created + " failed=" + failed);
        if (created == 0 || fixedList) break;
        }
    }
}
