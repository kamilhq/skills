// Headless Ghidra script: find large regions of executable sections that nothing references and that hold no
// relocation, clear any code Ghidra decoded there, and mark them as byte data so later steps do not decode them.
//
// Evidence (needs a PE with relocations; otherwise the script does nothing and says so). In a relocatable image
// every absolute address the program uses - a call through the IAT, a global, a string literal, a float
// constant, a switch table, a vtable or callback entry - is a relocation site, and every pointer to code is a
// relocation target. Compiled code goes at most a few KB without one (largest relocation-free run measured in
// real code: 7.2 KB of non-filler bytes, in a VS2010 game exe). A region is an interval of an executable block between
// two such anchors (relocation site, relocation target, exported/entry address) with >= MIN_NONFILL bytes that
// are not 00/CC/90. Inside it, code is kept when it is reached: every instruction reached by flow (branch or
// fall-through) from an instruction outside the region, transitively, and the whole body of a function that
// starts before the region or at kept code. Everything else in the region - remains of a removed protection
// layer, compressed blobs, stale linker buffers (source text, symbol names) - is unreferenced data: functions
// starting there are removed, instructions cleared, and the bytes defined as a byte array.
// code_coverage_check.py applies the same rule (gap kind "unreferenced_region").
// Log: one "UNREFREGION 0x<lo> len=<n> nonfill=<n> entropy=<bits/byte> kept_bytes=<n> kept_functions=<n>
// removed_functions=<n> cleared_instructions=<n>" line per region, then "UNREFREGIONS regions=N bytes=M".
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class UnreferencedRegions extends GhidraScript {
    static final int MIN_NONFILL = 32768;

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        List<MemoryBlock> exec = new ArrayList<>();
        for (MemoryBlock b : mem.getBlocks()) if (b.isExecute() && b.isInitialized()) exec.add(b);
        TreeSet<Long> anchors = new TreeSet<>();
        int nrel = 0;
        Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
        while (it.hasNext()) {
            Relocation r = it.next();
            if (r.getType() != 3) continue;     // IMAGE_REL_BASED_HIGHLOW; type 0 is block padding, not a site
            Address s = r.getAddress();
            nrel++;
            if (inExec(exec, s.getOffset())) for (int k = 0; k < 4; k++) anchors.add(s.getOffset() + k);
            try {
                long t = mem.getInt(s) & 0xffffffffL;
                if (inExec(exec, t)) anchors.add(t);
            } catch (MemoryAccessException e) { }
        }
        if (nrel == 0) { println("UNREFREGIONS skipped: the program has no relocations (no evidence)"); return; }
        AddressIterator ep = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (ep.hasNext()) anchors.add(ep.next().getOffset());
        int regions = 0; long total = 0;
        for (MemoryBlock b : exec) {
            long bs = b.getStart().getOffset(), be = b.getEnd().getOffset() + 1;
            long prev = bs;
            List<long[]> cand = new ArrayList<>();
            for (Long a : anchors.subSet(bs, be)) {
                if (a > prev) cand.add(new long[]{prev, a});
                prev = a + 1;
            }
            if (be > prev) cand.add(new long[]{prev, be});
            for (long[] c : cand) {
                long lo = c[0], hi = c[1];
                if (hi - lo < MIN_NONFILL) continue;
                byte[] buf = new byte[(int) (hi - lo)];
                mem.getBytes(toAddr(lo), buf);
                long nonfill = 0; long[] hist = new long[256];
                for (byte x : buf) { int v = x & 0xff; hist[v]++; if (v != 0 && v != 0xCC && v != 0x90) nonfill++; }
                if (nonfill < MIN_NONFILL) continue;
                double ent = 0;
                for (long h : hist) if (h > 0) { double p = (double) h / buf.length; ent -= p * Math.log(p) / Math.log(2); }
                AddressSet region = new AddressSet(toAddr(lo), toAddr(hi - 1));
                // kept code: every instruction of the region reached by flow - fall-through or branch - from an
                // instruction outside it, transitively (an EH funclet "mov eax, offset FuncInfo" ends right at the
                // relocation that bounds the region and falls through into its "jmp ___CxxFrameHandler"), and
                // the whole body of a function that starts before the region or at kept code
                AddressSet keep = new AddressSet();
                Deque<Address> work = new ArrayDeque<>();
                Instruction before = l.getInstructionContaining(toAddr(lo - 1));
                if (before != null) {
                    if (before.getMaxAddress().getOffset() >= lo) keep.add(toAddr(lo), before.getMaxAddress());
                    if (before.getFallThrough() != null) work.add(before.getFallThrough());
                    for (Address t : before.getFlows()) work.add(t);
                }
                AddressIterator dests = rm.getReferenceDestinationIterator(region, true);
                while (dests.hasNext()) {
                    Address to = dests.next();
                    for (Reference r : rm.getReferencesTo(to))
                        if (r.getReferenceType().isFlow() && !region.contains(r.getFromAddress())) { work.add(to); break; }
                }
                while (!work.isEmpty()) {
                    Address a = work.poll();
                    if (!region.contains(a) || keep.contains(a)) continue;
                    Instruction ins = l.getInstructionAt(a);
                    if (ins == null) continue;
                    keep.add(ins.getMinAddress(), ins.getMaxAddress());
                    if (ins.getFallThrough() != null) work.add(ins.getFallThrough());
                    for (Address t : ins.getFlows()) work.add(t);
                }
                Set<Function> kept = new HashSet<>();
                Function first = fm.getFunctionContaining(toAddr(lo));
                if (first != null && first.getEntryPoint().getOffset() < lo) kept.add(first);
                List<Function> inside = new ArrayList<>();
                for (Function f : fm.getFunctions(region, true)) {
                    if (keep.contains(f.getEntryPoint())) kept.add(f);
                    if (!kept.contains(f)) inside.add(f);
                }
                for (Function f : kept) keep.add(f.getBody().intersect(region));
                int removed = 0;
                for (Function f : inside) if (!kept.contains(f)) { fm.removeFunction(f.getEntryPoint()); removed++; }
                AddressSet dead = region.subtract(keep);
                long cleared = 0;
                for (AddressRange r : dead) {
                    InstructionIterator ii = l.getInstructions(new AddressSet(r), true);
                    while (ii.hasNext()) { ii.next(); cleared++; }
                    l.clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
                }
                for (AddressRange r : dead)       // kept code is whole instructions: nothing straddles
                    l.createData(r.getMinAddress(), new ArrayDataType(ByteDataType.dataType, (int) r.getLength(), 1));
                regions++; total += dead.getNumAddresses();
                println(String.format("UNREFREGION 0x%x len=%d nonfill=%d entropy=%.2f kept_bytes=%d kept_functions=%d removed_functions=%d cleared_instructions=%d",
                        lo, hi - lo, nonfill, ent, keep.getNumAddresses(), kept.size(), removed, cleared));
            }
        }
        println("UNREFREGIONS regions=" + regions + " bytes=" + total);
    }

    static boolean inExec(List<MemoryBlock> exec, long v) {
        for (MemoryBlock e : exec) if (v >= e.getStart().getOffset() && v <= e.getEnd().getOffset()) return true;
        return false;
    }
}
