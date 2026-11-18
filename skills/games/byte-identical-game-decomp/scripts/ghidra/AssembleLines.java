// Headless Ghidra script: assemble x86 instruction lines with Ghidra's SLEIGH assembler (phase 5b), choosing
// among ALL encodings Ghidra can produce by a fixed MSVC-style rule, so no external assembler is needed.
//
// Args: <in.tsv> <out.tsv> [choose]
//   in.tsv lines:  id <TAB> text <TAB> enc [<TAB> original_hex]
//     text = one instruction in Ghidra's syntax with numeric operands (labels already resolved);
//     enc  = index into the rule-sorted candidate list (0 = the rule's choice).
//   out.tsv lines: id <TAB> hex <TAB> ncandidates      (or id <TAB> ERR <TAB> message)
//   "choose" mode (used when splitting a binary into text): ignore enc, and report the index of the candidate
//   equal to original_hex instead: id <TAB> index_or_-1 <TAB> ncandidates.
// Encoding rule (sort key, ascending): number of prefix bytes; length; for ALU/MOV reg,reg forms the
// r/m,reg direction (opcode bit 1 clear: 01 09 11 19 21 29 31 39 89 ...) after the reg,r/m one (MSVC emits
// 03 0B 13 1B 23 2B 33 3B 8B); REP (F3) before REPNE (F2); then the bytes. On VVVVVV.exe this picks the
// original encoding for 99.8% of instructions; the rest carry an explicit enc index or become db bytes.
// The assembler runs in a fresh, empty program with the target's language: it never sees original bytes.
// x86-32 encodings do not depend on the instruction address except relative branches, which the caller
// (reassemble.py) encodes itself; this script assembles at a fixed dummy address.
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class AssembleLines extends GhidraScript {
    static final Set<Integer> PFX = new HashSet<>(Arrays.asList(0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x3e, 0x26, 0x36, 0x64, 0x65, 0xf0));

    static int npfx(byte[] b) { int n = 0; while (n < b.length && PFX.contains(b[n] & 0xff)) n++; return n; }

    static int dirWorse(byte[] b) {
        int p = npfx(b); if (p >= b.length) return 0;
        int op = b[p] & 0xff;
        if ((op < 0x40 && ((op & 7) == 0 || (op & 7) == 1)) || op == 0x88 || op == 0x89) return 1;
        return 0;
    }

    static int repWorse(byte[] b) { for (int i = 0; i < npfx(b); i++) if ((b[i] & 0xff) == 0xf2) return 1; return 0; }

    static int cmp(byte[] x, byte[] y) {
        int c = npfx(x) - npfx(y); if (c != 0) return c;
        c = x.length - y.length; if (c != 0) return c;
        c = dirWorse(x) - dirWorse(y); if (c != 0) return c;
        c = repWorse(x) - repWorse(y); if (c != 0) return c;
        for (int i = 0; i < x.length; i++) { c = (x[i] & 0xff) - (y[i] & 0xff); if (c != 0) return c; }
        return 0;
    }

    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        boolean choose = a.length > 2 && a[2].equals("choose");
        Language lang = currentProgram.getLanguage();
        CompilerSpec cs = lang.getCompilerSpecByID(currentProgram.getCompilerSpec().getCompilerSpecID());
        ProgramDB scratch = new ProgramDB("assemble_scratch", lang, cs, this);
        long n = 0, err = 0;
        try {
            Assembler asm = Assemblers.getAssembler(scratch);
            Address at = scratch.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000000L);
            try (BufferedReader r = Files.newBufferedReader(Paths.get(a[0]));
                 PrintWriter w = new PrintWriter(Files.newBufferedWriter(Paths.get(a[1])))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.isEmpty()) continue;
                    String[] f = line.split("\t");
                    String id = f[0], text = f[1];
                    int enc = f.length > 2 ? Integer.parseInt(f[2]) : 0;
                    n++;
                    try {
                        AssemblyResolutionResults rr = asm.resolveLine(at, text);
                        List<byte[]> cands = new ArrayList<>();
                        for (AssemblyResolution ar : rr) {
                            if (!(ar instanceof AssemblyResolvedPatterns)) continue;
                            AssemblyPatternBlock b = ((AssemblyResolvedPatterns) ar).getInstruction();
                            byte[] v = b.getVals(); byte[] full = new byte[b.length()];
                            System.arraycopy(v, 0, full, 0, Math.min(v.length, full.length));
                            cands.add(full);
                        }
                        cands.sort(AssembleLines::cmp);
                        List<byte[]> u = new ArrayList<>();
                        for (byte[] c : cands) if (u.isEmpty() || !Arrays.equals(u.get(u.size() - 1), c)) u.add(c);
                        if (u.isEmpty()) { err++; w.println(id + "\tERR\tno encoding"); continue; }
                        if (choose) {
                            byte[] orig = new byte[f[3].length() / 2];
                            for (int i = 0; i < orig.length; i++) orig[i] = (byte) Integer.parseInt(f[3].substring(2 * i, 2 * i + 2), 16);
                            int idx = -1; for (int i = 0; i < u.size(); i++) if (Arrays.equals(u.get(i), orig)) { idx = i; break; }
                            w.println(id + "\t" + idx + "\t" + u.size());
                        } else {
                            if (enc >= u.size()) { err++; w.println(id + "\tERR\tenc " + enc + " >= " + u.size() + " candidates"); continue; }
                            w.println(id + "\t" + hex(u.get(enc)) + "\t" + u.size());
                        }
                    } catch (Exception e) {
                        err++;
                        w.println(id + "\tERR\t" + e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()).replace('\t', ' ').replace('\n', ' '));
                    }
                }
            }
        } finally {
            scratch.release(this);
        }
        println("ASSEMBLE lines=" + n + " errors=" + err + (choose ? " (choose mode)" : ""));
    }
}
