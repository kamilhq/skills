// Headless Ghidra script: write every disassembled instruction to <out_dir>/instructions.tsv, so later checks
// and phase 5b need no external disassembler (objdump/llvm). One line per instruction, tab-separated:
//   address  length  function_entry_or_-  flow  targets  text
// flow: fall | call | jump | cjump | ccall (computed call) | cjmp (computed jump) | ret | term (other
// terminator); targets: comma-separated hex flow destinations (empty if none); text: Ghidra's rendering.
// Also writes <out_dir>/functions.tsv: entry  name  body ranges (start-end,...)  - exact, multi-range bodies.
// Arg: <out_dir>. Log line: "LISTING instructions=N functions=M".
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import java.io.*;
import java.nio.file.*;

public class ExportListing extends GhidraScript {
    static String hex(Address a) { return "0x" + Long.toHexString(a.getOffset()); }

    @Override
    public void run() throws Exception {
        Path out = Paths.get(getScriptArgs()[0]);
        Files.createDirectories(out);
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        long n = 0, nf = 0;
        try (BufferedWriter w = Files.newBufferedWriter(out.resolve("instructions.tsv"))) {
            w.write("address\tlength\tfunction\tflow\ttargets\ttext\n");
            InstructionIterator it = l.getInstructions(true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                Address a = ins.getMinAddress();
                Function f = fm.getFunctionContaining(a);
                FlowType ft = ins.getFlowType();
                String flow;
                if (ft.isCall()) flow = ft.isComputed() ? "ccall" : "call";
                else if (ft.isJump()) flow = ft.isComputed() ? "cjmp" : (ft.isConditional() ? "cjump" : "jump");
                else if (ft.isTerminal()) flow = ins.getMnemonicString().toUpperCase().startsWith("RET") ? "ret" : "term";
                else flow = "fall";
                StringBuilder t = new StringBuilder();
                for (Address d : ins.getFlows()) { if (t.length() > 0) t.append(','); t.append(hex(d)); }
                String text = ins.toString().replace('\t', ' ').replace('\n', ' ');
                w.write(hex(a) + "\t" + ins.getLength() + "\t" + (f == null ? "-" : hex(f.getEntryPoint())) + "\t"
                        + flow + "\t" + t + "\t" + text + "\n");
                n++;
            }
        }
        try (BufferedWriter w = Files.newBufferedWriter(out.resolve("functions.tsv"))) {
            w.write("entry\tname\tbody\n");
            for (Function f : fm.getFunctions(true)) {
                if (f.isExternal()) continue;
                StringBuilder b = new StringBuilder();
                for (AddressRange r : f.getBody()) {
                    if (b.length() > 0) b.append(',');
                    b.append(hex(r.getMinAddress())).append('-').append(hex(r.getMaxAddress()));
                }
                w.write(hex(f.getEntryPoint()) + "\t" + f.getName(true) + "\t" + b + "\n");
                nf++;
            }
        }
        println("LISTING instructions=" + n + " functions=" + nf);
    }
}
