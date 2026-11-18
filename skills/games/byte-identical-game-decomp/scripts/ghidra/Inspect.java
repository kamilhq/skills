// Headless Ghidra script for ad-hoc questions about an analysed project (replaces interactive tools):
// for each address argument, print the code unit there, the defined data / function containing it, and every
// reference to it. Run read-only against a project made by run_recovery.sh:
//   "$GHIDRA_HOME/support/analyzeHeadless" <project_dir> <program> -process <program> -noanalysis -readOnly \
//       -scriptPath <skill>/scripts/ghidra -postScript Inspect.java 0x401000 0x45cda0
// (or `sh scripts/ghidra/inspect.sh <project_dir> <binary name> <addr>...`). Lines start with "INSPECT".
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class Inspect extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing l = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String s : getScriptArgs()) {
            Address a = toAddr(s);
            CodeUnit cu = l.getCodeUnitContaining(a);
            Data d = l.getDefinedDataContaining(a);
            Function f = fm.getFunctionContaining(a);
            println("INSPECT " + s + " block=" + (currentProgram.getMemory().getBlock(a) == null ? "-" : currentProgram.getMemory().getBlock(a).getName())
                    + " unit=" + (cu == null ? "-" : (cu instanceof Instruction ? "instruction " : "data ") + cu.getMinAddress() + " " + cu)
                    + " data=" + (d == null ? "-" : d.getDataType().getName() + "@" + d.getMinAddress() + " len=" + d.getLength())
                    + " function=" + (f == null ? "-" : f.getName(true) + "@" + f.getEntryPoint()));
            for (Reference r : rm.getReferencesTo(a))
                println("INSPECT   ref from " + r.getFromAddress() + " " + r.getReferenceType()
                        + (fm.getFunctionContaining(r.getFromAddress()) == null ? "" : " in " + fm.getFunctionContaining(r.getFromAddress()).getName(true)));
        }
    }
}
