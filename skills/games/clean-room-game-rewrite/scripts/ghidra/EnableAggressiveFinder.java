// Headless pre-script: turn on Ghidra's Aggressive Instruction Finder so code reached only through
// pointers stored in data (vtables, callback tables) is disassembled and turned into functions.
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;

public class EnableAggressiveFinder extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "true");
        println("OPTIONS Aggressive Instruction Finder = " + getCurrentAnalysisOptionsAndValues(currentProgram).get("Aggressive Instruction Finder"));
    }
}
