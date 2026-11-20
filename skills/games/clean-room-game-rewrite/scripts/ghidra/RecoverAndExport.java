// Headless Ghidra post-script: create functions Ghidra's auto-analysis missed (targets of
// code-pointer tables), re-run analysis so their callees are found too, report uncovered code,
// and decompile every function to <outdir>/functions/0x<addr>.c plus an index.json.
//
// Args: <addresses.txt (one 0x... per line, may be empty)> <outdir> [names.json]
//   names.json (optional), UTF-8 JSON in one of two shapes:
//     {"0x401000": "Name", "0x401230": "Class::Method", "0x401300": "Ns::Class::~Class"}
//     [{"address": "0x401000", "name": "Name"}, ...]           ("addr" is accepted for "address")
//   The last "::" part is the function name, the part before it its class (created as a class if new;
//   outer parts become namespaces if new; templates with "::" inside <> are kept intact).
//   A names file that is missing, unparsable, empty, or of which no entry could be applied makes the
//   script throw (the headless log shows SCRIPT ERROR) before anything is exported.
// Output: functions/0x<addr>.c, index.json {"functions":[{address,name,size,status,callees[,thunk_of]}]}
//   (callees = entry addresses of the non-external functions it calls, i.e. the call graph independent of
//   names), coverage_gaps.txt, recover_failures.txt, name_failures.txt.
// Log lines: RECOVER, NAMES, COVERAGE, EXPORT.
//@category ByteIdenticalDecomp
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.SymbolPathParser;
import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class RecoverAndExport extends GhidraScript {
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
        String[] a = getScriptArgs();
        if (a.length < 2) throw new IllegalArgumentException("usage: RecoverAndExport.java <addresses.txt> <outdir> [names.json]");
        Path addrFile = Paths.get(a[0]);
        Path out = Paths.get(a[1]);
        Files.createDirectories(out.resolve("functions"));
        Listing listing = currentProgram.getListing();
        AddressFactory af = currentProgram.getAddressFactory();
        FunctionManager fm = currentProgram.getFunctionManager();

        // 1. create missing functions
        int created = 0, existed = 0, failed = 0;
        List<String> failures = new ArrayList<>();
        if (Files.exists(addrFile)) {
            for (String line : Files.readAllLines(addrFile)) {
                line = line.trim();
                if (line.isEmpty()) continue;
                Address ad = af.getAddress(line);
                if (ad == null) { failed++; failures.add(line + " not an address"); continue; }
                if (fm.getFunctionAt(ad) != null) { existed++; continue; }
                Function inside = fm.getFunctionContaining(ad);
                if (inside != null) {
                    // target sits inside an existing body (e.g. SEH funclet): split it out as its own function
                    failures.add(line + " inside 0x" + hex(inside.getEntryPoint()));
                }
                if (listing.getInstructionAt(ad) == null) {
                    new DisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
                }
                CreateFunctionCmd cmd = new CreateFunctionCmd(ad);
                if (cmd.applyTo(currentProgram, monitor)) created++;
                else { failed++; failures.add(line + " create failed: " + cmd.getStatusMsg()); }
            }
        }
        analyzeChanges(currentProgram);
        println("RECOVER created=" + created + " existed=" + existed + " failed=" + failed);

        // 2. optional names
        Path namesFile = a.length > 2 && !a[2].isEmpty() ? Paths.get(a[2]) : null;
        List<String> nameFailures = new ArrayList<>();
        if (namesFile != null) applyNames(namesFile, out, af, fm, nameFailures);

        // 3. coverage report: executable bytes not in any function and not padding
        long inFn = 0, gapCode = 0; List<String> gaps = new ArrayList<>();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isExecute()) continue;
            Address s = b.getStart(), e = b.getEnd();
            Address cur = s; Address gapStart = null; long gapLen = 0, gapNonPad = 0;
            while (cur != null && cur.compareTo(e) <= 0) {
                Function f = fm.getFunctionContaining(cur);
                if (f != null) {
                    if (gapStart != null && gapNonPad >= 16) gaps.add("0x" + hex(gapStart) + " len=" + gapLen + " nonpad=" + gapNonPad);
                    gapStart = null; gapLen = 0; gapNonPad = 0;
                    AddressSetView body = f.getBody();
                    AddressRange r = body.getRangeContaining(cur);
                    long n = r.getMaxAddress().subtract(cur) + 1;
                    inFn += n;
                    cur = r.getMaxAddress().next();
                    continue;
                }
                byte by = b.getByte(cur);
                if (gapStart == null) gapStart = cur;
                int pl = padLen(currentProgram.getMemory(), cur);
                if (pl > 1 && cur.add(pl - 1).compareTo(e) <= 0 && fm.getFunctionContaining(cur.add(pl - 1)) == null) {
                    gapLen += pl; cur = cur.add(pl); continue;          // multi-byte alignment filler
                }
                gapLen++;
                if (by != (byte) 0xCC && by != (byte) 0x90 && by != 0) { gapNonPad++; gapCode++; }
                cur = cur.next();
            }
            if (gapStart != null && gapNonPad >= 16) gaps.add("0x" + hex(gapStart) + " len=" + gapLen + " nonpad=" + gapNonPad);
        }
        println("COVERAGE bytes_in_functions=" + inFn + " nonpad_bytes_outside=" + gapCode + " gaps>=16=" + gaps.size());
        Files.write(out.resolve("coverage_gaps.txt"), gaps);
        Files.write(out.resolve("recover_failures.txt"), failures);
        if (namesFile == null) Files.write(out.resolve("name_failures.txt"), nameFailures);

        // 4. decompile everything
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true); di.toggleSyntaxTree(false);
        di.openProgram(currentProgram);
        StringBuilder idx = new StringBuilder("{\"functions\":[\n");
        int ok = 0, bad = 0, ext = 0; boolean first = true;
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk() && f.getBody().getNumAddresses() <= 8) { ext++; }
            String ad = "0x" + hex(f.getEntryPoint());
            String status;
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                String body = r.getDecompiledFunction().getC();
                String hdr = "// name: " + f.getName(true) + "\n// address: " + ad + "\n// body: " + f.getBody().getMinAddress() + "-" + f.getBody().getMaxAddress() + " (" + f.getBody().getNumAddresses() + " bytes)\n// source: Ghidra " + getGhidraVersion() + " headless (RecoverAndExport.java)\n";
                Files.write(out.resolve("functions").resolve(ad + ".c"), (hdr + body).getBytes("UTF-8"));
                ok++; status = "written";
            } else { bad++; status = "failed: " + (r == null ? "null" : r.getErrorMessage().replace("\n", " ")); }
            TreeSet<Address> cal = new TreeSet<>();
            for (Function c : f.getCalledFunctions(monitor)) if (!c.isExternal()) cal.add(c.getEntryPoint());
            StringBuilder cs = new StringBuilder();
            for (Address c : cal) { if (cs.length() > 0) cs.append(','); cs.append("\"0x").append(hex(c)).append('"'); }
            if (!first) idx.append(",\n"); first = false;
            idx.append("{\"address\":\"").append(ad).append("\",\"name\":").append(js(f.getName(true)))
               .append(",\"size\":").append(f.getBody().getNumAddresses()).append(",\"status\":").append(js(status))
               .append(",\"callees\":[").append(cs).append(']');
            if (f.isThunk()) {
                Function t = f.getThunkedFunction(true);
                if (t != null) idx.append(",\"thunk_of\":").append(js(t.isExternal() ? t.getName(true) : "0x" + hex(t.getEntryPoint())));
            }
            idx.append('}');
        }
        idx.append("\n]}\n");
        Files.write(out.resolve("index.json"), idx.toString().getBytes("UTF-8"));
        di.dispose();
        println("EXPORT written=" + ok + " failed=" + bad + " thunk_or_external=" + ext);
    }

    static String hex(Address a) { return Long.toHexString(a.getOffset()); }

    static String js(String v) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : v.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    void applyNames(Path namesFile, Path out, AddressFactory af, FunctionManager fm, List<String> nameFailures) throws Exception {
        final String FORMAT = "expected {\"0x401000\": \"Name\", \"0x401230\": \"Class::Method\"} or [{\"address\": \"0x401000\", \"name\": \"Name\"}]";
        if (!Files.exists(namesFile)) throw new FileNotFoundException("names file not found: " + namesFile);
        JsonElement root;
        try { root = JsonParser.parseString(new String(Files.readAllBytes(namesFile), "UTF-8")); }
        catch (JsonParseException e) { throw new IllegalArgumentException("names file " + namesFile + " is not valid JSON (" + e.getMessage() + "); " + FORMAT); }
        List<String[]> entries = new ArrayList<>();   // {address text, name or null, error or null}
        if (root.isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : root.getAsJsonObject().entrySet()) {
                JsonElement v = e.getValue();
                if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) entries.add(new String[]{e.getKey(), v.getAsString(), null});
                else entries.add(new String[]{e.getKey(), null, "value is not a string: " + v});
            }
        } else if (root.isJsonArray()) {
            for (JsonElement el : root.getAsJsonArray()) {
                if (!el.isJsonObject()) { entries.add(new String[]{"?", null, "array element is not an object: " + el}); continue; }
                JsonObject o = el.getAsJsonObject();
                JsonElement ad = o.has("address") ? o.get("address") : o.get("addr"), nm = o.get("name");
                if (ad == null || nm == null || !ad.isJsonPrimitive() || !nm.isJsonPrimitive())
                    entries.add(new String[]{"?", null, "needs string fields address (or addr) and name: " + el});
                else entries.add(new String[]{ad.getAsString(), nm.getAsString(), null});
            }
        } else throw new IllegalArgumentException("names file " + namesFile + ": top level is neither object nor array; " + FORMAT);
        if (entries.isEmpty()) throw new IllegalArgumentException("names file " + namesFile + " has no entries; " + FORMAT);

        SymbolTable st = currentProgram.getSymbolTable();
        Namespace global = currentProgram.getGlobalNamespace();
        int named = 0;
        for (String[] en : entries) {
            String key = en[0], full = en[1];
            if (en[2] != null) { nameFailures.add(key + " " + en[2]); continue; }
            Address ad = key.matches("(0[xX])?[0-9a-fA-F]{1,16}") ? af.getAddress(key) : null;
            if (ad == null) { nameFailures.add(key + " not a hex address"); continue; }
            Function f = fm.getFunctionAt(ad);
            if (f == null) {
                Function in = fm.getFunctionContaining(ad);
                nameFailures.add(key + " no function starts here" + (in != null ? " (inside 0x" + hex(in.getEntryPoint()) + ")" : ""));
                continue;
            }
            try {
                List<String> parts = SymbolPathParser.parse(full);
                Namespace ns = global;
                for (int p = 0; p < parts.size() - 1; p++) {
                    Namespace ex = st.getNamespace(parts.get(p), ns);
                    if (ex == null) ex = p == parts.size() - 2
                            ? st.createClass(ns, parts.get(p), SourceType.USER_DEFINED)
                            : st.createNameSpace(ns, parts.get(p), SourceType.USER_DEFINED);
                    ns = ex;
                }
                f.setParentNamespace(ns);
                f.setName(parts.get(parts.size() - 1), SourceType.USER_DEFINED);
                named++;
            } catch (Exception e) { nameFailures.add(key + " " + full + ": " + e.getMessage()); }
        }
        Files.write(out.resolve("name_failures.txt"), nameFailures);
        println("NAMES entries=" + entries.size() + " applied=" + named + " failed=" + nameFailures.size()
                + (nameFailures.isEmpty() ? "" : " (see name_failures.txt)"));
        if (named == 0)
            throw new IllegalArgumentException("NAMES: none of the " + entries.size() + " entries in " + namesFile
                    + " could be applied (first: " + nameFailures.get(0) + "); " + FORMAT);
    }
}
