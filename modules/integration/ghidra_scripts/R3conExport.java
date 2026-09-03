import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import java.io.File;
import java.io.PrintWriter;
import java.util.Set;

public class R3conExport extends ghidra.app.script.GhidraScript {
    private String esc(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                    .replace("\r", "\\r").replace("\n", "\\n");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) throw new IllegalArgumentException("output JSON path required");
        File output = new File(args[0]);
        output.getParentFile().mkdirs();

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        FunctionManager manager = currentProgram.getFunctionManager();
        FunctionIterator functions = manager.getFunctions(true);
        PrintWriter out = new PrintWriter(output, "UTF-8");
        out.println("{\"functions\":[");
        boolean first = true;
        int count = 0;
        while (functions.hasNext() && count < 500 && !monitor.isCancelled()) {
            Function function = functions.next();
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            String pseudo = result.decompileCompleted() && result.getDecompiledFunction() != null
                    ? result.getDecompiledFunction().getC() : "";
            if (!first) out.println(",");
            first = false;
            out.print("{\"address\":\"0x" + Long.toHexString(function.getEntryPoint().getOffset())
                    + "\",\"name\":\"" + esc(function.getName())
                    + "\",\"size\":" + function.getBody().getNumAddresses()
                    + ",\"decompiled\":\"" + esc(pseudo) + "\",\"calls\":[");
            boolean firstCall = true;
            try {
                Set<Function> called = function.getCalledFunctions(monitor);
                for (Function callee : called) {
                    if (!firstCall) out.print(",");
                    firstCall = false;
                    out.print("\"" + esc(callee.getName()) + "\"");
                }
            } catch (Exception ignored) { }
            out.print("]}");
            count++;
        }
        out.println("],\"function_count\":" + count + "}");
        out.close();
        decompiler.dispose();
        println("R3CON_EXPORT=" + output.getAbsolutePath());
    }
}
