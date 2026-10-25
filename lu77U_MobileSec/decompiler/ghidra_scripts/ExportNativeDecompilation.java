/*
 * Ghidra headless post-script used by lu77U-MobileSec to decompile an Android
 * native library. It writes one JSON document holding every defined function's
 * name, entry point, the external symbols it calls and its decompiled C, which
 * the Python side then prioritises and pages to the analysis agent.
 *
 * Script arguments:
 *   <output.json> [max_functions] [per_function_timeout_seconds] [decompile_budget_seconds]
 *
 * Decompilation stops once max_functions have been written or the budget is
 * spent, and the document is still completed with "truncated": true, so a huge
 * library yields its first functions rather than nothing.
 */
//@category lu77U-MobileSec

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.TreeSet;

import com.google.gson.stream.JsonWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ExportNativeDecompilation extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			printerr("usage: ExportNativeDecompilation <output.json> [max_functions] [timeout_seconds] [budget_seconds]");
			return;
		}
		String outputPath = args[0];
		int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 4000;
		int timeoutSeconds = args.length > 2 ? Integer.parseInt(args[2]) : 60;
		int budgetSeconds = args.length > 3 ? Integer.parseInt(args[3]) : 600;
		long deadline = System.currentTimeMillis() + budgetSeconds * 1000L;

		DecompInterface decompiler = new DecompInterface();
		decompiler.setOptions(new DecompileOptions());
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(false);
		if (!decompiler.openProgram(currentProgram)) {
			printerr("decompiler could not open program: " + decompiler.getLastMessage());
			return;
		}

		int total = 0;
		int exported = 0;
		boolean truncated = false;
		try (Writer out = new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8);
				JsonWriter json = new JsonWriter(out)) {
			json.beginObject();
			json.name("language").value(currentProgram.getLanguageID().getIdAsString());
			json.name("pointer_size").value(currentProgram.getDefaultPointerSize());
			json.name("image_base").value(currentProgram.getImageBase().toString());
			json.name("functions").beginArray();

			FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
			while (functions.hasNext() && !monitor.isCancelled()) {
				Function function = functions.next();
				if (function.isExternal() || function.isThunk()) {
					continue;
				}
				total++;
				if (exported >= maxFunctions || System.currentTimeMillis() > deadline) {
					truncated = true;
					continue;
				}

				TreeSet<String> calls = new TreeSet<>();
				for (Function callee : function.getCalledFunctions(monitor)) {
					Function target = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
					if (target != null && target.isExternal()) {
						calls.add(target.getName());
					}
				}

				String code = "";
				DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, monitor);
				if (results != null && results.decompileCompleted()) {
					DecompiledFunction decompiled = results.getDecompiledFunction();
					if (decompiled != null) {
						code = decompiled.getC();
					}
				}

				json.beginObject();
				json.name("name").value(function.getName());
				json.name("entry").value(function.getEntryPoint().toString());
				json.name("size").value(function.getBody().getNumAddresses());
				json.name("calls").beginArray();
				for (String name : calls) {
					json.value(name);
				}
				json.endArray();
				json.name("c").value(code);
				json.endObject();
				exported++;
			}

			json.endArray();
			json.name("function_count").value(total);
			json.name("truncated").value(truncated);
			json.endObject();
		}
		finally {
			decompiler.dispose();
		}
		println("lu77U: decompiled " + exported + " of " + total + " functions to " + outputPath);
	}
}
