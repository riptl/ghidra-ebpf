/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.app.cmd.function.SetFunctionVarArgsCommand;
import ghidra.app.cmd.function.SetReturnDataTypeCmd;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.*;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.*;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedQWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.app.cmd.function.AddMemoryParameterCommand;

public class eBPFAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "eBPF";

	public eBPFAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSet flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption);
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		BookmarkManager bmmanager = program.getBookmarkManager();
		bmmanager.removeBookmarks("Error", "Bad Instruction", monitor);

		SymbolTable table = program.getSymbolTable();
		boolean includeDynamicSymbols = true;
		SymbolIterator symbols = table.getAllSymbols(includeDynamicSymbols);

		return resultSet;
	}
}
