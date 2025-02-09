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
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.NotFoundException;

public class eBPF_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_BPF;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {
		Program program = elfRelocationContext.getProgram();
		int type = relocation.getType();

		int symbolIndex = relocation.getSymbolIndex();
		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym.getNameAsString();

		markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
				elfRelocationContext.getLog());
	}
}
