package snesloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class LoRomLoader implements RomInfoProvider {
	public static final long SNES_HEADER_OFFSET = 0x7FC0;
	public static final long MAX_ROM_SIZE = 0x80_0000;
	public static final int ROM_CHUNK_SIZE = 0x8000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		long startOffset = romInfo.getStartOffset();
		long romLength = provider.length() - startOffset;
		int bankCount = (int) (romLength / ROM_CHUNK_SIZE);
		// One summary log for LoROM memory mapping extent.
		Msg.info(LoRomLoader.class, "LoROM banks mapped: " + bankCount);

		AddressSpace busSpace = prog.getAddressFactory().getDefaultAddressSpace();
		Memory memory = prog.getMemory();

		for (int bank = 0; bank < bankCount; bank++) {
			long providerOffset = startOffset + ((long) bank * ROM_CHUNK_SIZE);
			long snesAddress = (((long) bank) << 16) | 0x8000L;
			Address blockStart = busSpace.getAddress(snesAddress);
			String blockName = String.format("rom_%02x:8000-%02x:ffff", bank & 0xff, bank & 0xff);

			try (InputStream in = provider.getInputStream(providerOffset)) {
				MemoryBlock block = memory.createInitializedBlock(blockName, blockStart, in, ROM_CHUNK_SIZE, monitor,
					false);
				block.setRead(true);
				block.setWrite(false);
				block.setExecute(true);
			}
			catch (Exception e) {
				throw new IOException(
					String.format("Failed to map LoROM bank %02X at %06X from file offset %06X", bank & 0xff,
						snesAddress, providerOffset),
					e);
			}
		}

		// LoROM reset vector is stored at PC offset 0x7FFC (no copier header), little-endian.
		long resetVectorOffset = startOffset + 0x7FFCL;
		int resetVector = Byte.toUnsignedInt(provider.readBytes(resetVectorOffset, 1)[0]) |
			(Byte.toUnsignedInt(provider.readBytes(resetVectorOffset + 1, 1)[0]) << 8);
		// Reset vector is read from LoROM header and interpreted in bank 00.
		Msg.info(LoRomLoader.class, String.format("Reset vector: 0x%04X", resetVector & 0xFFFF));
		long entrySnesAddress = ((0x00L << 16) | (resetVector & 0xFFFFL));
		Msg.info(LoRomLoader.class, String.format("Resolved entry point: 0x%06X", entrySnesAddress & 0xFFFFFFL));
		Address entryAddress = busSpace.getAddress(entrySnesAddress);
		SymbolTable symbolTable = prog.getSymbolTable();
		symbolTable.addExternalEntryPoint(entryAddress);
		try {
			if (symbolTable.getGlobalSymbol("entry_point", entryAddress) == null) {
				symbolTable.createLabel(entryAddress, "entry_point", SourceType.ANALYSIS);
			}
		}
		catch (Exception e) {
			throw new IOException("Failed to create entry_point label", e);
		}

		return true;
	}

	@Override
	public long getSnesHeaderOffset() {
		return SNES_HEADER_OFFSET;
	}

	@Override
	public long getMaxRomSize() {
		return MAX_ROM_SIZE;
	}

	@Override
	public long getChunkSize() {
		return ROM_CHUNK_SIZE;
	}

	@Override
	public RomLoader getLoaderFunction() {
		return LoRomLoader::load;
	}
}
