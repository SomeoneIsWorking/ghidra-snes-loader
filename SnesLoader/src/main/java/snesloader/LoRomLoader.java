package snesloader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import snesloader.RomReader.RomChunk;

public class LoRomLoader implements RomInfoProvider {
	public static final long SNES_HEADER_OFFSET = 0x7FC0;
	public static final long MAX_ROM_SIZE = 0x80_0000;
	public static final int ROM_CHUNK_SIZE = 0x8000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		AddressSpace busSpace = prog.getAddressFactory().getDefaultAddressSpace();
		boolean supports24BitBus = busSpace.getMaxAddress().getOffset() >= 0xFF_FFFF;

		RomReader reader = new RomReader(romInfo, provider);
		for (RomChunk romChunk : reader) {
			String primaryBlockName = getRomChunkPrimaryName(romChunk);

			if (supports24BitBus) {
				List<Address> busAddresses = getBusAddressesForRomChunk(romChunk, busSpace);
				Address primaryAddress = busAddresses.remove(0);
				try {
					MemoryBlockUtils.createInitializedBlock(prog, false, primaryBlockName, primaryAddress,
							romChunk.getInputStream(), romChunk.getLength(), "", provider.getAbsolutePath(), true, false,
							true, log, monitor);
				} catch (AddressOverflowException e) {
					throw new IllegalStateException(
						"Invalid address range specified: start:" + primaryAddress + ", length:"
							+ romChunk.getLength() + " - end address exceeds address space boundary!");
				}

				int mirrorNum = 1;
				for (Address mirrorAddress : busAddresses) {
					String mirrorBlockName = getRomChunkMirrorName(romChunk, mirrorNum);
					MemoryBlockUtils.createByteMappedBlock(prog, mirrorBlockName, mirrorAddress, primaryAddress,
							(int) romChunk.getLength(), String.format("mirror of %s", primaryBlockName), "", true, false,
							true, false, log);
					mirrorNum++;
				}
			}
			else {
				// Fallback for 16-bit CPU languages (e.g., 6502/65C02): map each LoROM bank as its own
				// overlay block at 0x8000-0xffff so large SNES ROMs still load instead of failing with
				// AddressOutOfBoundsException on 24-bit bus addresses.
				Address primaryAddress = busSpace.getAddress(0x8000);
				try {
					MemoryBlockUtils.createInitializedBlock(prog, true, primaryBlockName, primaryAddress,
							romChunk.getInputStream(), romChunk.getLength(), "", provider.getAbsolutePath(), true, false,
							true, log, monitor);
				}
				catch (AddressOverflowException e) {
					throw new IllegalStateException(
						"Invalid address range specified: start:" + primaryAddress + ", length:"
							+ romChunk.getLength() + " - end address exceeds address space boundary!");
				}
			}
		}

		return true;
	}

	private static List<Address> getBusAddressesForRomChunk(RomChunk chunk, AddressSpace space) {
		var busAddresses = new ArrayList<Address>();
		long chunkStartAddress = chunk.getRomAddresses().left;

		// Primary mapping.
		if (chunkStartAddress <= 0x3e_8000) {
			// Map to 00-7d:8000-ffff
			busAddresses.add(space.getAddress(((chunkStartAddress / 0x8000) * 0x1_0000) + 0x8000));
		}
		// Gap in banks 7e and 7f for RAM.

		// Mirroring, and primary mapping of 3f:0000-8000 to fe-ff:8000-ffff.
		busAddresses.add(space.getAddress(((chunkStartAddress / 0x8000) * 0x1_0000) + 0x80_8000));

		return busAddresses;
	}

	private static String getRomChunkPrimaryName(RomChunk chunk) {
		long leftAddr = chunk.getRomAddresses().left;
		int leftBank = (int) ((leftAddr & 0xff_0000) >> 16);
		int leftSmall = (int) (leftAddr & 0xffff);

		long rightAddr = chunk.getRomAddresses().right;
		int rightBank = (int) ((rightAddr & 0xff_0000) >> 16);
		int rightSmall = (int) (rightAddr & 0xffff);

		return String.format("rom_%02x:%04x-%02x:%04x", leftBank, leftSmall, rightBank, rightSmall);
	}

	private static String getRomChunkMirrorName(RomChunk chunk, int mirrorNum) {
		return String.format("%s_mirror%d", getRomChunkPrimaryName(chunk), mirrorNum);
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
