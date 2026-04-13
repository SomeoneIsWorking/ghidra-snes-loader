package snesloader;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.ByteProvider;

public class RomInfo {

	public static final int SMC_HEADER_LEN = 512;
	public static final int INVALID_DETECTION_SCORE = Integer.MIN_VALUE;

	public enum RomKind {
		LO_ROM(new LoRomLoader()),
		HI_ROM(new HiRomLoader());

		private final RomInfoProvider infoProvider;

		RomKind(RomInfoProvider infoProvider) {
			this.infoProvider = infoProvider;
		}

		private long getSnesHeaderOffset() {
			return infoProvider.getSnesHeaderOffset();
		}

		private long getMaxRomSize() {
			return infoProvider.getMaxRomSize();
		}

		private long getRomChunkSize() {
			return infoProvider.getChunkSize();
		}

		private RomLoader getLoader() {
			return infoProvider.getLoaderFunction();
		}
	}

	private RomKind kind;
	private boolean hasSmcHeader;

	public RomInfo(RomKind kind, boolean hasSmcHeader) {
		this.kind = kind;
		this.hasSmcHeader = hasSmcHeader;
	}

	public boolean bytesLookValid(ByteProvider provider) {
		return calculateDetectionScore(provider) != INVALID_DETECTION_SCORE;
	}

	public int calculateDetectionScore(ByteProvider provider) {
		try {
			long romLen = provider.length() - getStartOffset();
			// Basic structural checks first: if these fail, scoring is meaningless.
			// Must contain at least one chunk.
			if (romLen < getRomChunkSize()) {
				return INVALID_DETECTION_SCORE;
			}
			// ROM dumps should be a multiple of this chunk size (SMC header excepted). 
			if (romLen % getRomChunkSize() != 0) {
				return INVALID_DETECTION_SCORE;
			}
			// Too big to load.
			if (romLen > kind.getMaxRomSize()) {
				return INVALID_DETECTION_SCORE;
			}

			// Score both regular and BS-X interpretation and keep the stronger signal.
			int normalScore = calculateMapModeScore(provider, false);
			int bsScore = calculateMapModeScore(provider, true);
			int bestScore = Math.max(normalScore, bsScore);
			return bestScore <= -100 ? INVALID_DETECTION_SCORE : bestScore;
		}
		catch (IOException e) {
			return INVALID_DETECTION_SCORE;
		}
	}

	public long getStartOffset() {
		return (hasSmcHeader ? SMC_HEADER_LEN : 0);
	}

	public boolean hasSmcHeader() {
		return hasSmcHeader;
	}

	public long getSnesHeaderOffset() {
		return getStartOffset() + kind.getSnesHeaderOffset();
	}

	public long getRomChunkSize() {
		return kind.getRomChunkSize();
	}

	public String getDescription() {
		return kind.toString() +
			(hasSmcHeader ? " with SMC header" : "");
	}

	public RomLoader getLoader() {
		return kind.getLoader();
	}

	private int calculateMapModeScore(ByteProvider provider, boolean isBsRom) throws IOException {
		long headerOffset = getSnesHeaderOffset();
		long headerBaseOffset = headerOffset - 0x10;
		// We need at least the full 0x50-byte header region around the expected location.
		if (!isReadable(provider, headerBaseOffset, 0x50)) {
			return -100;
		}

		int score = 0;
		int resetVector = readUnsignedShortLE(provider, headerOffset + 0x3C);
		int checksum = readUnsignedShortLE(provider, headerOffset + 0x1E);
		int checksumInverse = readUnsignedShortLE(provider, headerOffset + 0x1C);
		int mapModeOffset = isBsRom ? 0x18 : 0x15;
		int mapMode = readUnsignedByte(provider, headerOffset + mapModeOffset) & 0x37;
		int romSize = readUnsignedByte(provider, headerOffset + 0x17);
		int destinationCode = readUnsignedByte(provider, headerOffset + 0x19);
		int fixedValue33 = readUnsignedByte(provider, headerOffset + 0x1A);
		byte[] fixedValue00 = provider.readBytes(headerOffset - 0x0A, 7);

		// A valid reset vector should point into ROM execution area.
		if (resetVector < 0x8000) {
			return -100;
		}

		// Match reference utility behavior: first opcode at reset target is a strong hint.
		long opCodeOffset = getStartOffset() + resetVector;
		if (!isReadable(provider, opCodeOffset, 1)) {
			return -100;
		}
		int opCode = readUnsignedByte(provider, opCodeOffset);

		// Most likely opcodes.
		if (opCode == 0x78 || opCode == 0x18 || opCode == 0x38 || opCode == 0x9C || opCode == 0x4C || opCode == 0x5C) {
			score += 8;
		}

		// Plausible opcodes.
		if (opCode == 0xC2 || opCode == 0xE2 || opCode == 0xAD || opCode == 0xAE || opCode == 0xAC || opCode == 0xAF
				|| opCode == 0xA9 || opCode == 0xA2 || opCode == 0xA0 || opCode == 0x20 || opCode == 0x22) {
			score += 4;
		}

		// Implausible opcodes.
		if (opCode == 0x40 || opCode == 0x60 || opCode == 0x6B || opCode == 0xCD || opCode == 0xEC || opCode == 0xCC) {
			score -= 4;
		}

		// Least likely opcodes.
		if (opCode == 0x00 || opCode == 0x02 || opCode == 0xDB || opCode == 0x42 || opCode == 0xFF) {
			score -= 8;
		}

		// Check if checksums add up to 0xFFFF.
		if ((checksum + checksumInverse) == 0xFFFF) {
			score += 4;
		}

		// Check if internal ROM type is valid.
		if (kind == RomKind.LO_ROM && (mapMode == 0x20 || mapMode == 0x30)) {
			score += 2;
		}
		if (kind == RomKind.HI_ROM && (mapMode == 0x21 || mapMode == 0x31 || mapMode == 0x3A)) {
			score += 2;
		}

		// Check if internal ROM size is valid.
		if (romSize >= 0x07 && romSize <= 0x0D) {
			score += 2;
		}

		// Check if destination code is valid.
		if (destinationCode <= 0x14) {
			score += 2;
		}

		// Check for some fixed ROM values.
		if (fixedValue33 == 0x33) {
			score += 4;
		}

		if (Arrays.equals(fixedValue00, new byte[7])) {
			score += 2;
		}

		// BS-X hint: many titles begin with "BS".
		if (isBsRom) {
			int title0 = readUnsignedByte(provider, headerOffset);
			int title1 = readUnsignedByte(provider, headerOffset + 1);
			if (title0 == 0x42 && title1 == 0x53) {
				score += 2;
			}
		}

		return score;
	}

	private static boolean isReadable(ByteProvider provider, long offset, long length) throws IOException {
		// Explicit bounds guard to avoid accidental wraparound on offset math.
		if (offset < 0 || length <= 0) {
			return false;
		}
		long endOffset = offset + length - 1;
		return endOffset >= offset && provider.isValidIndex(offset) && provider.isValidIndex(endOffset);
	}

	private static int readUnsignedByte(ByteProvider provider, long offset) throws IOException {
		return Byte.toUnsignedInt(provider.readBytes(offset, 1)[0]);
	}

	private static int readUnsignedShortLE(ByteProvider provider, long offset) throws IOException {
		byte[] bytes = provider.readBytes(offset, 2);
		return Byte.toUnsignedInt(bytes[0]) | (Byte.toUnsignedInt(bytes[1]) << 8);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (hasSmcHeader ? 1231 : 1237);
		result = prime * result + ((kind == null) ? 0 : kind.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RomInfo other = (RomInfo) obj;
		if (hasSmcHeader != other.hasSmcHeader)
			return false;
		if (kind != other.kind)
			return false;
		return true;
	}
}
