package snesloader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

public final class SnesHeader {

	public static final int SNES_HEADER_LEN = 64;
	public static final int RESET_VECTOR_OFFSET = 0x3C;
	public static final int COMPLEMENT_OFFSET = 0x1C;
	public static final int CHECKSUM_OFFSET = 0x1E;

	private short resetVector;
	private short checksum;
	private short checksumComplement;

	private SnesHeader(short resetVector, short checksum, short checksumComplement) {
		this.resetVector = resetVector;
		this.checksum = checksum;
		this.checksumComplement = checksumComplement;
	}

	public static SnesHeader fromProviderAtOffset(ByteProvider provider, long offset) throws IOException {
		if (offset < 0) { throw new IllegalArgumentException("offset cannot be negative"); }

		ByteBuffer header_bytes = ByteBuffer.wrap(provider.readBytes(offset, SNES_HEADER_LEN));
		header_bytes.order(ByteOrder.LITTLE_ENDIAN);

		short resetVector = header_bytes.getShort(RESET_VECTOR_OFFSET);
		short checksum = header_bytes.getShort(CHECKSUM_OFFSET);
		short checksumComplement = header_bytes.getShort(COMPLEMENT_OFFSET);

		return new SnesHeader(resetVector, checksum, checksumComplement);
	}

	public boolean looksValid( ) {
		// resetVector must point to bus address 0x8000 or higher. Lower addresses contain RAM and IO.
		// We intentionally do not require a valid checksum pair, because many real-world dumps/hacks
		// ship with stale header checksums.
		int unsignedReset = Short.toUnsignedInt(resetVector);
		boolean validReset = unsignedReset >= 0x8000 && unsignedReset != 0xFFFF;
		return validReset;
	}
}
