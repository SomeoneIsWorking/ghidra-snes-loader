package snesloader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageCompilerSpecQuery;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.ProcessorNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import snesloader.RomInfo.RomKind;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.bin.BinaryReader;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SnesLoader extends AbstractProgramLoader {

	public static final String APPLY_SNES_LABELS_OPTION_NAME = "Apply SNES-specific Labels";
	public static final String ANCHOR_SNES_LABELS_OPTION_NAME = "Anchor SNES-specific Labels";
	public static final Integer SIXTEEN_BIT = 16;

	@Override
	public String getName() {
		// This name must match the name of the loader in the .opinion files.
		return "SNES ROM";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return false;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		getLanguageService();  // Ensure Processors are loaded.
		Processor snesProcessor = null;
		for (String processorName : List.of("65816", "65C02", "6502")) {
			try {
				snesProcessor = Processor.toProcessor(processorName);
				break;
			}
			catch (ProcessorNotFoundException ignored) {
				// Try next fallback.
			}
		}
		if (snesProcessor == null) {
			return loadSpecs;
		}

		Collection<RomInfo> detectedRomKinds = detectRomKind(provider);
		if (!detectedRomKinds.isEmpty()) {
			LanguageCompilerSpecQuery query = new LanguageCompilerSpecQuery(
				snesProcessor, Endian.LITTLE, null, null, null);
			List<LanguageCompilerSpecPair> lcsps = getLanguageService().getLanguageCompilerSpecPairs(query);
			for (LanguageCompilerSpecPair lcsp : lcsps) {
				loadSpecs.add(new LoadSpec(this, 0, lcsp, false));
			}
		}

		return loadSpecs;
	}

	private Collection<RomInfo> detectRomKind(ByteProvider provider) {
		Collection<RomInfo> validRomKinds = new HashSet<RomInfo>();
		RomInfo[] candidateRomKinds = new RomInfo[] {
			new RomInfo(RomKind.LO_ROM, true),
			new RomInfo(RomKind.LO_ROM, false),
			new RomInfo(RomKind.HI_ROM, true),
			new RomInfo(RomKind.HI_ROM, false)};

		for (RomInfo rom : candidateRomKinds) {
			if (rom.bytesLookValid(provider)) {
				validRomKinds.add(rom);
			}
		}

		return validRomKinds;
	}

	@Override
	protected void loadProgramInto(Program prog, ImporterSettings settings)
			throws IOException, LoadException, CancelledException {

		Collection<RomInfo> detectedRomKinds = detectRomKind(settings.provider());
		if (detectedRomKinds.size() == 0) {
			throw new IOException("Not a valid SNES ROM");
		}

		RomInfo romInfo = detectedRomKinds.iterator().next();

		loadWithTransaction(
			settings.provider(),
			settings.loadSpec(),
			settings.options(),
			settings.log(),
			prog,
			settings.monitor(),
			romInfo
		);

		// Adding functionality for analysis
		// === SNES Helper Start ===
		try {
			AddressFactory af = prog.getAddressFactory();
			AddressSpace space = af.getDefaultAddressSpace();

			// Reset Vector (LoROM: 0x7FFC)
			BinaryReader reader = new BinaryReader(settings.provider(), true);
			int lo = reader.readUnsignedByte(0x7FFC);
			int hi = reader.readUnsignedByte(0x7FFD);
			int entryAddr = (hi << 8) | lo;

			Address entry = space.getAddress(entryAddr & 0xFFFF);

			// Funktion am Entry Point erstellen
			prog.getFunctionManager().createFunction(
				"entry_point",
				entry,
				new AddressSet(entry),
				SourceType.USER_DEFINED
			);

			// Alle JSR/JSL finden und Funktionen erstellen
			Listing listing = prog.getListing();
			InstructionIterator it = listing.getInstructions(true);

			while (it.hasNext()) {
				Instruction instr = it.next();
				String mnem = instr.getMnemonicString();

				if (mnem.equals("JSR") || mnem.equals("JSL")) {
					Object[] ops = instr.getOpObjects(0);
					if (ops.length > 0 && ops[0] instanceof Address) {
						Address target = (Address) ops[0];
						try {
							prog.getFunctionManager().createFunction(
								String.format("sub_%06X", target.getOffset()),
								target,
								new AddressSet(target),
								SourceType.ANALYSIS
							);
						} catch (Exception e) {
							// ignore duplicates
						}
					}
				}
			}

			Msg.info(this, "SNES helper applied.");

		} catch (Exception e) {
			Msg.error(this, "SNES helper failed: " + e.getMessage());
		}
		// === SNES Helper End ===
	}
	
	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		List<Loaded<Program>> programs = new ArrayList<>();
		Collection<RomInfo> detectedRomKinds = detectRomKind(settings.provider());
		if (detectedRomKinds.size() == 0) {
			throw new IOException("Not a valid SNES ROM");
		}
		if (detectedRomKinds.size() > 1) {
			String errSummary = "Can't uniquely determine what kind of SNES ROM this is.";
			StringBuilder sb = new StringBuilder(errSummary);
			sb.append(" Could be any of:");
			sb.append(System.lineSeparator());
			for (RomInfo rom : detectedRomKinds) {
				sb.append(rom.getDescription());
				sb.append(System.lineSeparator());
			}
			Msg.showError(this, null, "Can't load ROM", sb.toString());
			return programs;
		}

		Program prog = createProgram(settings);
		RomInfo romInfo = detectedRomKinds.iterator().next();
		boolean success = loadWithTransaction(settings.provider(), settings.loadSpec(), settings.options(),
				settings.log(), prog, settings.monitor(), romInfo);
		if (success) {
			programs.add(new Loaded<>(prog, settings));
		} else {
			prog.release(settings.consumer());
		}

		return programs;
	}

	private boolean loadWithTransaction(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, MessageLog log, Program prog, TaskMonitor monitor, RomInfo romInfo)
			throws IOException {
		prog.setEventsEnabled(false);
		int transactionID = prog.startTransaction("Loading - " + getName());
		RomLoader loader = romInfo.getLoader();
		boolean success = false;
		try {
			success = loader.load(provider, loadSpec, options, log, prog, monitor, romInfo);
			return success;
		}
		finally {
			prog.endTransaction(transactionID, success);
			prog.setEventsEnabled(true);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram, boolean isExpertContext) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram,
				isExpertContext);

		list.add(new Option(APPLY_SNES_LABELS_OPTION_NAME, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-applySnesLabels"));
		list.add(new Option(ANCHOR_SNES_LABELS_OPTION_NAME, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-anchorSnesLabels"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		String error = super.validateOptions(provider, loadSpec, options, program);
		
		if (error == null && options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(APPLY_SNES_LABELS_OPTION_NAME) ||
					name.equals(ANCHOR_SNES_LABELS_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						error = "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return error;
	}
}
