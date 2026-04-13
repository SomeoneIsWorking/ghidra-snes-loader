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
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageCompilerSpecQuery;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.ProcessorNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import snesloader.RomInfo.RomKind;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.util.bin.BinaryReader;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SnesLoader extends AbstractProgramLoader {

	public static final String APPLY_SNES_LABELS_OPTION_NAME = "Apply SNES-specific Labels";
	public static final String ANCHOR_SNES_LABELS_OPTION_NAME = "Anchor SNES-specific Labels";
	public static final Integer SIXTEEN_BIT = 16;
	private static final long SNES_BUS_HEADER_BASE = 0xFFC0;

	private static final class VectorSpec {
		private final String vectorName;
		private final int headerRelativeOffset;

		private VectorSpec(String vectorName, int headerRelativeOffset) {
			this.vectorName = vectorName;
			this.headerRelativeOffset = headerRelativeOffset;
		}
	}

	private static final VectorSpec[] SNES_VECTORS = {
		new VectorSpec("native_cop", 0x24),
		new VectorSpec("native_brk", 0x26),
		new VectorSpec("native_abort", 0x28),
		new VectorSpec("native_nmi", 0x2A),
		new VectorSpec("native_irq", 0x2E),
		new VectorSpec("emu_cop", 0x34),
		new VectorSpec("emu_abort", 0x38),
		new VectorSpec("emu_nmi", 0x3A),
		new VectorSpec("emu_reset", 0x3C),
		new VectorSpec("emu_irq_brk", 0x3E)
	};

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

		RomInfo detectedRomKind = detectBestRomKindOrNull(provider);
		if (detectedRomKind != null) {
			LanguageCompilerSpecQuery query = new LanguageCompilerSpecQuery(
				snesProcessor, Endian.LITTLE, null, null, null);
			List<LanguageCompilerSpecPair> lcsps = getLanguageService().getLanguageCompilerSpecPairs(query);
			for (LanguageCompilerSpecPair lcsp : lcsps) {
				loadSpecs.add(new LoadSpec(this, 0, lcsp, false));
			}
		}

		return loadSpecs;
	}

	private RomInfo detectBestRomKindOrNull(ByteProvider provider) {
		RomInfo[] candidateRomKinds = new RomInfo[] {
			new RomInfo(RomKind.LO_ROM, true),
			new RomInfo(RomKind.LO_ROM, false),
			new RomInfo(RomKind.HI_ROM, true),
			new RomInfo(RomKind.HI_ROM, false)};

		RomInfo bestRomKind = null;
		int bestScore = RomInfo.INVALID_DETECTION_SCORE;
		for (RomInfo rom : candidateRomKinds) {
			// Evaluate all mapping/header combinations and keep the strongest match.
			int score = rom.calculateDetectionScore(provider);
			if (score > bestScore) {
				bestScore = score;
				bestRomKind = rom;
			}
		}

		return bestRomKind;
	}

	@Override
	protected void loadProgramInto(Program prog, ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		RomInfo romInfo = detectUniqueRomKind(settings.provider());
		loadWithTransaction(settings.provider(), settings.loadSpec(), settings.options(), settings.log(), prog,
			settings.monitor(), romInfo);
	}

	@Override
	protected List<Loaded<Program>> loadProgram(ImporterSettings settings)
			throws IOException, LoadException, CancelledException {
		List<Loaded<Program>> programs = new ArrayList<>();
		RomInfo romInfo = detectUniqueRomKind(settings.provider());
		Program prog = createProgram(settings);
		boolean success = loadWithTransaction(settings.provider(), settings.loadSpec(), settings.options(),
			settings.log(), prog, settings.monitor(), romInfo);
		if (success) {
			programs.add(new Loaded<>(prog, settings));
		}
		else {
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
			if (success) {
				applySnesAnalysisHelpers(prog, provider, options, romInfo);
			}
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

	private RomInfo detectUniqueRomKind(ByteProvider provider) throws IOException {
		RomInfo bestRomKind = detectBestRomKindOrNull(provider);
		// If nothing scores above the invalid threshold, this is not a SNES ROM we can parse.
		if (bestRomKind == null) {
			throw new IOException("Not a valid SNES ROM");
		}
		return bestRomKind;
	}

	private void applySnesAnalysisHelpers(Program prog, ByteProvider provider, List<Option> options, RomInfo romInfo) {
		boolean applySnesLabels = getBooleanOption(options, APPLY_SNES_LABELS_OPTION_NAME, true);
		if (!applySnesLabels) {
			return;
		}

		boolean anchorSnesLabels = getBooleanOption(options, ANCHOR_SNES_LABELS_OPTION_NAME, true);
		AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();
		boolean supports24BitBus = space.getMaxAddress().getOffset() >= 0xFF_FFFF;
		SymbolTable symbolTable = prog.getSymbolTable();
		BinaryReader reader = new BinaryReader(provider, true);
		int createdFunctionCount = 0;

		for (VectorSpec vector : SNES_VECTORS) {
			long vectorFileOffset = romInfo.getSnesHeaderOffset() + vector.headerRelativeOffset;
			if (!provider.isValidIndex(vectorFileOffset + 1)) {
				continue;
			}

			try {
				int target16 = reader.readUnsignedShort(vectorFileOffset);
				if (!isLikelyVectorTarget(target16)) {
					continue;
				}

				long vectorBusAddress = SNES_BUS_HEADER_BASE + vector.headerRelativeOffset;
				Address vectorAddress = toProgramAddress(space, supports24BitBus, vectorBusAddress);
				Address targetAddress = toProgramAddress(space, supports24BitBus, target16 & 0xFFFFL);

				if (anchorSnesLabels) {
					safeCreateLabel(symbolTable, vectorAddress, "vec_" + vector.vectorName);
				}
				safeCreateLabel(symbolTable, targetAddress, "snes_" + vector.vectorName);
				prog.getSymbolTable().addExternalEntryPoint(targetAddress);

				if (prog.getFunctionManager().getFunctionAt(targetAddress) == null) {
					prog.getFunctionManager().createFunction("snes_" + vector.vectorName, targetAddress,
						new AddressSet(targetAddress), SourceType.ANALYSIS);
					createdFunctionCount++;
				}
			}
			catch (Exception e) {
				Msg.debug(this, "Skipping vector " + vector.vectorName + ": " + e.getMessage());
			}
		}

		applyHardwareRegisterLabels(symbolTable, space, supports24BitBus);
		Msg.info(this, "SNES helper applied (" + createdFunctionCount + " vector functions created).");
	}

	private void applyHardwareRegisterLabels(SymbolTable symbolTable, AddressSpace space, boolean supports24BitBus) {
		Map<Long, String> registers = new LinkedHashMap<>();
		registers.put(0x2100L, "INIDISP");
		registers.put(0x2101L, "OBSEL");
		registers.put(0x2102L, "OAMADDL");
		registers.put(0x2103L, "OAMADDH");
		registers.put(0x2104L, "OAMDATA");
		registers.put(0x2105L, "BGMODE");
		registers.put(0x2106L, "MOSAIC");
		registers.put(0x2107L, "BG1SC");
		registers.put(0x2108L, "BG2SC");
		registers.put(0x2109L, "BG3SC");
		registers.put(0x210AL, "BG4SC");
		registers.put(0x210BL, "BG12NBA");
		registers.put(0x210CL, "BG34NBA");
		registers.put(0x210DL, "BG1HOFS");
		registers.put(0x210EL, "BG1VOFS");
		registers.put(0x210FL, "BG2HOFS");
		registers.put(0x2110L, "BG2VOFS");
		registers.put(0x2111L, "BG3HOFS");
		registers.put(0x2112L, "BG3VOFS");
		registers.put(0x2113L, "BG4HOFS");
		registers.put(0x2114L, "BG4VOFS");
		registers.put(0x2115L, "VMAIN");
		registers.put(0x2116L, "VMADDL");
		registers.put(0x2117L, "VMADDH");
		registers.put(0x2118L, "VMDATAL");
		registers.put(0x2119L, "VMDATAH");
		registers.put(0x211AL, "M7SEL");
		registers.put(0x211BL, "M7A");
		registers.put(0x211CL, "M7B");
		registers.put(0x211DL, "M7C");
		registers.put(0x211EL, "M7D");
		registers.put(0x211FL, "M7X");
		registers.put(0x2120L, "M7Y");
		registers.put(0x2121L, "CGADD");
		registers.put(0x2122L, "CGDATA");
		registers.put(0x2123L, "W12SEL");
		registers.put(0x2124L, "W34SEL");
		registers.put(0x2125L, "WOBJSEL");
		registers.put(0x2126L, "WH0");
		registers.put(0x2127L, "WH1");
		registers.put(0x2128L, "WH2");
		registers.put(0x2129L, "WH3");
		registers.put(0x212AL, "WBGLOG");
		registers.put(0x212BL, "WOBJLOG");
		registers.put(0x212CL, "TM");
		registers.put(0x212DL, "TS");
		registers.put(0x212EL, "TMW");
		registers.put(0x212FL, "TSW");
		registers.put(0x2130L, "CGWSEL");
		registers.put(0x2131L, "CGADSUB");
		registers.put(0x2132L, "COLDATA");
		registers.put(0x2133L, "SETINI");
		registers.put(0x2140L, "APUIO0");
		registers.put(0x2141L, "APUIO1");
		registers.put(0x2142L, "APUIO2");
		registers.put(0x2143L, "APUIO3");
		registers.put(0x2180L, "WMDATA");
		registers.put(0x2181L, "WMADDL");
		registers.put(0x2182L, "WMADDM");
		registers.put(0x2183L, "WMADDH");
		registers.put(0x4016L, "JOY1");
		registers.put(0x4017L, "JOY2");
		registers.put(0x4200L, "NMITIMEN");
		registers.put(0x4201L, "WRIO");
		registers.put(0x4202L, "WRMPYA");
		registers.put(0x4203L, "WRMPYB");
		registers.put(0x4204L, "WRDIVL");
		registers.put(0x4205L, "WRDIVH");
		registers.put(0x4206L, "WRDIVB");
		registers.put(0x4207L, "HTIMEL");
		registers.put(0x4208L, "HTIMEH");
		registers.put(0x4209L, "VTIMEL");
		registers.put(0x420AL, "VTIMEH");
		registers.put(0x420BL, "MDMAEN");
		registers.put(0x420CL, "HDMAEN");
		registers.put(0x420DL, "MEMSEL");
		registers.put(0x4210L, "RDNMI");
		registers.put(0x4211L, "TIMEUP");
		registers.put(0x4212L, "HVBJOY");
		registers.put(0x4213L, "RDIO");
		registers.put(0x4214L, "RDDIVL");
		registers.put(0x4215L, "RDDIVH");
		registers.put(0x4216L, "RDMPYL");
		registers.put(0x4217L, "RDMPYH");
		registers.put(0x4218L, "JOY1L");
		registers.put(0x4219L, "JOY1H");
		registers.put(0x421AL, "JOY2L");
		registers.put(0x421BL, "JOY2H");
		registers.put(0x421CL, "JOY3L");
		registers.put(0x421DL, "JOY3H");
		registers.put(0x421EL, "JOY4L");
		registers.put(0x421FL, "JOY4H");

		for (Map.Entry<Long, String> reg : registers.entrySet()) {
			long offset = supports24BitBus ? reg.getKey() : (reg.getKey() & 0xFFFFL);
			try {
				Address addr = space.getAddress(offset);
				safeCreateLabel(symbolTable, addr, reg.getValue());
			}
			catch (Exception ignored) {
				// Ignore address-space limits in fallback CPU modes.
			}
		}
	}

	private boolean isLikelyVectorTarget(int target16) {
		return target16 >= 0x8000 && target16 != 0xFFFF;
	}

	private Address toProgramAddress(AddressSpace space, boolean supports24BitBus, long offset16Or24) {
		long normalizedOffset = supports24BitBus ? (offset16Or24 & 0xFFFFFFL) : (offset16Or24 & 0xFFFFL);
		return space.getAddress(normalizedOffset);
	}

	private void safeCreateLabel(SymbolTable symbolTable, Address address, String labelName) {
		try {
			if (symbolTable.getGlobalSymbol(labelName, address) == null) {
				symbolTable.createLabel(address, labelName, SourceType.ANALYSIS);
			}
		}
		catch (Exception ignored) {
			// Label may already exist under another namespace/name, which is okay.
		}
	}

	private boolean getBooleanOption(List<Option> options, String optionName, boolean defaultValue) {
		if (options == null) {
			return defaultValue;
		}
		for (Option option : options) {
			if (optionName.equals(option.getName()) && option.getValue() instanceof Boolean) {
				return (Boolean) option.getValue();
			}
		}
		return defaultValue;
	}
}
