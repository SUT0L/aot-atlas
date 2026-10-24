using System.Buffers.Binary;
using System.Diagnostics;
using Atlas;

if (args.Length == 1 && args[0] == "--registered-cli-commands") {
    foreach (string command in CommandPlan.Commands.Order(StringComparer.Ordinal))
        Console.WriteLine(command);
    return;
}

if (args.Length == 1 && args[0] == "--typemaps") {
    TypeMapsChecks.Run();
    return;
}

if (args.Length == 2 && args[0] == "--typemaps-producer") {
    TypeMapsProducerChecks.Run(args[1]);
    return;
}

if (args.Length == 1 && args[0] == "--json-output") {
    JsonOutputChecks.Run();
    return;
}

if (args.Length is 1 or 2 && args[0] == "--rtr32") {
    Rtr32Checks.Run();
    if (args.Length == 2)
        Rtr32Checks.Producer(args[1]);
    return;
}

if (args.Length == 1 && args[0] == "--metadata-facts") {
    MetadataFactsChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--metadata-payloads") {
    MetadataPayloadChecks.Run();
    return;
}

if (args.Length is 1 or 2 && args[0] == "--gc-cancellation") {
    MethodGcCancellationChecks.Run(args.Length == 2 ? int.Parse(args[1]) : 8_000_000);
    return;
}

if (args.Length == 3 && args[0] == "--call-write-effects") {
    FatCallEffectsChecks.Run(args[1], args[2]);
    return;
}

if (args.Length > 1 && args[0] == "--selective-runtime-references") {
    SelectiveRuntimeReferenceChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 3 && args[0] == "--gc-class-shapes") {
    GcShapeChecks.Classes(args[1], args[2]);
    return;
}

if (args.Length == 3 && args[0] == "--gc-array-elements") {
    GcShapeChecks.ArrayElements(args[1], args[2]);
    return;
}

if (args.Length == 3 && args[0] == "--gc-inherited-shapes") {
    GcShapeChecks.Inherited(args[1], args[2]);
    return;
}

if (args.Length == 3 && args[0] == "--gc-explicit-inheritance") {
    GcShapeChecks.ExplicitInheritance(args[1], args[2]);
    return;
}

if (args.Length is 1 or 3 && args[0] == "--gc-shapes") {
    GcShapeChecks.Run();
    GcShapeChecks.Inheritance();
    GcShapeChecks.ArrayElements();

    if (args.Length == 3)
        GcShapeChecks.Binary(args[1], args[2]);

    return;
}

if (args.Length == 3 && args[0] == "--dictionary-context-relations") {
    DictionaryContextRelationChecks.Run(args[1], args[2]);
    return;
}

if (args.Length == 3 && args[0] == "--analysis-measurements") {
    AnalysisMeasurementChecks.Run(args[1], args[2]);
    return;
}

if (args.Length > 1 && args[0] == "--analysis-products") {
    AnalysisProductChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 0 && args[0] == "--metadata-transactions") {
    MetadataDefinitionRecoveryChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 0 && args[0] == "--owned-references") {
    OwnedReferenceChecks.Run();

    foreach (string path in args.AsSpan(1))
        OwnedReferenceChecks.Binary(path);

    return;
}

if (args.Length == 1 && args[0] == "--owned-collections") {
    OwnedCollectionChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--short-tailcalls") {
    ShortTailcallChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--signature-comparison") {
    SignatureComparisonChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--prepared-analysis") {
    PreparedAnalysisChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length is 3 or 4 && args[0] == "--metadata-producers") {
    MetadataProducerChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length is 2 or 3 && args[0] == "--gc-transition-oracle") {
    GcTransitionOracleChecks.Run(args[1], args.Length == 3 ? int.Parse(args[2]) : null);
    return;
}

if (args.Length == 1 && args[0] == "--iterative-bindings") {
    IterativeBindingChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--binding-workspace") {
    BindingWorkspaceChecks.Run();
    return;
}

if (args.Length > 0 && args[0] == "--signature-ownership") {
    SignatureOwnershipChecks.Run();
    SignatureOwnershipChecks.Binaries(args.AsSpan(1));
    return;
}

if (args.Length > 0 && args[0] == "--extraction-phases") {
    ExtractionPhaseChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--runtime-type-index") {
    RuntimeTypeIndexChecks.Run();
    return;
}

if (args.Length is 1 or 2 && args[0] == "--method-control-flow") {
    MethodControlFlowChecks.Run();

    if (args.Length == 2)
        MethodControlFlowChecks.Binary(args[1]);

    return;
}

if (args.Length == 1 && args[0] == "--historical-dictionaries") {
    HistoricalDictionaryChecks.Run();
    return;
}

if (args.Length > 0 && args[0] == "--dictionary-stages") {
    DictionaryStageChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--template-relations") {
    TemplateRelationChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--write-extents") {
    FatWriteExtentChecks.Run();
    return;
}

if (args.Length == 5 && args[0] == "--dictionary-slot-consumers") {
    DictionarySlotConsumerChecks.Run(args[1], args[2], int.Parse(args[3]), int.Parse(args[4]));
    return;
}

if (args.Length is 3 or 5 && args[0] == "--fat-function-pointers") {
    FatFunctionPointerChecks.Run(
        args[1], args[2],
        args.Length == 5 ? int.Parse(args[3]) : null,
        args.Length == 5 ? int.Parse(args[4]) : null);
    return;
}

if (args.Length == 1 && args[0] == "--native-layout-state") {
    NativeLayoutChecks.Run();
    NativeLayoutStateChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--native-reader-source") {
    NativeReaderSourceChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--signature-rendering") {
    SignatureRenderChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--signature-contexts") {
    SignatureContextChecks.Run();
    SignatureOwnershipChecks.Run();
    return;
}

if (args.Length > 0 && args[0] == "--signature-parser-state") {
    SignatureParserStateChecks.Run();
    SignatureParserStateChecks.Binaries(args.AsSpan(1));
    return;
}

if (args.Length == 3 && args[0] == "--generic-context") {
    GenericContextReferenceChecks.Run(args[1], args[2]);
    return;
}

if (args.Length == 2 && args[0] == "--generic-context-bench") {
    GenericContextReferenceChecks.Benchmark(args[1]);
    return;
}

if (args.Length == 1 && args[0] == "--bounded-names") {
    RuntimeNameChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--metadata-identities") {
    MetadataIdentityChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--shared-bindings") {
    TypeBindingChecks.Run();
    SharedBindingChecks.Run();
    SignatureComparisonChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--type-graphs") {
    TypeGraphChecks.Run();
    return;
}

if (args.Length > 0 && args[0] == "--trace-stages") {
    TraceStageChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 0 && args[0] == "--extraction-stages") {
    ExtractionStageChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--hydration") {
    HydrationChecks.Run();
    HydrationBoundaryChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--cancellation") {
    CancellationChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--timed-cancellation") {
    CancellationChecks.RunTimedFixups();
    return;
}

if (args.Length == 3 && args[0] == "--frozen-runtime-types") {
    FrozenRuntimeTypeChecks.Run(args[1], args[2]);
    return;
}

if (args.Length == 1 && args[0] == "--method-gc") {
    MethodGcChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--managed-unwind") {
    ManagedUnwindChecks.Run();
    return;
}

if (args.Length > 1 && args[0] == "--extraction-availability") {
    ExtractionAvailabilityChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--metadata-values") {
    MetadataValueChecks.Run();
    TemplateFactChecks.Run();
    return;
}

if (args.Length == 2 && args[0] == "--trace-abi") {
    TraceAbiChecks.Run(args[1]);
    return;
}

if (args.Length == 2 && args[0] == "--trace-abi-folded") {
    TraceAbiChecks.Run(args[1], folded: true);
    return;
}

if (args.Length > 1 && args[0] == "--dictionary-relationships") {
    DictionarySlotChecks.Relationships(args.AsSpan(1));
    return;
}

if (args.Length > 0 && args[0] == "--dispatch-resolution") {
    DispatchResolutionChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--runtime-helpers") {
    RuntimeHelperChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--properties") {
    PropertyChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 1 && args[0] == "--strings") {
    NativeStringChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--rtr-source") {
    RtrSourceChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--rtr-format") {
    RtrFormatChecks.Run();
    RtrEmptySectionChecks.Run();
    return;
}

if (args.Length == 1 && args[0] == "--code-flow") {
    CodeFlowChecks.Run();
    return;
}

if (args.Length != 0 && args[0] == "--pinvoke") {
    PInvokeScanChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 2 && args[0] == "--managed-template") {
    ManagedTemplateChecks.Run(args[1]);
    return;
}

if (args.Length > 1 && args[0] == "--shared-methods") {
    SharedMethodChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length > 1 && args[0] == "--dictionary-slots") {
    DictionarySlotChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length != 0 && args[0] == "--marshalling-sizes") {
    MarshallingChecks.Run(args.AsSpan(1));
    return;
}

if (args.Length == 3 && args[0] == "--marshalling-positive") {
    MarshallingProducerChecks.Run(args[1], args[2]);
    return;
}

static void Assert(bool condition) {
    if (!condition)
        throw new Exception("Assertion failed.");
}

var random = new Random(0x41544C41);
byte[] buffer = new byte[9];

for (int sample = 0; sample < 100_000; ++sample) {
    uint value = sample < 256 ? (uint)sample : (uint)random.NextInt64(0, 1L << 32);
    int size = value < (1U << 7) ? 1
        : value < (1U << 14) ? 2
        : value < (1U << 21) ? 3
        : value < (1U << 28) ? 4
        : 5;

    if (size == 5) {
        buffer[0] = 15;
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(1), value);
    } else {
        uint encoded = (value << size) | ((1U << (size - 1)) - 1);

        for (int i = 0; i < size; ++i)
            buffer[i] = (byte)(encoded >> (8 * i));
    }

    var reader = new NativeReader(buffer.AsSpan(0, size));
    Assert(reader.Unsigned() == value && reader.Position == size);

    reader = new NativeReader(buffer.AsSpan(0, size));
    int signShift = size == 5 ? 0 : 32 - 7 * size;
    int signed = unchecked((int)(value << signShift)) >> signShift;
    Assert(reader.Signed() == signed && reader.Position == size);

    for (int end = 0; end < size; ++end) {
        bool failed = false;

        try {
            reader = new NativeReader(buffer.AsSpan(0, end));
            reader.Unsigned();
        } catch (InvalidDataException) {
            failed = true;
        }

        Assert(failed);
    }
}

foreach (byte invalid in new byte[] { 31, 63, 127, 255 }) {
    bool failed = false;

    try {
        var reader = new NativeReader(new byte[] { invalid, 0, 0, 0, 0 });
        reader.Unsigned();
    } catch (InvalidDataException) {
        failed = true;
    }

    Assert(failed);
}

buffer[0] = 31;
BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(1), ulong.MaxValue);

var longReader = new NativeReader(buffer);
Assert(longReader.UnsignedLong() == ulong.MaxValue);

longReader = new NativeReader(buffer);
Assert(longReader.SignedLong() == -1);

var table = new NativeTable(new byte[] { 0, 2, 4, 0, 2, 0x42 });
Assert(table.MoveNext() && table.Bucket == 0 && table.LowHash == 0 && table.Vertex == 5);
Assert(!table.MoveNext());
Assert(!new NativeTable([]).MoveNext());

bool unordered = false;

try {
    var invalidTable = new NativeTable(new byte[] { 0, 2, 6, 1, 6, 0, 2, 0x42 });
    Assert(invalidTable.MoveNext());

    invalidTable.MoveNext();
} catch (InvalidDataException) {
    unordered = true;
}

Assert(unordered);

// Each opcode has a known byte-level result, including negative relocations
byte[] commands = [0x18, 0xAA, 0xBB, 0xCC, 0x11, 0x03, 0x02, 0x0D, 0, 0, 0, 0, 0x0C, 0, 0, 0, 0];
BinaryPrimitives.WriteInt32LittleEndian(commands.AsSpan(8), -8);
BinaryPrimitives.WriteInt32LittleEndian(commands.AsSpan(13), 0x2000 - 0x100D);

byte[] fixups = new byte[4];
BinaryPrimitives.WriteInt32LittleEndian(fixups, 0x3000 - 0x1800);

byte[] expanded = new byte[40];
Array.Fill(expanded, (byte)0xFF);

int length = Hydration.Expand(commands, 0, fixups, 0x1000, 0x1800, 0x2000, expanded);

byte[] expected = new byte[29];
expected[0] = 0xAA;
expected[1] = 0xBB;
expected[2] = 0xCC;
BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(5), 0x3000);
BinaryPrimitives.WriteInt32LittleEndian(expected.AsSpan(13), 0x3000 - 0x200D);
BinaryPrimitives.WriteUInt64LittleEndian(expected.AsSpan(17), 0x1000);
BinaryPrimitives.WriteInt32LittleEndian(expected.AsSpan(25), -25);

Assert(length == expected.Length && expanded.AsSpan(0, length).SequenceEqual(expected));
Assert(expanded[29] == 0xFF);

foreach (byte[] invalid in new byte[][] {
    [6],
    [7],
    [0xE8],
    [0xF0, 0],
    [0xF8, 0, 0],
    [0x18, 1],
    [0x0D, 0, 0, 0],
    [0xFB, 0xFF, 0xFF, 0xFF]
}) {
    bool failed = false;

    try {
        Hydration.Expand(invalid, 0, fixups, 0x1000, 0x1800, 0x2000, expanded);
    } catch (InvalidDataException) {
        failed = true;
    }

    Assert(failed);
}

foreach (int payload in new[] { 28, 29, 283, 284, 65563, 65564 }) {
    int extra = payload <= 28 ? 0 : payload <= 283 ? 1 : payload <= 65563 ? 2 : 3;
    byte[] zeroCommand = new byte[extra + 1];
    zeroCommand[0] = (byte)(1 | ((extra == 0 ? payload : 28 + extra) << 3));

    int remaining = payload - 28;

    for (int i = 0; i < extra; ++i)
        zeroCommand[i + 1] = (byte)(remaining >> (i * 8));

    byte[] dest = new byte[payload + 1];
    Array.Fill(dest, (byte)0xFF);

    Assert(Hydration.Expand(zeroCommand, 0, [], 0, 0, 0, dest) == payload);
    Assert(dest.AsSpan(0, payload).IndexOfAnyExcept((byte)0) < 0 && dest[payload] == 0xFF);
}

Console.WriteLine("NativeFormat: 100000 seeded values and all truncations; hydration: all opcodes, extent failures, and payload boundaries passed.");

AllocationMeasurementChecks.Run();
RtrFormatChecks.Run();
RtrEmptySectionChecks.Run();
RtrSourceChecks.Run();
ExtractionStageChecks.Run([]);
ExtractionPhaseChecks.Run([]);
HistoricalDictionaryChecks.Run();
DictionaryStageChecks.Run([]);
TemplateRelationChecks.Run();
MethodControlFlowChecks.Run();
ShortTailcallChecks.Run();

Rtr32Checks.Run();
MetadataFactsChecks.Run();
MetadataChecks.Run();
MetadataValueChecks.Run();
MetadataPayloadChecks.Run();
OwnedReferenceChecks.Run();
OwnedCollectionChecks.Run();
TemplateFactChecks.Run();
NativeLayoutChecks.Run();
NativeLayoutStateChecks.Run();
NativeReaderSourceChecks.Run();
SignatureRenderChecks.Run();
SignatureContextChecks.Run();
SignatureOwnershipChecks.Run();
SignatureParserStateChecks.Run();
RuntimeNameChecks.Run();
MetadataIdentityChecks.Run();
TypeGraphChecks.Run();
TypeBindingChecks.Run();
SharedBindingChecks.Run();
SignatureComparisonChecks.Run();
BindingWorkspaceChecks.Run();
IterativeBindingChecks.Run();
RuntimeTypeIndexChecks.Run();
FatWriteExtentChecks.Run();
FrozenChecks.Run();
UnwindChecks.Run();
ManagedUnwindChecks.Run();
MethodGcChecks.Run();
MethodGcCancellationChecks.Run();
MarshallingChecks.Run([]);
TypeMapsChecks.Run();
CodeFlowChecks.Run();
PropertyAccessCodeChecks.Run();

foreach (string probe in args) {
    var image = new PeImage(File.ReadAllBytes(probe));
    var rtr = ReadyToRun.Read(image);

    var section = rtr.Find(313);
    var metadata = new MetadataBuilder(
        image.FileMemory(section.Start, checked((int)section.Length)),
        rtr.MetadataHandleBits, rtr.Major < 10);
    metadata.ReadDefinitions();

    var maps = new ReflectionMaps();
    var commonFixups = RuntimeTables.Fixups(image, rtr.Find(308));
    maps.Read(image, rtr, metadata, commonFixups);

    var extraction = new Extraction(image, rtr, metadata, maps, commonFixups);
    var hydrated = extraction.Hydrated;
    var types = extraction.Types;

    var start = new ProcessStartInfo(Path.GetFullPath(probe)) {
        RedirectStandardOutput = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };
    using var process = Process.Start(start)!;
    string output = process.StandardOutput.ReadToEnd();
    process.WaitForExit();
    Assert(process.ExitCode == 0);

    string[] lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    Assert(lines.Length == 9);

    foreach (string line in lines) {
        string[] parts = line.Split('|');
        ulong va = image.ImageBase + Convert.ToUInt64(parts[1], 16);
        var type = types.Types[types.Index[va]];
        Assert(type.IsValueType && type.ValueSize == uint.Parse(parts[2]));

        byte[] live = Convert.FromHexString(parts[3]);
        var bytes = va >= hydrated.Start && va - hydrated.Start < (ulong)hydrated.Length
            ? hydrated.Bytes.Slice(checked((int)(va - hydrated.Start)), 24)
            : image.FileSpan(va, 24);
        Assert(bytes[..8].SequenceEqual(live.AsSpan(0, 8)) && bytes[16..].SequenceEqual(live.AsSpan(16)));

        if (parts.Length == 5) {
            ulong baseAddress = Convert.ToUInt64(parts[4], 16);
            ulong related = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
            ulong expectedRelated = related == 0 ? 0 : related - image.ImageBase + baseAddress;
            Assert(BinaryPrimitives.ReadUInt64LittleEndian(live.AsSpan(8)) == expectedRelated);
        }
    }

    string pointerCheck = lines[0].Split('|').Length == 5 ? "including relocated pointers" : "ASLR pointer excluded";
    Console.WriteLine($"{probe}: RTR {rtr.Major}.{rtr.Minor}, 9/9 live MethodTable headers and value sizes match ({pointerCheck}).");

    foreach (ref readonly var peSection in image.Sections.AsSpan()) {
        if (peSection.FileSize == 0)
            continue;

        ulong last = image.ImageBase + peSection.Rva + (uint)peSection.FileSize - 1;
        Assert(image.FileSpan(last, 1)[0] == image.FileData[peSection.FileOffset + peSection.FileSize - 1]);

        bool failed = false;

        try {
            image.FileSpan(last, 2);
        } catch (InvalidDataException) {
            failed = true;
        }

        Assert(failed);
    }

    byte[] malformed = (byte[])image.FileData.Clone();
    BinaryPrimitives.WriteUInt64LittleEndian(malformed.AsSpan(rtr.FileOffset + 24), ulong.MaxValue);
    bool invalidRow = false;

    try {
        ReadyToRun.Read(new PeImage(malformed));
    } catch (InvalidDataException) {
        invalidRow = true;
    }

    Assert(invalidRow);
}

NativeStringChecks.Run();

HydrationChecks.Run();
HydrationBoundaryChecks.Run();
