using System.Buffers.Binary;
using System.Diagnostics;
using Atlas;

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

static void Assert(bool condition) {
    if (!condition)
        throw new Exception("Assertion failed.");
}

var random = new Random(0x41544C41);
byte[] buffer = new byte[9];
for (int sample = 0; sample < 100_000; ++sample) {
    uint value = sample < 256 ? (uint)sample : (uint)random.NextInt64(0, 1L << 32);
    int size = value < (1U << 7) ? 1 : value < (1U << 14) ? 2 : value < (1U << 21) ? 3 : value < (1U << 28) ? 4 : 5;
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
        } catch (InvalidDataException) { failed = true; }
        Assert(failed);
    }
}
foreach (byte invalid in new byte[] { 31, 63, 127, 255 }) {
    bool failed = false;
    try {
        var reader = new NativeReader(new byte[] { invalid, 0, 0, 0, 0 });
        reader.Unsigned();
    } catch (InvalidDataException) { failed = true; }
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
} catch (InvalidDataException) { unordered = true; }
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
foreach (byte[] invalid in new byte[][] { [6], [7], [0xE8], [0xF0, 0], [0xF8, 0, 0], [0x18, 1], [0x0D, 0, 0, 0], [0xFB, 0xFF, 0xFF, 0xFF] }) {
    bool failed = false;
    try {
        Hydration.Expand(invalid, 0, fixups, 0x1000, 0x1800, 0x2000, expanded);
    } catch (InvalidDataException) { failed = true; }
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
MetadataChecks.Run();
NativeLayoutChecks.Run();
TypeBindingChecks.Run();
FrozenChecks.Run();
UnwindChecks.Run();
ManagedUnwindChecks.Run();
MarshallingChecks.Run([]);
CodeFlowChecks.Run();

foreach (string probe in args) {
    var image = new PeImage(File.ReadAllBytes(probe));
    var rtr = ReadyToRun.Read(image);
    var section = rtr.Find(313);
    var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)), rtr.MetadataHandleBits, rtr.Major < 10);
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
        } catch (InvalidDataException) { failed = true; }
        Assert(failed);
    }
    byte[] malformed = (byte[])image.FileData.Clone();
    BinaryPrimitives.WriteUInt64LittleEndian(malformed.AsSpan(rtr.FileOffset + 24), ulong.MaxValue);
    bool invalidRow = false;
    try {
        ReadyToRun.Read(new PeImage(malformed));
    } catch (InvalidDataException) { invalidRow = true; }
    Assert(invalidRow);
}
NativeStringChecks.Run();
