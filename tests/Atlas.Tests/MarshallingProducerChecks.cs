using System.Globalization;
using System.Text;
using Atlas;

internal static class MarshallingProducerChecks {
    private readonly record struct Layout(
        string Name, uint Size, NativeSizeSource SizeSource, string[] Names, uint[] Offsets);

    // These extents follow the declarations in MarshallingProbe: byte packing,
    // four-byte native BOOLs, UTF-16 inline text, and eight-byte native pointers.
    private static readonly Layout[] Layouts = [
        new("Blittable", 9, NativeSizeSource.MethodTable, ["Tag", "Value"], [0, 1]),
        new("NativeBool", 7, NativeSizeSource.MarshallingMap, ["Tag", "Enabled", "Code"], [0, 1, 5]),
        new("Inline", 20, NativeSizeSource.MarshallingMap, ["Code", "Text", "Samples"], [0, 2, 14]),
        new("Owned", 16, NativeSizeSource.MarshallingMap, ["Text", "Number"], [0, 8]),
        new("LayoutClass", 7, NativeSizeSource.MarshallingMap, ["Tag", "Enabled", "Code"], [0, 1, 5])
    ];

    internal static void Run(string binary, string linkerMap) {
        var image = PeImage.ReadFile(binary);
        var symbols = ReadSymbols(linkerMap);
        var selected = Extraction.Read(image, ExtractionStage.RuntimeTypes);
        var full = Extraction.Read(image);

        Check(selected.Stages == ExtractionStage.RuntimeTypes, "The narrow extraction added stages.");
        CheckLayouts(selected, symbols);
        CheckLayouts(full, symbols);

        Console.WriteLine($"Marshalling producer: {binary}; five declared layouts, thirteen fields, invalid layout, four conversion/cleanup triplets and delegate stubs matched source declarations and linker symbols.");
    }

    private static void CheckLayouts(Extraction extraction, Dictionary<string, ulong> symbols) {
        var marshalling = extraction.Marshalling;
        Check(marshalling.StructEntries.Length == 6 && marshalling.FieldEntries.Length == 13
            && marshalling.DelegateEntries.Length == 1, "The producer fixture lost positive marshalling records.");

        foreach (var expected in Layouts) {
            ulong address = TypeAddress(symbols, expected.Name, expected.Name != "LayoutClass");
            int position = StructPosition(extraction, address);
            var entry = marshalling.StructEntries[position];
            Check(extraction.NativeStructTypeAt(position).Address == address,
                $"{expected.Name}: public runtime reference differs from the linker type symbol.");
            Check(extraction.Names.Values[entry.TypeIndex] == $"MarshallingFixture.{expected.Name}",
                $"{expected.Name}: retained type name differs from the source declaration.");
            Check(entry.Size == expected.Size && entry.SizeSource == expected.SizeSource
                && entry.HasLayoutSize && !entry.InvalidLayout && entry.Fields.Count == expected.Names.Length,
                $"{expected.Name}: native size or layout provenance differs from the source declaration.");

            bool blittable = expected.Name == "Blittable";
            if (blittable) {
                Check(entry.ToNative == 0 && entry.ToManaged == 0 && entry.Cleanup == 0,
                    "A blittable layout invented marshalling stubs.");
            } else {
                CheckStub(extraction, symbols, entry.ToNative, "ManagedToNative", expected.Name);
                CheckStub(extraction, symbols, entry.ToManaged, "NativeToManaged", expected.Name);
                CheckStub(extraction, symbols, entry.Cleanup, "Cleanup", expected.Name);
            }

            for (int i = 0; i < expected.Names.Length; ++i) {
                var field = marshalling.FieldEntries[entry.Fields.Start + i];
                string name = Encoding.UTF8.GetString(marshalling.StructBytes.Slice(field.Name.Start, field.Name.Count));
                Check(name == expected.Names[i] && field.Offset == expected.Offsets[i],
                    $"{expected.Name}.{expected.Names[i]}: field offset or name differs from its declaration.");
            }
        }

        int invalidPosition = StructPosition(extraction, TypeAddress(symbols, "InvalidLayout", true));
        var invalid = marshalling.StructEntries[invalidPosition];
        Check(invalid.InvalidLayout && invalid.Size == 0 && invalid.SizeSource == NativeSizeSource.Unknown
            && !invalid.HasLayoutSize && invalid.Fields.Count == 0 && invalid.ToNative == 0
            && invalid.ToManaged == 0 && invalid.Cleanup == 0,
            "An invalid layout published native fields, size, or callable stubs.");

        var callback = marshalling.DelegateEntries[0];
        ulong callbackAddress = TypeAddress(symbols, "Callback", false);
        Check(extraction.NativeDelegateTypeAt(0).Address == callbackAddress,
            "The callback runtime reference differs from its linker type symbol.");
        CheckStub(extraction, symbols, callback.Open, "ReverseOpenStaticDelegateStub", "Callback");
        CheckStub(extraction, symbols, callback.Closed, "ReverseDelegateStub", "Callback");
        CheckStub(extraction, symbols, callback.Create, "ForwardDelegateCreationStub", "Callback");
    }

    private static void CheckStub(
        Extraction extraction, Dictionary<string, ulong> symbols, ulong address,
        string operation, string name) {
        var matches = symbols.Where(symbol => symbol.Key.StartsWith("Internal_CompilerGenerated__Module___<", StringComparison.Ordinal)
            && symbol.Key.Contains($"<{operation}>", StringComparison.Ordinal)
            && symbol.Key.EndsWith($"_MarshallingFixture_{name}", StringComparison.Ordinal)).ToArray();
        Check(matches.Length == 1 && matches[0].Value == address
            && extraction.Image.IsExecutable(address),
            $"{name}: {operation} differs from the linker stub symbol.");
    }

    private static ulong TypeAddress(Dictionary<string, ulong> symbols, string name, bool valueType) {
        string prefix = valueType ? "??_7Boxed_" : "??_7";
        return symbols.Single(symbol => symbol.Key.StartsWith(prefix, StringComparison.Ordinal)
            && !symbol.Key.Contains('<')
            && symbol.Key.EndsWith($"_MarshallingFixture_{name}@@6B@", StringComparison.Ordinal)).Value;
    }

    private static int StructPosition(Extraction extraction, ulong address) {
        for (int i = 0; i < extraction.Marshalling.StructEntries.Length; ++i)
            if (extraction.NativeStructTypeAt(i).Address == address)
                return i;

        throw new Exception($"Missing compiler-produced struct at 0x{address:X}.");
    }

    private static Dictionary<string, ulong> ReadSymbols(string path) {
        var symbols = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(path)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length >= 3 && columns[0].Contains(':')
                && ulong.TryParse(columns[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong address))
                symbols.TryAdd(columns[1], address);
        }
        return symbols;
    }

    private static void Check(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
