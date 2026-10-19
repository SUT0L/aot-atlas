using Atlas;
using System.Buffers.Binary;

internal static class TypeGraphChecks {
    private const ulong ImageBase = 0x140000000;

    private const uint Class = 0x14U << 26;
    private const uint Generic = Class | 0x02000000;
    private const uint Definition = Class | 0x00030000;

    private readonly record struct Row(uint Flags = Class, int Related = -1, int Definition = -1, int Argument = -1);

    internal static void Run() {
        Rejects(() => Read([new(Related: 0)]), "Cyclic base type");
        Rejects(() => Read([new(Related: 1), new(Related: 0)]), "Cyclic base type");
        Rejects(() => Read([new(Generic, Definition: 1, Argument: 0), new(Definition)]),
            "Cyclic runtime type identity");
        Rejects(() => Read([
            new(Generic, Definition: 2, Argument: 1),
            new(Generic, Definition: 2, Argument: 0),
            new(Definition)
        ]), "Cyclic runtime type identity");
        Rejects(() => Read([new((0x1AU << 26) | 0x00020000, Related: 0)]), "Cyclic runtime type identity");

        // C : Base<C> forms a cycle only when two distinct graphs are incorrectly combined.
        var valid = Read([new(Related: 1), new(Generic, Definition: 2, Argument: 0), new(Definition)]);
        Assert(valid.Types.Count == 3 && valid.Types[1].GenericArity == 1, "Valid base/generic closure changed.");

        var names = new RuntimeNames(valid, new ReflectionMaps());
        Assert(names.Values[1] == $"mt_ref_{Address(2):X}<mt_ref_{Address(0):X}>", "Generic name postorder changed.");
        _ = new FieldLayouts(Metadata.Read(default, new(7)), new ReflectionMaps(), valid);

        var chain = new Row[4096];

        for (int i = 0; i < chain.Length; ++i)
            chain[i] = new(Related: i == chain.Length - 1 ? -1 : i + 1);

        Assert(Read(chain).Types.Count == chain.Length, "Deep base chain changed.");

        // Public tables can also be assembled by callers without invoking the PE reader.
        var manual = new MethodTables();
        int index = manual.Add(Address(0), TypeEvidence.TypeMap);
        manual.Types[index] = new MethodTable {
            Address = Address(0),
            Flags = Class,
            BaseSize = 24,
            RelatedType = Address(0)
        };

        Rejects(() => _ = new FieldLayouts(Metadata.Read(default, new(7)), new ReflectionMaps(), manual),
            "Cyclic base type");

        manual.Types[index] = new MethodTable {
            Address = Address(0),
            Flags = Generic,
            BaseSize = 24,
            GenericDefinition = Address(1),
            Arguments = new IndexRange(0, 1)
        };
        index = manual.Add(Address(1), TypeEvidence.TypeLink);
        manual.Types[index] = new MethodTable {
            Address = Address(1),
            Flags = Definition,
            GenericArity = 1
        };
        manual.Pointers.Add(Address(0));

        Rejects(() => _ = new RuntimeNames(manual, new ReflectionMaps()), "Cyclic runtime type identity");

        Console.WriteLine("Type graphs: source-boundary base and identity cycles reject; C : Base<C>, deep base chains and manual-table consumers passed.");
    }

    private static MethodTables Read(Row[] rows) {
        int length = checked(64 + rows.Length * 64);
        int aligned = (length + 511) / 512 * 512;
        byte[] bytes = new byte[512 + aligned];

        "MZ"u8.CopyTo(bytes);
        W32(60, 64);
        "PE\0\0"u8.CopyTo(bytes.AsSpan(64));
        W16(68, 0x8664);
        W16(70, 1);
        W16(84, 240);
        W16(88, 0x20B);

        W64(112, ImageBase);
        W32(120, 4096);
        W32(124, 512);
        W32(144, (uint)((0x2000 + length + 4095) / 4096 * 4096));
        W32(148, 512);
        W32(196, 16);

        ".rdata"u8.CopyTo(bytes.AsSpan(328));
        W32(336, (uint)length);
        W32(340, 0x2000);
        W32(344, (uint)aligned);
        W32(348, 512);
        W32(364, 0x40000040);

        "RTR\0"u8.CopyTo(bytes.AsSpan(512));
        W16(516, 16);
        W16(524, 1);
        bytes[526] = 24;
        bytes[527] = 1;
        W32(528, 1);
        W32(532, 1);
        W64(536, Address(0));
        W64(544, ImageBase + 0x2000 + (uint)length);

        for (int i = 0; i < rows.Length; ++i) {
            Row row = rows[i];
            int offset = 576 + i * 64;

            W32(offset, row.Flags);
            W32(offset + 4, row.Flags == Definition ? 1U : (row.Flags >> 26) == 0x1A ? 0U : 24U);

            if (row.Related >= 0)
                W64(offset + 8, Address(row.Related));

            W32(offset + 24, unchecked((uint)(-64 - i * 64 - 24)));

            if (row.Definition >= 0)
                W32(offset + 32, unchecked((uint)((row.Definition - i) * 64 - 32)));
            if (row.Argument >= 0)
                W32(offset + 36, unchecked((uint)((row.Argument - i) * 64 - 36)));
        }

        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var tables = new MethodTables();

        tables.Add(Address(0), TypeEvidence.TypeMap);
        tables.Read(image, header, new RuntimeMemory(image, default));

        return tables;

        void W16(int at, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(at), value);
        void W32(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        void W64(int at, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(at), value);
    }

    private static ulong Address(int index) => ImageBase + 0x2040 + (uint)index * 64;

    private static void Rejects(Action action, string message) {
        try {
            action();
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.Ordinal)) {
            return;
        }

        throw new InvalidOperationException($"Expected rejection: {message}.");
    }

    private static void Assert(bool value, string message) {
        if (!value)
            throw new InvalidOperationException(message);
    }
}
