using System.Buffers.Binary;
using Atlas;

internal static class FrozenChecks {
    internal static void Run() {
        const ulong start = 0x140001000;
        byte[] pe = new byte[256];
        "MZ"u8.CopyTo(pe);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(60), 64);
        "PE\0\0"u8.CopyTo(pe.AsSpan(64));
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(68), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(84), 112);
        BinaryPrimitives.WriteUInt16LittleEndian(pe.AsSpan(88), 0x20B);
        BinaryPrimitives.WriteUInt64LittleEndian(pe.AsSpan(112), start - 0x1000);
        BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(144), 0x10000);
        var image = new PeImage(pe);

        byte[] data = new byte[1024];
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(8), start + 512);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), 4);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), start + 536);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(64), start + 560);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(88), start + 560);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(96), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(100), 0xD800);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(512), 0xE0020008);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(516), 24);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(536), 0x2C000000);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(540), 24);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(560), 0xD0000002);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(564), 22);

        var memory = new RuntimeMemory(image, new HydratedRegion(start, data, data.Length));
        var tables = new MethodTables();
        var frozen = new FrozenObjects(new RtrSection(206, 1, start, 112), memory, tables);
        Assert(frozen.Objects.Count == 3 && tables.Types.Count == 2);
        Assert(!tables.Index.ContainsKey(start + 536));
        Assert(frozen.Objects[0].Offset == 8 && frozen.Objects[0].Count == 4);
        Assert(frozen.Objects[1].Kind == FrozenKind.String && frozen.Objects[1].Count == 0);
        Assert(frozen.Objects[2].UnpairedSurrogate && frozen.Objects[2].Data.Count == 2);

        var empty = new FrozenObjects(new RtrSection(206, 1, start + 104, 8), memory, new MethodTables());
        Assert(empty.Objects.Count == 0);
        for (int fault = 0; fault < 5; ++fault) {
            byte[] malformed = (byte[])data.Clone();
            if (fault == 0)
                malformed[104] = 1;
            else if (fault == 1)
                malformed[0] = 1;
            else if (fault == 2)
                BinaryPrimitives.WriteInt32LittleEndian(malformed.AsSpan(16), -1);
            else if (fault == 3)
                BinaryPrimitives.WriteInt32LittleEndian(malformed.AsSpan(16), int.MaxValue);
            else
                malformed[102] = 1;

            bool failed = false;
            try {
                var invalidMemory = new RuntimeMemory(image, new HydratedRegion(start, malformed, malformed.Length));
                _ = new FrozenObjects(new RtrSection(206, 1, start, 112), invalidMemory, new MethodTables());
            } catch (InvalidDataException) { failed = true; }
            Assert(failed);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), start + 8);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), start + 64);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(48), start + 8);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(488), -24);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(496), 16);
        BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(504), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(512), 0xE1020008);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(536), 0x50000000);
        tables = new MethodTables();
        frozen = new FrozenObjects(new RtrSection(206, 1, start, 112), memory, tables);
        tables.Types[0] = new MethodTable {
            Address = start + 512,
            Flags = 0xE1020008,
            BaseSize = 24,
            RelatedType = start + 536,
            Evidence = TypeEvidence.FrozenObject
        };
        tables.Types[1] = new MethodTable { Address = start + 560, Flags = 0xD0000002, BaseSize = 22 };
        int objectType = tables.Add(start + 536, TypeEvidence.TypeLink);
        tables.Types[objectType] = new MethodTable { Address = start + 536, Flags = 0x50000000, BaseSize = 24 };
        var gc = new GcLayouts();
        gc.Read(tables, memory, false);
        Assert(gc.Layouts.Count == 1 && gc.Unproven.Count == 0);
        frozen.Bind(tables, gc);
        Assert(frozen.References.Count == 3 && frozen.NullReferences == 1);
        Assert(frozen.References[0].Offset == 16 && frozen.References[0].Target == 0);
        Assert(frozen.References[1].Offset == 24 && frozen.References[1].Target == 1);
        Assert(frozen.References[2].Offset == 40 && frozen.References[2].Target == 0);

        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), start + 536);
        bool rejected = false;
        try {
            new FrozenObjects(new RtrSection(206, 1, start, 112), memory, tables).Bind(tables, gc);
        } catch (NotSupportedException) { rejected = true; }
        Assert(rejected);

        byte[] matrix = new byte[1024];
        BinaryPrimitives.WriteUInt64LittleEndian(matrix.AsSpan(8), start + 512);
        BinaryPrimitives.WriteInt32LittleEndian(matrix.AsSpan(16), 6);
        BinaryPrimitives.WriteInt32LittleEndian(matrix.AsSpan(24), 2);
        BinaryPrimitives.WriteInt32LittleEndian(matrix.AsSpan(28), 3);
        BinaryPrimitives.WriteInt32LittleEndian(matrix.AsSpan(32), -2);
        BinaryPrimitives.WriteInt32LittleEndian(matrix.AsSpan(36), 5);
        BinaryPrimitives.WriteUInt32LittleEndian(matrix.AsSpan(512), 0xDC020004);
        BinaryPrimitives.WriteUInt32LittleEndian(matrix.AsSpan(516), 40);
        memory = new RuntimeMemory(image, new HydratedRegion(start, matrix, matrix.Length));
        frozen = new FrozenObjects(new RtrSection(206, 1, start, 72), memory, new MethodTables());
        Assert(frozen.Objects.Count == 1 && frozen.Objects[0].Count == 6);
        Assert(frozen.Objects[0].Data.Start == 40 && frozen.Objects[0].Data.Count == 24);

        Console.WriteLine("Frozen objects: interior fake headers, exact boundaries, lone surrogates, zero-slot construction, cycles, and GC reference targets passed.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Frozen allocation boundary differs from the fixture.");
    }
}
