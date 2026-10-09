using System.Buffers.Binary;
using Atlas;

internal static class HistoricalDictionaryChecks {
    internal static void Run() {
        TemplateRoots();
        var full = Decode(Fixture(9, 1), retainRecipes: true);
        var narrow = Decode(Fixture(9, 1), retainRecipes: false);

        // The .NET 7 writer emits these fourteen historical/common recipes followed
        // by a type handle. The final three types exist only beyond the old first gap.
        Assert(full.Dictionaries.Recipes.Count == 15);
        Assert(full.Dictionaries.SignatureGaps.IsEmpty);
        Assert(full.Native.ExternalTypes.Keys.Order().SequenceEqual(new ulong[] {
            0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888
        }));
        EqualGraph(full, narrow);
        Assert(narrow.Dictionaries.Recipes.Count == 0 && narrow.Dictionaries.SignatureGaps.IsEmpty);
        Assert(full.Dictionaries.MethodLayouts.SequenceEqual(new[] { 1, 1 }));
        Assert(full.Dictionaries.Layouts.Count == 1);

        var recipes = full.Dictionaries.Recipes;
        Assert(recipes[0].Kind == DictionaryFixup.IsInstance && recipes[0].Length == 10);
        Assert(recipes[4].Kind == DictionaryFixup.FieldOffset && recipes[4].Number == 7);
        Assert(recipes[5].Kind == DictionaryFixup.VTableOffset && recipes[5].Number == 9);
        Assert(recipes[8].Method.Identity.Name == "M" && recipes[8].Method.Offset == 400);
        Assert(recipes[9].Kind == DictionaryFixup.PointerToOtherSlot && recipes[9].Number == 0);
        Assert(recipes[10].Kind == DictionaryFixup.IntegerValue && recipes[10].EncodedKind == 0x20
            && unchecked((int)recipes[10].Number) == -1);
        Assert(recipes[11].Kind == DictionaryFixup.CallingConventionConverter
            && recipes[11].Number == 2 && recipes[11].PayloadOffset == 520);
        var converter = full.Metadata.SignatureBuilder.Methods[recipes[11].ConverterSignature];
        Assert(converter.Parameters.Count == 1
            && full.Metadata.SignatureBuilder.Nodes[converter.ReturnType].TypeAddress == 0x6666
            && full.Metadata.SignatureBuilder.Nodes[full.Metadata.SignatureBuilder.Edges[converter.Parameters.Start]].TypeAddress == 0x7777);
        Assert(recipes[12].Kind == DictionaryFixup.StaticConstrainedMethod && recipes[12].Number == 2);
        Assert(recipes[13].Method.Offset == 400 && recipes[14].Kind == DictionaryFixup.TypeHandle);

        foreach (var version in new (ushort Major, ushort Minor)[] { (10, 1), (12, 0), (16, 0), (18, 4), (18, 5) }) {
            var gated = Decode(Fixture(version.Major, version.Minor), retainRecipes: true);
            Assert(gated.Dictionaries.Recipes.Count == 0 && gated.Native.ExternalTypes.Count == 0);
            Assert(gated.Dictionaries.SignatureGaps.SequenceEqual(new[] { new DictionarySignatureGap(64, 69, 0x0e, 15) }));
        }

        foreach (var version in new (ushort Major, ushort Minor)[] {
            (9, 1), (10, 1), (12, 0), (16, 0), (18, 4), (18, 5)
        }) {
            var encodedSemanticTag = Fixture(version.Major, version.Minor);
            Put(encodedSemanticTag, 128 + 69, 0x10020);
            var rejected = Decode(encodedSemanticTag, retainRecipes: true);
            Assert(rejected.Dictionaries.Recipes.Count == 0 && rejected.Native.ExternalTypes.Count == 0);
            Assert(rejected.Dictionaries.SignatureGaps.SequenceEqual(new[] {
                new DictionarySignatureGap(64, 69, 0x10020, 15)
            }));
        }

        var unknown = Fixture(9, 1);
        Put(unknown, 128 + 69, 0x03);
        var gap = Decode(unknown, retainRecipes: false);
        Assert(gap.Native.ExternalTypes.Count == 0 && gap.Metadata.SignatureBuilder.Nodes.Length == 1);
        Assert(gap.Dictionaries.SignatureGaps.SequenceEqual(new[] { new DictionarySignatureGap(64, 69, 3, 15) }));

        var invalidPointer = Fixture(9, 1);
        Put(invalidPointer, 128 + recipes[9].PayloadOffset, 15);
        Reject(invalidPointer, "outside its layout");
        EqualGraph(full, Decode(invalidPointer, retainRecipes: false));

        var invalidConverter = Fixture(9, 1);
        Put(invalidConverter, 128 + recipes[11].Offset + 5, 3);
        Reject(invalidConverter, "outside 0..2");
        EqualGraph(full, Decode(invalidConverter, retainRecipes: false));

        Console.WriteLine("Historical dictionaries: .NET 7 grammar closes eight dictionary and five independent template roots; later versions retain exact gaps; integer/method collision, relative payloads, duplicate layouts, semantic faults and narrow closure pass.");
    }

    private static void TemplateRoots() {
        foreach (var version in new (ushort Major, ushort Minor)[] {
            (9, 1), (10, 1), (12, 0), (16, 0), (18, 4), (18, 5)
        }) {
            var image = PeFixture.Create(TemplateFixture(version.Major, version.Minor), ".rdata", 0x40000040);
            var header = ReadyToRun.Read(image);
            var storage = header.Find(RtrSectionId.NativeLayoutInfo);
            var metadata = new Metadata(default, header.MetadataHandleBits);
            var native = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
                [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
                    0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd], metadata.SignatureBuilder, takeOwnership: true);
            var templates = new TemplateMaps();
            templates.Types.Add(new TypeTemplate(0, 0, 0, default));
            var dictionaries = new GenericDictionaries();
            dictionaries.ReadSignatures(image, header, metadata, native, templates, MapFormat.Legacy);
            Assert(native.ExternalTypes.Count == 0);
            Assert(dictionaries.SignatureGaps.SequenceEqual(new[] { new DictionarySignatureGap(64, 69, 0xef, 2) }));

            // Each bag entry anchors its own grammar. An unknown dictionary payload
            // cannot hide the independently bounded fields or method signatures.
            templates.ReadSignatures(image, header, native);
            ulong[] expected = version.Major == 9 ? [0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd]
                : version.Major <= 12 ? [0x9999, 0xaaaa] : [];
            Assert(native.ExternalTypes.Keys.Order().SequenceEqual(expected));
            Assert(metadata.SignatureBuilder.Methods.Length == (version.Major == 9 ? 3 : 1));
        }

        RejectTemplate(15, int.MaxValue, "outside NativeLayout storage", []);
        RejectTemplate(96, 512, "signature count exceeds", []);
        RejectTemplate(101, 0, "field signature is null", []);
        RejectTemplate(101, 0x0c, "Unknown NativeLayout type signature", []);
        RejectTemplate(170, int.MaxValue, "method signature is outside", [0x9999, 0xaaaa]);
    }

    private static void RejectTemplate(int offset, uint replacement, string message, ulong[] completedRoots) {
        byte[] original = TemplateFixture(9, 1);
        byte[] changed = (byte[])original.Clone();
        Put(changed, 128 + offset, replacement);
        var image = PeFixture.Create(changed, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var storage = header.Find(RtrSectionId.NativeLayoutInfo);
        var metadata = new Metadata(default, 8);
        ulong[] references = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
            0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd];
        var native = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
            references, metadata.SignatureBuilder, takeOwnership: true);
        var templates = new TemplateMaps();
        templates.Types.Add(new TypeTemplate(0, 0, 0, default));
        bool rejected = false;
        try {
            templates.ReadSignatures(image, header, native);
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.Ordinal)) {
            rejected = true;
        }
        Assert(rejected && native.ExternalTypes.Keys.Order().SequenceEqual(completedRoots));

        original.CopyTo(image.FileData, 512);
        if (replacement == 0) {
            // Null is valid native grammar, rejected by the field owner. Replacing
            // successfully cached grammar requires the fresh owner used by Extraction.
            metadata = new Metadata(default, 8);
            native = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
                references, metadata.SignatureBuilder, takeOwnership: true);
        }
        templates.ReadSignatures(image, header, native);
        Assert(native.ExternalTypes.Keys.Order().SequenceEqual(new ulong[] {
            0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd
        }));
    }

    private static byte[] TemplateFixture(ushort major, ushort minor) {
        byte[] blob = new byte[512];
        int at = Put(blob, 0, 0x40);
        at = Put(blob, at, (uint)(64 - at), 0x4b);
        at = Put(blob, at, (uint)(96 - at), 0x4c);
        at = Put(blob, at, (uint)(160 - at), 0x51);
        Put(blob, at, (uint)(200 - at), 0);
        Put(blob, 64, 2, 0xef, 1, 0x16);
        Put(blob, 96, 2, 0x86, 0, 0x96, 3);
        at = Put(blob, 160, 1, 2);
        Put(blob, at, (uint)(240 - at));
        Put(blob, 200, 2, 1, 0xb6, 0xc6);
        Put(blob, 240, 2, 0, 0xa6);
        return Wrap(blob, major, minor);
    }

    private static (GenericDictionaries Dictionaries, NativeLayout Native, Metadata Metadata) Decode(byte[] data, bool retainRecipes) {
        var image = PeFixture.Create(data, ".rdata", 0x40000040);
        var header = ReadyToRun.Read(image);
        var storage = header.Find(RtrSectionId.NativeLayoutInfo);
        var metadata = new Metadata(default, header.MetadataHandleBits);
        var native = new NativeLayout(image.FileMemory(storage.Start, (int)storage.Length),
            [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888], metadata.SignatureBuilder, takeOwnership: true);
        var templates = new TemplateMaps();
        templates.Methods.Add(new MethodTemplate { LayoutOffset = 0 });
        templates.Methods.Add(new MethodTemplate { LayoutOffset = 0 });
        var dictionaries = new GenericDictionaries();
        if (retainRecipes)
            dictionaries.Read(image, header, metadata, native, templates, MapFormat.Legacy);
        else
            dictionaries.ReadSignatures(image, header, metadata, native, templates, MapFormat.Legacy);
        return (dictionaries, native, metadata);
    }

    private static byte[] Fixture(ushort major, ushort minor) {
        byte[] blob = new byte[640];
        int origin = Put(blob, 0, 0x40);
        Put(blob, origin, (uint)(64 - origin), 0);
        int at = Put(blob, 64, 15,
            0x0e, 6, 0x0f, 0x16, 0x10, 6, 0x12, 0x26,
            0x13, 0x36, 7, 0x15, 0x46, 9,
            0x16, 6, 0x16, 0, 0x18, 6, 0x16, 1,
            0x17, 0x26);
        at = Put(blob, at, (uint)(400 - at), 0x19, 0, 0x20, uint.MaxValue, 0x14, 2);
        at = Put(blob, at, (uint)(520 - at), 0x21, 6, 0x16, 2, 0x22, 0x26);
        at = Put(blob, at, (uint)(400 - at), 1, 0x76);
        Assert(at < 400);

        at = Put(blob, 400, 0, 6, 1);
        blob[at++] = (byte)'M';
        Put(blob, at, (uint)(480 - at));
        Put(blob, 480, 2, 0, 0x15);
        Put(blob, 520, 2, 1, 0x56, 0x66);

        return Wrap(blob, major, minor);
    }

    private static byte[] Wrap(byte[] blob, ushort major, ushort minor) {
        byte[] data = new byte[128 + blob.Length];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), major);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(6), minor);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 1);
        bool lengths = major == 18;
        data[14] = lengths ? (byte)16 : (byte)24;
        data[15] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(16), (int)RtrSectionId.NativeLayoutInfo);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(20), lengths ? (uint)blob.Length : 1);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(24), 0x140001080);
        if (!lengths)
            BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(32), 0x140001080UL + (uint)blob.Length);
        blob.CopyTo(data, 128);
        return data;
    }

    private static int Put(byte[] bytes, int offset, params uint[] values) {
        foreach (uint value in values) {
            bytes[offset++] = 15;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
            offset += 4;
        }
        return offset;
    }

    private static void EqualGraph(
        (GenericDictionaries Dictionaries, NativeLayout Native, Metadata Metadata) left,
        (GenericDictionaries Dictionaries, NativeLayout Native, Metadata Metadata) right) {
        Assert(left.Metadata.SignatureBuilder.Nodes.SequenceEqual(right.Metadata.SignatureBuilder.Nodes));
        Assert(left.Metadata.SignatureBuilder.Edges.SequenceEqual(right.Metadata.SignatureBuilder.Edges));
        Assert(left.Metadata.SignatureBuilder.Methods.SequenceEqual(right.Metadata.SignatureBuilder.Methods));
    }

    private static void Reject(byte[] data, string message) {
        try {
            Decode(data, retainRecipes: true);
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.Ordinal)) {
            return;
        }
        throw new InvalidDataException("Malformed historical dictionary semantics were accepted.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Historical dictionary assertion failed.");
    }
}
