using System.Buffers.Binary;
using Atlas;

internal static class TemplateRelationChecks {
    private const ulong DataAddress = 0x140001000;

    internal static void Run() {
        var image = Fixture();
        var full = Extract(image, ExtractionStage.All);
        Assert(full.Types.Types.Select(type => type.Address).SequenceEqual(new[] {
            DataAddress + 512, DataAddress + 576, DataAddress + 640,
            DataAddress + 704, DataAddress + 768
        }));
        Assert(full.Types.Pointers[full.Types.Types[0].Interfaces.Start] == 0);
        Assert(full.TypeTemplateBaseTypeAt(0).TypeAddress == DataAddress + 576);
        Assert(full.TypeTemplateInterfaceTypeAt(0, 0).TypeAddress == DataAddress + 768);
        Assert(full.Bindings.Resolve(full.TypeTemplateInterfaceTypeAt(0, 0)).Address == DataAddress + 768);
        Assert(full.Signatures.Nodes[1].Name == "Prefix" && full.Names.Values.Length == 5);

        var neutral = Extract(Changed(image, 512 + 4, 12, 0), ExtractionStage.RuntimeTypes);
        Assert(neutral.Maps.Format == MapFormat.Auto && neutral.Types.Types.SequenceEqual(full.Types.Types));
        Assert(neutral.Signatures.Nodes.SequenceEqual(full.Signatures.Nodes));

        for (int bits = 1; bits <= (int)ExtractionStage.All; ++bits) {
            var extraction = Extract(image, (ExtractionStage)bits);
            if ((extraction.Stages & ExtractionStage.RuntimeTypes) == 0) {
                Assert(!extraction.PhaseMeasurements.ToArray().Any(phase => phase.Phase == "TemplateSignatures"));
                continue;
            }

            Assert(extraction.Types.Types.SequenceEqual(full.Types.Types));
            Assert(extraction.Types.Pointers.SequenceEqual(full.Types.Pointers));
            Assert(extraction.Signatures.Nodes.SequenceEqual(full.Signatures.Nodes));
            Assert(extraction.Signatures.Edges.SequenceEqual(full.Signatures.Edges));
            Assert(extraction.Signatures.Methods.SequenceEqual(full.Signatures.Methods));
            Assert(extraction.Templates.Types.SequenceEqual(full.Templates.Types));
            Assert(extraction.Templates.Interfaces.SequenceEqual(full.Templates.Interfaces));
            Assert(extraction.Names.Values.SequenceEqual(full.Names.Values));
            Assert(extraction.Gc.Layouts.SequenceEqual(full.Gc.Layouts));
        }

        Reject(Changed(image, 512 + 128 + 64, 0), "base-type signature is null");
        Reject(Changed(image, 512 + 128 + 64, 15, 0x85, 0, 0, 0), "not a class type");
        Reject(Changed(image, 512 + 128 + 64, 0x24, 0x2c), "not a class type");
        Reject(Changed(image, 512 + 128 + 64, 12), "not a class type");
        Reject(Changed(image, 512 + 128 + 81, 0x2c), "no interface MethodTable");
        Reject(Changed(image, 512 + 128 + 81, 8), "no interface MethodTable");
        var genericInterface = Changed(image, 512 + 768, 0, 0, 3, 0x54, 1, 0, 0, 0);
        Reject(Changed(genericInterface, 512 + 128 + 81, 0x26, 12, 0x28), "variable is outside");
        Reject(Changed(genericInterface, 512 + 128 + 81, 0x26, 12, 0x48), "variable is outside");

        Console.WriteLine("Template relations: late runtime leaf closes after four stable roots; null canonical interface retains an owned signature; all 511 stage subsets preserve graphs/facts; invalid roots and owner variables reject.");
    }

    private static PeImage Changed(PeImage image, int offset, params byte[] replacement) {
        byte[] bytes = (byte[])image.FileData.Clone();
        replacement.CopyTo(bytes, offset);

        return new PeImage(bytes);
    }

    private static Extraction Extract(PeImage image, ExtractionStage stages) {
        var header = ReadyToRun.Read(image);
        var metadata = new Metadata(default, 7);
        metadata.SignatureBuilder.Named("Prefix");
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, [DataAddress + 512]);

        return new Extraction(image, header, metadata, maps, [DataAddress + 512], stages);
    }

    private static PeImage Fixture() {
        byte[] data = new byte[1024];
        "RTR\0"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 16);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(12), 3);
        data[14] = 24;
        data[15] = 1;
        Section(data, 16, RtrSectionId.TypeTemplateMap, 256, 7);
        Section(data, 40, RtrSectionId.NativeLayoutInfo, 128, 128);
        Section(data, 64, RtrSectionId.NativeReferences, 288, 8);

        // Bag: base at 64, interfaces at 80. Its interface target is absent
        // from the original owner/base/definition/argument MethodTable closure.
        data[128] = 2;
        data[129] = 126;
        data[130] = 4;
        data[131] = 15;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(132), 77);
        data[192] = 0x2c;
        data[208] = 2;
        data[209] = 12;

        new byte[] { 0, 2, 4, 0, 2, 0, 0 }.CopyTo(data, 256);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(288), 768 - 288);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(292), 576 - 292);

        Type(data, 512, 0x52000000, 24);
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(520), DataAddress + 576);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(530), 1);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(552), 640 - 552);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(556), 704 - 556);
        Type(data, 576, 0x50000000, 24);
        Type(data, 640, 0x50030000, 1);
        Type(data, 704, 0x50000000, 24);
        Type(data, 768, 0x54000000, 0);

        return PeFixture.Create(data, ".rdata", 0x40000040);
    }

    private static void Type(byte[] bytes, int offset, uint flags, uint size) {
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), flags);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 4), size);
    }

    private static void Section(byte[] bytes, int row, RtrSectionId id, int offset, int length) {
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(row), (int)id);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(row + 4), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(row + 8), DataAddress + (uint)offset);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(row + 16), DataAddress + (uint)(offset + length));
    }

    private static void Reject(PeImage image, string message) {
        try {
            Extract(image, ExtractionStage.RuntimeTypes);
        } catch (InvalidDataException error) when (error.Message.Contains(message, StringComparison.Ordinal)) {
            return;
        }

        throw new InvalidDataException("Malformed template relation was accepted.");
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Template relation assertion failed.");
    }
}
