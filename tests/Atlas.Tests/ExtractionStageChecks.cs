using System.Buffers.Binary;
using Atlas;

internal static class ExtractionStageChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        Assert(ExtractionPlan.Required(ExtractionStage.MemberLayouts)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.MemberLayouts));
        Assert(ExtractionPlan.Required(ExtractionStage.Dispatch)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.Dispatch));
        Assert(ExtractionPlan.Required(ExtractionStage.MethodTracing)
            == (ExtractionStage.RuntimeTypes | ExtractionStage.MethodTracing));
        Assert(ExtractionPlan.Required(ExtractionStage.All) == ExtractionStage.All);

        foreach (var request in new[] { ExtractionStage.None, (ExtractionStage)512 }) {
            bool invalid = false;

            try {
                ExtractionPlan.Required(request);
            } catch (ArgumentOutOfRangeException) {
                invalid = true;
            }

            Assert(invalid);
        }

        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var full = Extraction.Read(image);
            var types = Extraction.Read(image, ExtractionStage.RuntimeTypes);

            Assert(types.Stages == ExtractionStage.RuntimeTypes);
            Assert(types.Types.Types.SequenceEqual(full.Types.Types)
                && types.Types.Pointers.SequenceEqual(full.Types.Pointers));
            Assert(types.Names.Values.SequenceEqual(full.Names.Values)
                && types.Names.Complete.SequenceEqual(full.Names.Complete));
            Assert(types.Gc.Layouts.SequenceEqual(full.Gc.Layouts) && types.Gc.Runs.SequenceEqual(full.Gc.Runs));
            Assert(types.Frozen.Objects.SequenceEqual(full.Frozen.Objects));
            Assert(types.Statics.Fields.SequenceEqual(full.Statics.Fields));
            Assert(types.Generics.Types.SequenceEqual(full.Generics.Types));
            Assert(types.Templates.Types.Count == full.Templates.Types.Count);
            for (int i = 0; i < types.Templates.Types.Count; i++) {
                var selected = types.Templates.Types[i];
                var complete = full.Templates.Types[i];
                Assert(selected.Vertex == complete.Vertex && selected.MethodTable == complete.MethodTable
                    && selected.LayoutOffset == complete.LayoutOffset && selected.Facts.Equals(complete.Facts)
                    && selected.BaseType.Offset == complete.BaseType.Offset
                    && selected.Interfaces.Equals(complete.Interfaces));
                Assert(types.Signatures.RenderType(selected.BaseType.Signature)
                    == full.Signatures.RenderType(complete.BaseType.Signature));
            }

            AssertMissing(() => types.Fields);
            AssertMissing(() => types.Shared);
            AssertMissing(() => types.Dispatch);
            AssertMissing(() => types.Virtuals);
            AssertMissing(() => types.Enums);
            AssertMissing(() => types.Dictionaries);
            AssertMissing(() => types.Traces);

            var members = Extraction.Read(image, ExtractionStage.MemberLayouts);

            Assert(members.Fields.Fields.SequenceEqual(full.Fields.Fields)
                && members.Fields.FieldTypes.Count == full.Fields.FieldTypes.Count);
            for (int i = 0; i < members.Fields.FieldTypes.Count; i++) {
                var selected = members.Fields.FieldTypes[i];
                var complete = full.Fields.FieldTypes[i];
                Assert(selected.MapIndex == complete.MapIndex && selected.Owner == complete.Owner
                    && selected.Binding == complete.Binding && selected.MetadataOffset == complete.MetadataOffset
                    && selected.Size == complete.Size && selected.Storage == complete.Storage && selected.Source == complete.Source);
                Assert(members.Signatures.RenderType(selected.Signature) == full.Signatures.RenderType(complete.Signature));
            }
            Assert(members.Shared.Templates.SequenceEqual(full.Shared.Templates));
            AssertMissing(() => members.Dispatch);
            AssertMissing(() => members.Dictionaries);
            AssertMissing(() => members.Traces);

            var dispatch = Extraction.Read(image, ExtractionStage.Dispatch);

            Assert(dispatch.Dispatch.Targets.SequenceEqual(full.Dispatch.Targets)
                && dispatch.Dispatch.Entries.SequenceEqual(full.Dispatch.Entries));
            AssertMissing(() => dispatch.Fields);
            AssertMissing(() => dispatch.Enums);
            AssertMissing(() => dispatch.Dictionaries);
            AssertMissing(() => dispatch.Traces);

            var corruptible = full.Dispatch.Maps.FirstOrDefault(map => map.Entries.Count != 0
                && full.Memory.Find(map.Address + 8) >= 0
                && !full.Memory.Regions[full.Memory.Find(map.Address + 8)].Hydrated);

            if (corruptible.Address == 0)
                throw new InvalidOperationException("Stage fault fixture needs a file-backed dispatch entry.");

            byte[] changed = (byte[])image.FileData.Clone();
            BinaryPrimitives.WriteUInt16LittleEndian(
                changed.AsSpan(image.FileRange(corruptible.Address + 8).Start), ushort.MaxValue);

            var corrupt = new PeImage(changed);
            var independent = Extraction.Read(corrupt, ExtractionStage.RuntimeTypes);
            Assert(independent.Types.Types.SequenceEqual(types.Types.Types));

            bool rejected = false;

            try {
                _ = Extraction.Read(corrupt, ExtractionStage.Dispatch);
            } catch (InvalidDataException error) when (error.Message.Contains("exceeds the interface list", StringComparison.Ordinal)) {
                rejected = true;
            }

            Assert(rejected);

            Console.WriteLine($"{Path.GetFileName(binary)}: {full.Types.Types.Count} type records preserved across plans; member/dispatch outputs equal; omitted stages explicit; corrupt dispatch cannot block independent type extraction.");
        }
    }

    private static void AssertMissing(Func<object> access) {
        bool missing = false;

        try {
            _ = access();
        } catch (InvalidOperationException) {
            missing = true;
        }

        Assert(missing);
    }

    private static void Assert(bool condition) {
        if (!condition)
            throw new InvalidDataException("Extraction stage assertion failed.");
    }
}
