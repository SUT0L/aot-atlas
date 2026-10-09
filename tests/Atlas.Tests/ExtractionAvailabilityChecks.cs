using System.Buffers.Binary;
using Atlas;

internal static class ExtractionAvailabilityChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            byte[] original = File.ReadAllBytes(binary);
            var healthy = Read(original);
            Assert(healthy.Maps.Types.Count != 0, "Fixture must have independent type-map evidence.");

            var image = healthy.Image;
            int row = image.FileRange(image.ImageBase + image.ExceptionRva).Start;
            uint unwindRva = BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(row + 8));
            Assert((unwindRva & 1) == 0, "Fixture's first unwind record must have a direct header.");
            int header = image.FileRange(image.ImageBase + unwindRva).Start;

            byte[] unsupported = (byte[])original.Clone();
            unsupported[header] = (byte)((unsupported[header] & ~7) | 7);

            var withoutUnwind = Read(unsupported);
            CompareIndependent(healthy, withoutUnwind);
            Rejects(() => _ = withoutUnwind.Unwind);
            Rejects(() => _ = withoutUnwind.Managed);
            Rejects(() => _ = new ManagedAbi(withoutUnwind));

            byte[] invalidRange = (byte[])original.Clone();
            original.AsSpan(row, 4).CopyTo(invalidRange.AsSpan(row + 4));

            var withoutRanges = Read(invalidRange);
            CompareIndependent(healthy, withoutRanges);
            Rejects(() => _ = withoutRanges.Unwind);

            byte[] invalidDebug = (byte[])original.Clone();
            int optional = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(60)) + 24);
            BinaryPrimitives.WriteUInt32LittleEndian(invalidDebug.AsSpan(optional + 112 + 6 * 8 + 4), 27);

            var withoutDebug = Read(invalidDebug);
            CompareIndependent(healthy, withoutDebug);
            Assert(withoutDebug.Unwind.DirectoryCount == healthy.Unwind.DirectoryCount,
                "Debug corruption must not disable Windows unwind.");
            Rejects(() => _ = withoutDebug.Debug);

            var startup = new RuntimeHelpers(image, healthy.Header, healthy.Memory, healthy.Unwind);

            if (startup.Status == RuntimeHelperStatus.Complete) {
                Assert(withoutDebug.Managed.RegionSource == ManagedRegionSource.Startup,
                    "Rejected debug records must not disable validated startup recovery.");
                Assert(withoutDebug.Managed.Frames.Length == healthy.Managed.Frames.Length,
                    "Recovered managed frame count changed.");
                Assert(withoutDebug.Managed.Clauses.Length == healthy.Managed.Clauses.Length,
                    "Recovered exception clause count changed.");
            }

            byte[] invalidBoth = (byte[])invalidDebug.Clone();
            invalidBoth[header] = unsupported[header];

            var withoutBoth = Read(invalidBoth);
            CompareIndependent(healthy, withoutBoth);
            Assert(withoutBoth.UnwindAnalysis.Failures.Any(failure => failure.Phase == UnwindPhase.Unwind),
                "Windows unwind failure was lost.");
            Assert(withoutBoth.UnwindAnalysis.Failures.Any(failure => failure.Phase == UnwindPhase.PeDebug),
                "Independent debug failure was lost.");

            if (healthy.Managed.Frames.Length != 0) {
                byte[] invalidManaged = (byte[])original.Clone();
                uint trailer = healthy.Managed.Frames[0].Trailer;
                invalidManaged[image.FileRange(image.ImageBase + trailer).Start] = 32;

                var withoutManaged = Read(invalidManaged);
                CompareIndependent(healthy, withoutManaged);
                Assert(withoutManaged.Unwind.DirectoryCount == healthy.Unwind.DirectoryCount,
                    "Managed trailer corruption must not disable Windows unwind.");
                Rejects(() => _ = withoutManaged.Managed);
                CheckCatchClosure(healthy);
            }

            byte[] invalidMetadata = (byte[])unsupported.Clone();
            int metadataStart = image.FileRange(healthy.Header.Find(RtrSectionId.EmbeddedMetadata).Start).Start;
            "BAD!"u8.CopyTo(invalidMetadata.AsSpan(metadataStart));

            Rejects(() => _ = Read(invalidMetadata));
            Console.WriteLine($"Extraction availability: {binary}; independent maps, types, frozen objects, statics and dispatch survive unwind faults; unrelated metadata corruption rejects.");
        }
    }

    private static void CheckCatchClosure(Extraction healthy) {
        var clause = healthy.Managed.Clauses.FirstOrDefault(value => value.Kind == ExceptionClauseKind.Typed);

        if (clause.TypeCell == 0)
            throw new InvalidOperationException("Catch closure fixture must retain a typed exception clause.");

        foreach (var valid in healthy.Managed.Clauses) {
            if (valid.Kind == ExceptionClauseKind.Typed)
                Assert((healthy.Types.Types[healthy.Types.Index[healthy.Image.ImageBase + valid.Type]].Evidence
                    & TypeEvidence.ExceptionHandling) != 0, "A validated catch root was not published.");
        }

        for (int fault = 0; fault < 5; ++fault) {
            byte[] changed = AddCandidateStorage(healthy.Image, out uint candidateRva, out int candidateOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(
                changed.AsSpan(healthy.Image.FileRange(healthy.Image.ImageBase + clause.TypeCell).Start), candidateRva);

            if (fault == 4) {
                ulong address = healthy.Image.ImageBase + candidateRva;
                ulong definition = healthy.Types.Types.First(type => type.Kind == 3 && type.GenericArity == 1).Address;
                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(candidateOffset), 0x52000000);
                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(candidateOffset + 4), 24);
                BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(candidateOffset + 32),
                    checked((int)((long)definition - (long)address - 32)));
                BinaryPrimitives.WriteInt32LittleEndian(changed.AsSpan(candidateOffset + 36), -36);
            } else if (fault != 0) {
                uint flags = 0x14U << 26;

                if (fault == 2)
                    flags |= healthy.Header.Major < 10 ? 0x00200000U : 0x01000000U;

                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(candidateOffset), flags);
                BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(candidateOffset + 4), 24);

                if (fault == 3)
                    BinaryPrimitives.WriteUInt64LittleEndian(changed.AsSpan(candidateOffset + 8),
                        healthy.Image.ImageBase + candidateRva);
                else if (fault == 1)
                    BinaryPrimitives.WriteUInt64LittleEndian(changed.AsSpan(candidateOffset + 8),
                        healthy.Image.ImageBase + candidateRva + 64);
                else {
                    BinaryPrimitives.WriteUInt16LittleEndian(changed.AsSpan(candidateOffset + 16), 1);
                    BinaryPrimitives.WriteUInt64LittleEndian(changed.AsSpan(candidateOffset + 24),
                        healthy.Image.ImageBase + healthy.Unwind.Entries[0].Function.Begin);
                }
            }

            var damaged = Read(changed);
            CompareIndependent(healthy, damaged);
            Assert(damaged.Unwind.DirectoryCount == healthy.Unwind.DirectoryCount,
                "Catch EEType corruption discarded valid Windows unwind.");
            Assert(damaged.Debug.Entries.Count == healthy.Debug.Entries.Count,
                "Catch EEType corruption discarded valid PE debug records.");
            Assert(!damaged.Types.Index.ContainsKey(healthy.Image.ImageBase + candidateRva)
                && !damaged.Types.Index.ContainsKey(healthy.Image.ImageBase + candidateRva + 64),
                "Rejected optional type closure leaked into core ownership.");
            Assert(damaged.UnwindAnalysis.Failures.Any(failure => failure.Phase == UnwindPhase.ManagedUnwind
                && failure.Error.Contains(fault == 4 ? "Cyclic runtime type identity"
                    : fault == 3 ? "Cyclic base type" : fault == 2 ? "Empty GCDesc" : "Invalid allocation size",
                    StringComparison.Ordinal)), "Catch closure failure was not exposed.");
            Rejects(() => _ = damaged.Managed);
        }
    }

    private static byte[] AddCandidateStorage(PeImage image, out uint candidateRva, out int candidateOffset) {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.FileData.AsSpan(60));
        int optional = nt + 24;
        int section = optional + BinaryPrimitives.ReadUInt16LittleEndian(image.FileData.AsSpan(nt + 20))
            + image.Sections.Length * 40;
        Assert(section + 40 <= image.HeaderSize, "Fixture needs room for an additional section header.");

        uint sectionAlignment = BinaryPrimitives.ReadUInt32LittleEndian(image.FileData.AsSpan(optional + 32));
        uint fileAlignment = BinaryPrimitives.ReadUInt32LittleEndian(image.FileData.AsSpan(optional + 36));
        uint sectionRva = checked((image.ImageSize + sectionAlignment - 1) / sectionAlignment * sectionAlignment);
        int fileOffset = checked((image.FileData.Length + (int)fileAlignment - 1)
            / (int)fileAlignment * (int)fileAlignment);

        byte[] changed = new byte[checked(fileOffset + (int)fileAlignment)];
        image.FileData.CopyTo(changed, 0);
        ".ehcheck"u8.CopyTo(changed.AsSpan(section));
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(section + 8), 128);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(section + 12), sectionRva);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(section + 16), fileAlignment);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(section + 20), (uint)fileOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(section + 36), 0x40000040);
        BinaryPrimitives.WriteUInt16LittleEndian(changed.AsSpan(nt + 6), checked((ushort)(image.Sections.Length + 1)));
        BinaryPrimitives.WriteUInt32LittleEndian(changed.AsSpan(optional + 56), checked(sectionRva + sectionAlignment));

        candidateRva = sectionRva + 8;
        candidateOffset = fileOffset + 8;
        return changed;
    }

    private static Extraction Read(byte[] bytes) {
        var image = new PeImage(bytes);
        var header = ReadyToRun.Read(image);
        var section = header.Find(RtrSectionId.EmbeddedMetadata);
        var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Major < 10);
        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = new ReflectionMaps();
        maps.Read(image, header, metadata, fixups, MapFormat.Auto);

        return new Extraction(image, header, metadata, maps, fixups);
    }

    private static void CompareIndependent(Extraction healthy, Extraction damaged) {
        Assert(damaged.Metadata.Types.Count == healthy.Metadata.Types.Count, "Metadata definitions changed.");
        Assert(damaged.Metadata.Methods.Count == healthy.Metadata.Methods.Count, "Metadata methods changed.");
        Assert(damaged.Maps.Types.Count == healthy.Maps.Types.Count, "Type map changed.");

        foreach (var entry in healthy.Maps.Types) {
            Assert(damaged.Types.Index.ContainsKey(entry.MethodTable), "A mapped runtime type was lost.");

            var expected = healthy.Types.Types[healthy.Types.Index[entry.MethodTable]];
            var actual = damaged.Types.Types[damaged.Types.Index[entry.MethodTable]];
            Assert(actual.Flags == expected.Flags && actual.BaseSize == expected.BaseSize && actual.Hash == expected.Hash,
                "A mapped runtime type's independently encoded layout changed.");
        }

        Assert(damaged.Frozen.Objects.Count == healthy.Frozen.Objects.Count, "Frozen allocations changed.");
        Assert(damaged.Statics.Allocations.Count == healthy.Statics.Allocations.Count, "Static allocations changed.");
        Assert(damaged.Dispatch.Targets.Count == healthy.Dispatch.Targets.Count, "Dispatch targets changed.");
    }

    private static void Rejects(Action action) {
        bool rejected = false;

        try {
            action();
        } catch (InvalidDataException) {
            rejected = true;
        }

        Assert(rejected, "Required unavailable analysis or malformed metadata must reject.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
