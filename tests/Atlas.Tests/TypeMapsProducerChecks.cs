using System.Buffers.Binary;
using Atlas;
using Atlas.Binja;

internal static class TypeMapsProducerChecks {
    internal static void Run(string binary) {
        var image = PeImage.ReadFile(binary);
        var header = ReadyToRun.Read(image);
        var metadata = Metadata.FromImage(image, header);

        metadata.ReadDefinitions();

        var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
        var selected = new Extraction(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
        var prepared = new PreparedAnalysis(image, header, metadata, maps, fixups);
        var full = prepared.Extraction;

        foreach (var extraction in new[] { selected, full }) {
            var external = extraction.TypeMaps.External;
            var proxy = extraction.TypeMaps.Proxy;

            Check(external.Present && proxy.Present, "Producer omitted the map sections.");
            Check(external.Groups.Length == 4 && external.Entries.Length == 3
                && proxy.Groups.Length == 3 && proxy.Entries.Length == 4, "Unexpected retained group or mapping counts.");

            var externalMaps = Group(external, "Maps", extraction);
            var proxyMaps = Group(proxy, "Maps", extraction);
            var names = external.Entries.Slice(externalMaps.Entries.Start, externalMaps.Entries.Count).ToArray()
                .Select(entry => entry.Name).ToHashSet();

            Check(names.SetEquals(["alpha", "é😀", "conditional"]), "External names or trimming differ from source declarations.");

            var sources = proxy.Entries.Slice(proxyMaps.Entries.Start, proxyMaps.Entries.Count).ToArray()
                .Select(entry => Name(extraction, entry.SourceType)).ToHashSet();
            Check(sources.SetEquals(["Source", "Source[]", "System.Collections.Generic.List`1<System.Int32>",
                "System.Collections.Generic.List`1"]), "Proxy types or trimming differ from source declarations.");

            Check(!Group(external, "Missing", extraction).IsValid
                && !Group(external, "Invalid", extraction).IsValid
                && !Group(proxy, "Missing", extraction).IsValid, "Compiler-invalid groups became valid or disappeared.");
            Check(Group(external, "Empty", extraction).IsValid && Group(external, "Empty", extraction).Entries.Count == 0
                && Group(proxy, "Empty", extraction).IsValid && Group(proxy, "Empty", extraction).Entries.Count == 0,
                "Empty compiler groups disappeared.");

            foreach (var typeMap in new[] { external, proxy }) {
                var evidence = typeMap.Section == RtrSectionId.ExternalTypeMap
                    ? TypeEvidence.ExternalTypeMap : TypeEvidence.ProxyTypeMap;
                foreach (var group in typeMap.Groups) {
                    Check(fixups[group.GroupFixup] == group.GroupType, "Group CommonFixups provenance changed.");
                    Check((extraction.Types.Types[extraction.Types.Index[group.GroupType]].Evidence & evidence) != 0,
                        "Group runtime type lacks map evidence.");
                    if (!group.IsValid) {
                        Check(group.ThrowingStub == fixups[group.ThrowingStubFixup] && image.IsExecutable(group.ThrowingStub),
                            "Invalid-group function pointer differs from compiler storage.");
                    }
                }

                foreach (var entry in typeMap.Entries) {
                    Check(Name(extraction, entry.TargetType) == "Target" && fixups[entry.TargetFixup] == entry.TargetType,
                        "Target relationship differs from source declaration or compiler fixup.");
                    Check((extraction.Types.Types[extraction.Types.Index[entry.TargetType]].Evidence & evidence) != 0,
                        "Target type lacks map evidence.");
                    if (entry.SourceType != 0)
                        Check(entry.SourceType == fixups[entry.SourceFixup], "Source CommonFixups provenance changed.");
                }
            }
        }

        var normal = AnalysisEvidence.Read(prepared, image.ImageBase);
        const ulong delta = 0x10000000;
        var rebased = AnalysisEvidence.Read(prepared, image.ImageBase + delta);
        Check(rebased.References.ToHashSet().SetEquals(normal.References.Select(reference =>
            new AnalysisReference(reference.From + delta, reference.To + delta))), "Producer host references failed rebasing.");
        foreach (var typeMap in new[] { full.TypeMaps.External, full.TypeMaps.Proxy }) {
            foreach (var group in typeMap.Groups) {
                ulong witness = typeMap.Address + (uint)group.Vertex;
                Check(normal.References.Contains(new(witness, group.GroupType)), "Host omitted a group type reference.");
                if (!group.IsValid) {
                    Check(normal.References.Contains(new(witness, group.ThrowingStub)), "Host omitted a throwing-stub reference.");
                    Check(prepared.Code is not null && prepared.Code.Context.Origins.OriginEntries.ToArray()
                        .Any(origin => origin.Address == group.ThrowingStub), "Code origins omitted a throwing stub.");
                }
            }
        }

        CheckOriginsWithoutTraces(image, header);
        Console.WriteLine($"{binary}: .NET 10 producer external/proxy groups, Unicode, trimming, invalid stubs, selective/full extraction, code origins and rebased host references passed.");
    }

    private static void CheckOriginsWithoutTraces(PeImage source, ReadyToRun header) {
        byte[] bytes = (byte[])source.FileData.Clone();
        for (int i = 0; i < header.Sections.Length; ++i) {
            if (header.Sections[i].Id != (int)RtrSectionId.StackTraceMethodMapping)
                continue;

            int row = header.FileOffset + 16 + i * header.EntrySize;
            if (header.EntrySize == 16)
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(row + 4), 0);
            else
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(row + 16), header.Sections[i].Start);
        }

        var image = new PeImage(bytes);
        var withoutTraces = ReadyToRun.Read(image);
        var metadata = Metadata.FromImage(image, withoutTraces);
        metadata.ReadDefinitions();
        var fixups = RuntimeTables.Fixups(image, withoutTraces.Find(RtrSectionId.CommonFixupsTable));
        var maps = ReflectionMaps.Decode(image, withoutTraces, metadata, fixups);
        var prepared = new PreparedAnalysis(image, withoutTraces, metadata, maps, fixups);
        Check(prepared.Code is not null, "Trace removal disabled code origins.");
        var extraction = prepared.Extraction;
        var origins = new CodeOrigins(extraction, prepared.ManagedAbi!, prepared.Code!.Runtime);
        origins.Render(extraction, prepared.Code.Runtime, Enumerable.Repeat(true, origins.OriginEntries.Length).ToArray());

        foreach (ref readonly var stub in extraction.TypeMaps.ThrowingStubs) {
            ref readonly var group = ref stub.Map.Groups[stub.GroupIndex];
            ulong stubAddress = group.ThrowingStub;
            var origin = origins.OriginEntries.ToArray().Single(entry => entry.Address == stubAddress);
            string prefix = stub.Map.Section == RtrSectionId.ExternalTypeMap
                ? "invalid_external_type_map::" : "invalid_proxy_type_map::";
            Check(origins.NameText.Slice(origin.Name.Start, origin.Name.Count).SequenceEqual(prefix + Name(extraction, group.GroupType)),
                "A sparse throwing-stub index selected the wrong owner or section.");
            Check(origin.Witness == stub.Map.Address + (uint)group.Vertex, "Throwing-stub origin lost its metadata witness.");
            Check(origin.Index == stub.GroupIndex, "Throwing-stub origin index no longer identifies its source group.");
        }
    }

    private static InteropTypeMapGroup Group(InteropTypeMap map, string name, Extraction extraction) =>
        map.Groups.ToArray().Single(group => Name(extraction, group.GroupType) == name);

    private static string Name(Extraction extraction, ulong address) =>
        extraction.Names.Values[extraction.Types.Index[address]];

    private static void Check(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
