using System.Diagnostics;
using System.Security.Cryptography;
using Atlas;

internal static class PropertyChecks {
    internal static void Run(ReadOnlySpan<string> binaries) {
        foreach (string binary in binaries) {
            var image = new PeImage(File.ReadAllBytes(binary));
            var header = ReadyToRun.Read(image);
            var section = header.Find(313);
            var metadata = new Metadata(image.FileMemory(section.Start, checked((int)section.Length)), header.MetadataHandleBits, header.Major < 10);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(308));
            var maps = new ReflectionMaps();
            maps.Read(image, header, metadata, fixups, MapFormat.Auto);
            var extraction = new Extraction(image, header, metadata, maps, fixups);
            var abi = new ManagedAbi(extraction);
            var properties = new PropertyProjections(extraction, abi);
            using var process = Process.Start(new ProcessStartInfo(Path.GetFullPath(binary)) {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            })!;
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert(process.ExitCode == 0, $"Property fixture failed: {error}");
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            int observed = 0;

            if (lines.Contains("shared-property-bodies-executed")) {
                var projection = properties.Projections.Single(value => extraction.Names.Values[value.Owner] == "Published"
                    && properties.Members.Properties[value.Property].Name == "Name");
                string[] live = lines.Single(line => line.StartsWith("shared-layout|Published|")).Split('|');
                Assert(projection.Offset == int.Parse(live[2]) && projection.Size == uint.Parse(live[3])
                    && projection.Storage.Kind == AbiKind.Reference, "The shared getter lost its proven owner-specific storage projection.");
                Assert(!properties.Functions.Any(function => function.Address == projection.Getter),
                    "A shared machine body acquired a single concrete property signature.");
                Assert(extraction.Dispatch.Targets.Any(target => target.Target == projection.Getter && target.OwnerType != projection.Owner),
                    "The fixture did not fold an unrelated receiver into the property getter.");
                Assert(extraction.Dispatch.Targets.Any(target => target.Target == projection.Getter && target.OwnerType == projection.Owner
                    && target.InterfaceType != projection.Contract), "The fixture lost its same-owner, different-signature interface collision.");
                var stripped = metadata.Types.Where(type => type.Name is "Published" or "Unrelated" or "IUnrelated" or "IExtra").ToArray();
                Assert(stripped.Length >= 3 && stripped.All(type => type.Methods.Count == 0 && type.Properties.Count == 0 && type.Fields.Count == 0),
                    "Competing methods must remain stripped from reflection metadata.");
                if (lines.Any(line => line.StartsWith("shared-unboxed|"))) {
                    Assert(abi.Methods.Any(method => method.UnboxedTarget == projection.Getter),
                        "The fixture did not fold an unboxed value-type getter into the reference getter.");
                }
                observed = 1;
            } else if (lines.Any(line => line.StartsWith("layout|"))) {
                var live = new Dictionary<(string Owner, string Property), (int Offset, uint Size)>();
                foreach (string line in lines) {
                    if (!line.StartsWith("layout|")) {
                        continue;
                    }
                    string[] values = line.Split('|');
                    live.Add((values[1], values[2]), (int.Parse(values[3]), uint.Parse(values[4])));
                }
                Assert(live.Count == 10 && lines[^1] == "interface-projections-executed", "The interface fixture lost live storage observations.");
                foreach (var projection in properties.Projections) {
                    string owner = extraction.Names.Values[projection.Owner];
                    string name = properties.Members.Properties[projection.Property].Name;
                    if (!live.TryGetValue((owner, name), out var expected)) {
                        continue;
                    }
                    Assert(projection.Offset == expected.Offset && projection.Size == expected.Size,
                        $"{owner}.{name} disagrees with its live field address or width.");
                    ++observed;
                }
                bool retained = metadata.Types.Any(type => type.Name == "IFields" && type.Properties.Count != 0);
                Assert(observed == (retained ? 8 : 0), "Named interface projections must require retained property semantics.");
                foreach (var type in metadata.Types) {
                    if (type.Name is "Ordinary" or "Explicit" or "UsesDefault" or "Covariant" or "Value`1" or "AbstractDerived" or "IndirectDerived") {
                        Assert(type.Methods.Count == 0 && type.Properties.Count == 0 && type.Fields.Count == 0,
                            "The interface fixture accidentally retained implementation metadata.");
                    }
                }
                Assert(!properties.Projections.Any(projection => properties.Members.Properties[projection.Property].Name == "Next"),
                    "A computed default-interface property became a storage projection.");
                CheckConflictingInterfaceAccessors(extraction, abi, properties);
            } else if (lines.Any(line => line.StartsWith("owner|"))) {
                int liveCount = 0;
                foreach (string line in lines) {
                    if (!line.StartsWith("owner|")) {
                        continue;
                    }
                    string[] values = line.Split('|');
                    ++liveCount;
                    ulong owner = image.ImageBase + Convert.ToUInt64(values[2], 16);
                    ulong value = image.ImageBase + Convert.ToUInt64(values[5], 16);
                    var matches = properties.Projections.Where(projection => extraction.Types.Types[projection.Owner].Address == owner
                        && properties.Members.Properties[projection.Property].Name == "Value").ToArray();
                    if (header.Major < 10 && values[1] is "Box`1[Nested`1[System.String]]" or "Box`1[Nested`1[System.Object]]") {
                        Assert(matches.Length == 0, "The NET8 nested-reference copy requires a proven write-barrier helper.");
                        continue;
                    }
                    Assert(matches.Length == 1, "Each live generic owner must have exactly one property view.");
                    var match = matches[0];
                    Assert(match.Offset == int.Parse(values[3]) && match.Size == uint.Parse(values[4]) && match.Storage.Binding != 0
                        && extraction.Types.Types[match.Storage.Binding - 1].Address == value,
                        "A canonical property disagrees with the live offset, width, or independently observed runtime type.");
                    ++observed;
                }
                Assert(liveCount == 9 && observed == (header.Major < 10 ? 7 : 9) && lines[^1] == "assertions|passed",
                    "The canonical fixture lost an observed instantiation.");
                Assert(properties.Projections.Any(projection => projection.Origin == PropertyOrigin.Canonical),
                    "The fixture did not exercise canonical expansion.");
            } else if (lines.Contains("counterexamples-executed")) {
                string[] rejected = ["FalseGcValue", "HidesGcValue", "FalseFunctionPointer", "CutsGcSlot", "HidesUnknownGc"];
                Assert(!properties.Projections.Any(projection => rejected.Contains(properties.Members.Properties[projection.Property].Name)),
                    "An incompatible or partially cut GC projection was accepted.");
                observed = properties.Projections.Count(projection => properties.Members.Properties[projection.Property].Name is "ReferenceView" or "NumericView");
                Assert(observed == 2, "Legitimate scalar/reference value projections were lost.");
                string? storeLine = lines.SingleOrDefault(line => line.StartsWith("store-only|"));
                if (storeLine != null) {
                    string[] values = storeLine.Split('|');
                    var store = properties.Projections.Single(projection => properties.Members.Properties[projection.Property].Name == "ComputedRead");
                    Assert(store.Getter == 0 && store.Setter != 0 && store.Offset == int.Parse(values[1]) && store.Size == uint.Parse(values[2])
                        && values[3] == "21" && values[4] == "42", "A computed getter became a readable property storage alias.");
                }
            } else {
                throw new InvalidDataException("Expected a property projection fixture with a live storage oracle.");
            }
            Console.WriteLine($"{Path.GetFileName(binary)}: {observed} live property observations; {properties.Projections.Count} projections; sha256={Convert.ToHexStringLower(SHA256.HashData(image.FileData))}");
        }
    }

    private static void CheckConflictingInterfaceAccessors(Extraction extraction, ManagedAbi abi, PropertyProjections baseline) {
        PropertyProjection destination = default;
        PropertyProjection source = default;
        bool getter = false;
        bool found = false;
        for (int i = 0; i < baseline.Projections.Count && !found; ++i) {
            var first = baseline.Projections[i];
            if (first.Owner == first.Contract) {
                continue;
            }
            for (int j = i + 1; j < baseline.Projections.Count; ++j) {
                var second = baseline.Projections[j];
                if (first.Owner == second.Owner || first.Contract != second.Contract || first.Property != second.Property
                    || first.Offset != second.Offset || first.Size != second.Size || first.Storage.Kind != second.Storage.Kind
                    || first.Storage.Binding != second.Storage.Binding || first.ByReference != second.ByReference) {
                    continue;
                }
                if (first.Getter != 0 && second.Getter != 0 && first.Getter != second.Getter) {
                    destination = first;
                    source = second;
                    getter = true;
                    found = true;
                    break;
                }
                if (first.Setter != 0 && second.Setter != 0 && first.Setter != second.Setter) {
                    destination = first;
                    source = second;
                    found = true;
                    break;
                }
            }
        }
        Assert(found, "The interface fixture did not provide distinct accessors with the same property storage shape.");

        ulong sourceAddress = getter ? source.Getter : source.Setter;
        var injected = extraction.Dispatch.Targets.Single(target => target.OwnerType == source.Owner
            && target.InterfaceType == source.Contract && target.Target == sourceAddress);
        injected.OwnerType = destination.Owner;
        extraction.Dispatch.Targets.Add(injected);
        try {
            var conflicted = new PropertyProjections(extraction, abi);
            Assert(conflicted.Rejected[(int)PropertyRejection.ConflictingAccessors]
                    == baseline.Rejected[(int)PropertyRejection.ConflictingAccessors] + 1,
                "Distinct implementations of one property accessor were not reported as a conflict.");
            Assert(!conflicted.Projections.Any(projection => projection.Owner == destination.Owner
                    && projection.Contract == destination.Contract && projection.Property == destination.Property),
                "A property with conflicting accessor implementations was retained.");
        } finally {
            extraction.Dispatch.Targets.RemoveAt(extraction.Dispatch.Targets.Count - 1);
        }
    }

    private static void Assert(bool condition, string message) {
        if (!condition) {
            throw new InvalidDataException(message);
        }
    }
}
