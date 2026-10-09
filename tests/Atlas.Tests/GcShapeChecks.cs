using System.Buffers.Binary;
using Atlas;

internal static class GcShapeChecks {
    internal static void Run() {
        const uint pointerFlag = 0x01000000;
        PeImage image = PeFixture.Create(new byte[8], ".rdata", 0x40000040);
        RuntimeMemory memory = new(image, new HydratedRegion());
        MethodTables tables = new();

        tables.Types.Add(new MethodTable { Address = 0x140010000, Flags = 0x10U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x140010020, Flags = 0x10U << 26 | pointerFlag, BaseSize = 32, ValuePadding = 8 });
        tables.Types.Add(new MethodTable { Address = 0x140010040, Flags = 0x10U << 26 | pointerFlag, BaseSize = 32 });
        tables.Types.Add(new MethodTable { Address = 0x140010060, Flags = 0x10U << 26, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x140010080, Flags = 0x14U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x1400100A0, Flags = 0x10U << 26 | pointerFlag, BaseSize = 24, ByrefLike = true });
        tables.Types.Add(new MethodTable { Address = 0x1400100C0, Flags = 0x80020008U | 0x18U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x1400100E0, Flags = 0x80020008U | 0x17U << 26 | pointerFlag, BaseSize = 40 });
        tables.Types.Add(new MethodTable { Address = 0x140010100, Flags = 0x80020010U | 0x18U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x140010120, Flags = 0x0AU << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x140010140, Flags = 0x11U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x140010160, Flags = 0x12U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x140010180, Flags = 0x13U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x1400101A0, Flags = 0x15U << 26 | pointerFlag, BaseSize = 24 });
        tables.Types.Add(new MethodTable { Address = 0x1400101C0, Flags = 0x80000008U | 0x14U << 26 | pointerFlag, BaseSize = 24 });

        GcLayouts gc = new();
        gc.Read(tables, memory, false);
        Assert(gc.Layouts.Select(layout => layout.TypeIndex).SequenceEqual(new[] { 0, 1, 4, 6, 7 }),
            "An ambiguous or absent pointer shape became an exact layout.");
        Assert(gc.Unproven.SequenceEqual(new[] { 2, 5, 8, 9, 10, 11, 12, 13, 14 }), "Unresolved construction/layout identities changed.");
        Assert(gc.Layouts.All(layout => layout.SeriesCount is null && layout.Runs.Count == 1)
            && gc.Runs.All(run => run.EncodedSize is null && run.Count == 1),
            "Shape inference invented an encoded GCDesc.");
        Assert(gc.Runs.Select(run => run.Offset).SequenceEqual(new uint[] { 8, 8, 8, 16, 32 })
            && gc.Layouts.Select(layout => layout.RepeatStride).SequenceEqual(new uint[] { 0, 0, 0, 8, 8 }),
            "Exact pointer slot differs from the boxed/array layout contract.");
        Assert(gc.Layouts[2].Source == GcLayoutSource.ExactObjectShape,
            "Necessary ordinary reference class lost its exact object shape provenance.");

        byte[] descriptor = new byte[32];
        BinaryPrimitives.WriteInt64LittleEndian(descriptor, -16);
        BinaryPrimitives.WriteUInt64LittleEndian(descriptor.AsSpan(8), 8);
        BinaryPrimitives.WriteInt64LittleEndian(descriptor.AsSpan(16), 1);
        PeImage encodedImage = PeFixture.Create(descriptor, ".rdata", 0x40000040);
        MethodTables encodedTables = new();
        encodedTables.Types.Add(new MethodTable {
            Address = encodedImage.ImageBase + 0x1018,
            Flags = 0x10U << 26 | pointerFlag,
            BaseSize = 24,
            VtableCount = 1
        });
        GcLayouts encoded = new();
        encoded.Read(encodedTables, new RuntimeMemory(encodedImage, new HydratedRegion()), false);
        Assert(encoded.Layouts.Single().Source == GcLayoutSource.Descriptor
            && encoded.Layouts.Single().SeriesCount == 1 && encoded.Runs.Single().EncodedSize == -16
            && encoded.Runs.Single().Offset == gc.Runs[0].Offset && encoded.Runs.Single().Count == gc.Runs[0].Count,
            "Exact value shape disagrees with an independently encoded constructed GCDesc.");

        Console.WriteLine("GC shapes: single-pointer structs/classes, padding, SZ/MD components, ambiguous widths, absent flags, byref-like and malformed primitive/interface/string/canonical shapes; encoded descriptors and unavailable construction remain distinct.");
    }

    internal static void Binary(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RtrSection section = header.Find(RtrSectionId.EmbeddedMetadata);
        Metadata metadata = new(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();
        ulong[] fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        ReflectionMaps maps = new();
        maps.Read(image, header, metadata, fixups);
        Extraction extraction = new(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
        int checkedShapes = 0;

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 3 || columns[1] is not ("??_7Boxed_S_P_CoreLib_System_Delegate_Wrapper@@6B@"
                or "??_7__Array<S_P_CoreLib_System_Delegate_Wrapper>@@6B@"))
                continue;

            ulong address = Convert.ToUInt64(columns[2], 16);
            int index = extraction.Types.Index[address];
            MethodTable type = extraction.Types.Types[index];
            GcLayout layout = extraction.Gc.Layouts.Single(layout => layout.TypeIndex == index);
            GcRun run = extraction.Gc.Runs[layout.Runs.Start];
            bool array = columns[1].Contains("__Array", StringComparison.Ordinal);
            Assert(type.VtableCount == 0 && (type.Evidence & TypeEvidence.FrozenObject) == 0,
                "Producer fixture no longer tests an omitted necessary GCDesc.");
            Assert(layout.Source == (array ? GcLayoutSource.ExactArrayShape : GcLayoutSource.ExactValueShape)
                && layout.SeriesCount is null && run.EncodedSize is null
                && run.Offset == (array ? 16U : 8U) && run.Count == 1,
                "Delegate.Wrapper's independently declared single Delegate field has a different GC shape.");
            ++checkedShapes;
        }

        Assert(checkedShapes == 2, "Independent linker Wrapper and Wrapper[] oracle is incomplete.");
        Console.WriteLine($"GC producer shapes: {checkedShapes} exact necessary layouts recovered; {extraction.Gc.Unproven.Count} remain unresolved; no encoded GCDesc or construction fact invented.");
    }

    internal static void Inheritance() {
        const uint pointerClass = 0x14U << 26 | 0x01000000;
        byte[] descriptor = new byte[64];
        BinaryPrimitives.WriteInt64LittleEndian(descriptor, -40);
        BinaryPrimitives.WriteUInt64LittleEndian(descriptor.AsSpan(8), 24);
        BinaryPrimitives.WriteInt64LittleEndian(descriptor.AsSpan(16), -40);
        BinaryPrimitives.WriteUInt64LittleEndian(descriptor.AsSpan(24), 8);
        BinaryPrimitives.WriteInt64LittleEndian(descriptor.AsSpan(32), 2);
        PeImage image = PeFixture.Create(descriptor, ".rdata", 0x40000040);
        ulong parent = image.ImageBase + 0x1028;
        MethodTables tables = new();

        Add(parent + 0x100, parent + 0x120, 48);
        Add(parent + 0x120, parent, 48);
        Add(parent + 0x140, parent, 56);
        Add(parent + 0x160, parent + 0x180, 48);
        Add(parent + 0x180, parent + 0x160, 48);
        Add(parent + 0x1A0, parent + 0x1C0, 48);
        Add(parent + 0x1C0, 0, 48);
        Add(parent, 0, 48, vtable: 1);

        GcLayouts gc = new();
        gc.Read(tables, new RuntimeMemory(image, new HydratedRegion()), false);
        Assert(gc.Unproven.SequenceEqual(new[] { 2, 3, 4, 5, 6 }),
            "Growth, a cycle, or an unresolved base became an exact inherited map.");
        Assert(gc.Inherited.Count == 1 && gc.Inherited[0].TypeIndex == 2
            && gc.Inherited[0].BaseTypeIndex == 7 && gc.Inherited[0].Runs.Count == 2,
            "Guaranteed base runs escaped partial evidence or disappeared from a larger derived class.");

        foreach (int index in new[] { 0, 1 }) {
            GcLayout layout = gc.Layouts.Single(layout => layout.TypeIndex == index);
            Assert(layout.Source == GcLayoutSource.ExactInheritedShape && layout.SeriesCount is null
                && layout.RepeatStride == 0 && layout.Runs.Count == 2,
                "Inherited shape fabricated a GCDesc or lost a base run.");
            GcRun[] runs = gc.Runs.Skip(layout.Runs.Start).Take(layout.Runs.Count).ToArray();
            Assert(runs.Select(run => run.Offset).SequenceEqual(new uint[] { 8, 24 })
                && runs.All(run => run.Count == 1 && run.EncodedSize is null),
                "Exact inherited shape differs from the independent two-run base descriptor.");
        }

        Assert(gc.Runs.Count == 4 && gc.Layouts.Where(layout => layout.TypeIndex is 0 or 1)
            .Select(layout => layout.Runs).Distinct().Count() == 1,
            "Same-root inherited shapes duplicated immutable pointer runs.");

        Console.WriteLine("GC inheritance: later bases, chains, multiple runs, allocation growth, cycles and unresolved ancestors verified; descriptor construction remains distinct.");

        void Add(ulong address, ulong related, uint size, ushort vtable = 0) {
            int index = tables.Add(address, TypeEvidence.TypeMap);
            tables.Types[index] = new MethodTable {
                Address = address,
                RelatedType = related,
                BaseSize = size,
                Flags = pointerClass,
                VtableCount = vtable
            };
        }
    }

    internal static void ArrayElements() {
        const uint pointerFlag = 0x01000000;
        const uint valueFlags = 0x10U << 26 | pointerFlag;
        byte[] descriptor = new byte[48];
        BinaryPrimitives.WriteInt64LittleEndian(descriptor, -40);
        BinaryPrimitives.WriteUInt64LittleEndian(descriptor.AsSpan(8), 24);
        BinaryPrimitives.WriteInt64LittleEndian(descriptor.AsSpan(16), -40);
        BinaryPrimitives.WriteUInt64LittleEndian(descriptor.AsSpan(24), 8);
        BinaryPrimitives.WriteInt64LittleEndian(descriptor.AsSpan(32), 2);
        PeImage image = PeFixture.Create(descriptor, ".rdata", 0x40000040);
        ulong element = image.ImageBase + 0x1028;
        RuntimeMemory memory = new(image, new HydratedRegion());
        MethodTables tables = new();

        AddArray(element + 0x100, element, 24, 32);
        AddArray(element + 0x120, element, 40, 32, multidimensional: true);
        AddArray(element + 0x140, element, 24, 24);
        AddArray(element + 0x160, element + 0x500, 24, 32);
        AddArray(element + 0x180, element, 24, 32, hasPointers: false);
        int elementIndex = tables.Add(element, TypeEvidence.TypeMap);
        tables.Types[elementIndex] = new MethodTable {
            Address = element,
            Flags = valueFlags,
            BaseSize = 48,
            VtableCount = 1
        };

        GcLayouts gc = new();
        gc.Read(tables, memory, false);
        Assert(gc.Unproven.SequenceEqual(new[] { 2, 3 }),
            "Missing or incompatible array elements received an invented complete map.");

        foreach (int index in new[] { 0, 1 }) {
            GcLayout layout = gc.Layouts.Single(layout => layout.TypeIndex == index);
            GcRun[] runs = gc.Runs.Skip(layout.Runs.Start).Take(layout.Runs.Count).ToArray();
            uint start = index == 0 ? 16U : 32U;
            Assert(layout.Source == GcLayoutSource.ExactArrayElementShape
                && layout.SeriesCount is null && layout.RepeatStride == 32
                && runs.Select(run => run.Offset).SequenceEqual(new[] { start, start + 16 })
                && runs.All(run => run.Count == 1 && run.EncodedSize is null),
                "Exact element runs lost ordering, pointer counts, array headers or omitted-descriptor provenance.");
        }

        Assert(!gc.Layouts.Any(layout => layout.TypeIndex == 4),
            "An array without HasPointers received a GC layout.");

        foreach (var (flags, byrefLike) in new[] {
            (0x14U << 26 | pointerFlag, false),
            (valueFlags, true)
        }) {
            tables.Types[elementIndex] = new MethodTable {
                Address = element,
                Flags = flags,
                BaseSize = 48,
                VtableCount = 1,
                ByrefLike = byrefLike
            };
            GcLayouts incompatible = new();
            incompatible.Read(tables, memory, false);
            Assert(incompatible.Unproven.SequenceEqual(new[] { 0, 1, 2, 3 }),
                "Reference-class or byref-like element fields became array payload fields.");
        }

        tables.Types[elementIndex] = new MethodTable {
            Address = element,
            Flags = valueFlags,
            BaseSize = 48,
            VtableCount = 1
        };
        BinaryPrimitives.WriteUInt64LittleEndian(descriptor.AsSpan(24), 48);
        PeImage damagedImage = PeFixture.Create(descriptor, ".rdata", 0x40000040);
        GcLayouts damaged = new();
        bool rejected = false;

        try {
            damaged.Read(tables, new RuntimeMemory(damagedImage, new HydratedRegion()), false);
        } catch (InvalidDataException) {
            rejected = true;
        }

        Assert(rejected && !damaged.Layouts.Any(layout => layout.Source == GcLayoutSource.ExactArrayElementShape),
            "An invalid component descriptor published an exact array map.");

        Console.WriteLine("GC array elements: exact boxed multi-run maps, SZ/MD headers, absent flags and incompatible/missing/byref-like components verified.");

        void AddArray(ulong address, ulong related, uint baseSize, uint componentSize,
            bool multidimensional = false, bool hasPointers = true) {
            int index = tables.Add(address, TypeEvidence.TypeMap);
            tables.Types[index] = new MethodTable {
                Address = address,
                RelatedType = related,
                BaseSize = baseSize,
                Flags = 0x80020000U | (multidimensional ? 0x17U : 0x18U) << 26
                    | componentSize | (hasPointers ? pointerFlag : 0)
            };
        }
    }

    internal static void ArrayElements(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RtrSection section = header.Find(RtrSectionId.EmbeddedMetadata);
        Metadata metadata = new(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();
        ulong[] fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        ReflectionMaps maps = new();
        maps.Read(image, header, metadata, fixups);
        Extraction extraction = new(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
        Dictionary<string, ulong> arrays = new();
        string[] names = ["PointerPair", "PointerGap", "PointerTail", "ConstructedPair", "ConstructedGap", "ConstructedTail"];

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 3 || !columns[1].StartsWith("??_7__Array<", StringComparison.Ordinal))
                continue;

            foreach (string name in names) {
                if (columns[1].EndsWith($"_{name}>@@6B@", StringComparison.Ordinal))
                    arrays.Add(name, Convert.ToUInt64(columns[2], 16));
            }
        }

        Assert(arrays.Count == names.Length, "Necessary and constructed array linker witnesses are incomplete.");

        foreach (var (suffix, stride, offsets, counts) in new (string, uint, uint[], uint[])[] {
            ("Pair", 16, [16], [2]),
            ("Gap", 24, [16, 32], [1, 1]),
            ("Tail", 16, [16], [1])
        }) {
            foreach (bool constructed in new[] { false, true }) {
                string name = (constructed ? "Constructed" : "Pointer") + suffix;
                int index = extraction.Types.Index[arrays[name]];
                MethodTable type = extraction.Types.Types[index];
                GcLayout layout = extraction.Gc.Layouts.Single(layout => layout.TypeIndex == index);
                GcRun[] runs = extraction.Gc.Runs.Skip(layout.Runs.Start).Take(layout.Runs.Count).ToArray();
                Assert(layout.RepeatStride == stride
                    && runs.Select(run => run.Offset).SequenceEqual(offsets)
                    && runs.Select(run => run.Count).SequenceEqual(counts),
                    $"{name}[] differs from its independently declared field layout.");
                Assert(constructed
                    ? type.VtableCount != 0 && layout.Source == GcLayoutSource.Descriptor && layout.SeriesCount is not null
                    : type.VtableCount == 0 && layout.Source == GcLayoutSource.ExactArrayElementShape
                        && layout.SeriesCount is null && runs.All(run => run.EncodedSize is null),
                    $"{name}[] lost necessary/constructed descriptor provenance.");
            }
        }

        Console.WriteLine("GC array producer: three necessary component maps agree with independently constructed contiguous, separated and scalar-tail array descriptors.");
    }

    internal static void Inherited(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RtrSection section = header.Find(RtrSectionId.EmbeddedMetadata);
        Metadata metadata = new(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();
        ulong[] fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        ReflectionMaps maps = new();
        maps.Read(image, header, metadata, fixups);
        Extraction extraction = new(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
        int inherited = 0;
        int constructed = 0;
        int rejected = 0;

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 3 || columns[1] is not ("??_7Probe_NecessaryEmpty@@6B@"
                or "??_7Probe_NecessaryScalar@@6B@" or "??_7Probe_NecessaryChain@@6B@"
                or "??_7Probe_ConstructedScalar@@6B@" or "??_7Probe_Parent@@6B@"
                or "??_7Probe_NecessaryPointer@@6B@" or "??_7Probe_AmbiguousChild@@6B@"))
                continue;

            ulong address = Convert.ToUInt64(columns[2], 16);
            int index = extraction.Types.Index[address];
            MethodTable type = extraction.Types.Types[index];

            if (columns[1] is "??_7Probe_NecessaryPointer@@6B@" or "??_7Probe_AmbiguousChild@@6B@") {
                Assert(extraction.Gc.Unproven.Contains(index),
                    "A new pointer or an unresolved base received an invented exact layout.");
                Assert(extraction.Gc.Inherited.Any(inherited => inherited.TypeIndex == index)
                    == (columns[1] == "??_7Probe_NecessaryPointer@@6B@"),
                    "Known inherited slots and wholly unresolved ancestors became interchangeable.");
                ++rejected;
                continue;
            }

            GcLayout layout = extraction.Gc.Layouts.Single(layout => layout.TypeIndex == index);
            GcRun run = extraction.Gc.Runs[layout.Runs.Start];
            Assert(type.BaseSize == 32 && layout.RepeatStride == 0 && layout.Runs.Count == 1
                && run.Offset == 8 && run.Count == 1,
                "The inherited map differs from the producer's object field and scalar tail padding.");

            if (columns[1] is "??_7Probe_ConstructedScalar@@6B@" or "??_7Probe_Parent@@6B@") {
                Assert(type.VtableCount != 0 && layout.Source == GcLayoutSource.Descriptor
                    && layout.SeriesCount == 1 && run.EncodedSize == -24,
                    "Constructed inherited fixture lost its encoded descriptor.");
                ++constructed;
            } else {
                Assert(type.VtableCount == 0 && layout.Source == GcLayoutSource.ExactInheritedShape
                    && layout.SeriesCount is null && run.EncodedSize is null,
                    "Necessary inherited fixture invented construction or an encoded descriptor.");
                ++inherited;
            }
        }

        Assert(inherited == 3 && constructed == 2 && rejected == 2,
            "Producer inherited, constructed, and ambiguous linker witnesses are incomplete.");
        Console.WriteLine($"GC inherited producer: {inherited} exact necessary maps agree with {constructed} constructed descriptors; {rejected} ambiguous shapes remain unresolved.");
    }

    internal static void ExplicitInheritance(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RtrSection section = header.Find(RtrSectionId.EmbeddedMetadata);
        Metadata metadata = new(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();
        ulong[] fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        ReflectionMaps maps = new();
        maps.Read(image, header, metadata, fixups);
        Extraction extraction = new(image, header, metadata, maps, fixups, ExtractionStage.All);
        int partialType = -1;
        int checkedTypes = 0;

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 3 || columns[1] is not ("??_7Probe_NecessaryScalar@@6B@"
                or "??_7Probe_NecessaryPointer@@6B@" or "??_7Probe_ConstructedPointer@@6B@"))
                continue;

            int index = extraction.Types.Index[Convert.ToUInt64(columns[2], 16)];
            MethodTable type = extraction.Types.Types[index];

            if (columns[1] == "??_7Probe_NecessaryScalar@@6B@") {
                GcLayout layout = extraction.Gc.Layouts.Single(layout => layout.TypeIndex == index);
                GcRun run = extraction.Gc.Runs[layout.Runs.Start];
                Assert(type.BaseSize == 32 && type.VtableCount == 0
                    && layout.Source == GcLayoutSource.ExactInheritedShape && layout.Runs.Count == 1
                    && run.Offset == 8 && run.Count == 1,
                    "Derived explicit FieldOffset(0) scalar overlaid the inherited reference.");
            } else if (columns[1] == "??_7Probe_NecessaryPointer@@6B@") {
                partialType = index;
                InheritedGcRuns inherited = extraction.Gc.Inherited.Single(item => item.TypeIndex == index);
                GcRun run = extraction.Gc.Runs[inherited.Runs.Start];
                Assert(type.BaseSize == 40 && type.VtableCount == 0
                    && extraction.Gc.Unproven.Contains(index)
                    && !extraction.Gc.Layouts.Any(layout => layout.TypeIndex == index)
                    && inherited.Runs.Count == 1 && run.Offset == 8 && run.Count == 1,
                    "Explicit derived GC tail became a complete inferred layout.");
            } else {
                GcLayout layout = extraction.Gc.Layouts.Single(layout => layout.TypeIndex == index);
                uint[] offsets = extraction.Gc.Runs.Skip(layout.Runs.Start).Take(layout.Runs.Count)
                    .Select(run => run.Offset).Order().ToArray();
                Assert(type.BaseSize == 40 && layout.Source == GcLayoutSource.Descriptor
                    && offsets.SequenceEqual(new uint[] { 8, 24 }),
                    "Constructed explicit counterpart differs from inherited offset8 and added offset24.");
            }

            ++checkedTypes;
        }

        Assert(checkedTypes == 3 && partialType >= 0, "Explicit inheritance linker witnesses are incomplete.");
        int inheritedIndex = extraction.Gc.Inherited.FindIndex(item => item.TypeIndex == partialType);
        InheritedGcRuns prefix = extraction.Gc.Inherited[inheritedIndex];
        Assert(extraction.InheritedGcTypeAt(inheritedIndex).Address == extraction.Types.Types[partialType].Address
            && extraction.InheritedGcBaseTypeAt(inheritedIndex).Address == extraction.Types.Types[prefix.BaseTypeIndex].Address,
            "Partial inherited type identities escaped their extraction's runtime namespace.");
        Console.WriteLine("GC explicit inheritance: scalar FieldOffset(0) preserves parent slot; added reference remains partial and outside complete layouts.");
    }

    internal static void Classes(string binary, string linkerMap) {
        PeImage image = new(File.ReadAllBytes(binary));
        ReadyToRun header = ReadyToRun.Read(image);
        RtrSection section = header.Find(RtrSectionId.EmbeddedMetadata);
        Metadata metadata = new(image.FileMemory(section.Start, checked((int)section.Length)),
            header.MetadataHandleBits, header.Format.LegacyMetadataConstants);
        metadata.ReadDefinitions();
        ulong[] fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
        ReflectionMaps maps = new();
        maps.Read(image, header, metadata, fixups);
        Extraction extraction = new(image, header, metadata, maps, fixups, ExtractionStage.RuntimeTypes);
        int necessary = 0;
        int constructed = 0;

        foreach (string line in File.ReadLines(linkerMap)) {
            string[] columns = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (columns.Length < 3 || columns[1] is not ("??_7Probe_NecessaryPointerOnly@@6B@"
                or "??_7Probe_NecessaryBase@@6B@" or "??_7Probe_NecessaryDerived@@6B@"
                or "??_7Probe_ConstructedPointerOnly@@6B@"))
                continue;

            ulong address = Convert.ToUInt64(columns[2], 16);
            int index = extraction.Types.Index[address];
            MethodTable type = extraction.Types.Types[index];
            GcLayout layout = extraction.Gc.Layouts.Single(layout => layout.TypeIndex == index);
            GcRun run = extraction.Gc.Runs[layout.Runs.Start];
            Assert(type.Kind == 0 && type.ElementType == 0x14 && type.BaseSize == 24
                && layout.RepeatStride == 0 && layout.Runs.Count == 1 && run.Offset == 8 && run.Count == 1,
                "Independent class field or inherited field differs from the exact object shape.");

            if (columns[1].Contains("ConstructedPointerOnly", StringComparison.Ordinal)) {
                Assert(type.VtableCount != 0 && layout.Source == GcLayoutSource.Descriptor
                    && layout.SeriesCount == 1 && run.EncodedSize == -16,
                    "Constructed class lost its independently emitted GCDesc evidence.");
                ++constructed;
            } else {
                Assert(type.VtableCount == 0 && (type.Evidence & TypeEvidence.FrozenObject) == 0
                    && layout.Source == GcLayoutSource.ExactObjectShape
                    && layout.SeriesCount is null && run.EncodedSize is null,
                    "Necessary class shape invented construction or an encoded GCDesc.");
                ++necessary;
            }
        }

        Assert(necessary == 3 && constructed == 1, "Independent necessary/constructed class linker oracle is incomplete.");
        Console.WriteLine($"GC class producer: {necessary} necessary single-field/inherited layouts agree with {constructed} constructed class GCDesc; no construction fact invented.");
    }

    private static void Assert(bool condition, string message) {
        if (!condition)
            throw new Exception(message);
    }
}
