using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class Staticantations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, DataVariables variables, nint view, Extraction extraction, ReadOnlySpan<nint> fieldTypes,
        nint voidPointer, nint methodTablePointer, ref ApplyStats stats, nint task) {
        var statics = extraction.Statics;
        ownership.Reserve(checked(statics.Allocations.Count + statics.GcCells.Count + statics.ThreadIndices.Count
            + statics.Constructors.Count + statics.Generics.Count + statics.Fields.Count));
        var allocations = CollectionsMarshal.AsSpan(statics.Allocations);
        var runs = CollectionsMarshal.AsSpan(statics.Runs);
        ulong imageBase = extraction.Image.ImageBase;
        byte[] text = new byte[StaticText.BufferLength(extraction)];
        byte empty = 0;
        BoolConfidence signed = new() { Value = 1, Confidence = 255 }, unsigned = new() { Confidence = 255 }, qualifier = default;
        nint i32 = Core.BNCreateIntegerType(4, &signed, &empty);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint i64 = Core.BNCreateIntegerType(8, &signed, &empty);
        nint header = DefineType(view, "aot-atlas:static-header:v1"u8, "allocation_descriptor"u8, StaticTypes.Header(u32, methodTablePointer));
        nint cell = DefineType(view, "aot-atlas:static-cell:v1"u8, "initial_gc_cell"u8, StaticTypes.Cell(i32, false));
        nint preinitCell = DefineType(view, "aot-atlas:static-preinit-cell:v1"u8, "initial_preinit_gc_cell"u8, StaticTypes.Cell(i32, true));
        nint threadIndex = DefineType(view, "aot-atlas:static-thread-index:v1"u8, "thread_index"u8, StaticTypes.ThreadIndex(voidPointer, i64));
        nint constructorContext = DefineType(view, "aot-atlas:cctor-context:v1"u8, "constructor_context"u8, StaticTypes.Callable(voidPointer, false));
        nint functionDescriptor = DefineType(view, "aot-atlas:function-descriptor:v1"u8, "function_descriptor"u8, StaticTypes.Callable(voidPointer, true));
        var headerConfidence = new TypeConfidence(header);
        nint descriptorPointer = Core.BNCreatePointerTypeOfWidth(8, &headerConfidence, &qualifier, &qualifier, 0);
        nint[] payloadTypes = new nint[allocations.Length];
        var gcTypes = new Dictionary<int, nint>(allocations.Length);
        var preinitAddresses = new HashSet<ulong>(statics.GcCells.Count);
        var constructorAddresses = new HashSet<ulong>(statics.Constructors.Count);
        var functionDescriptors = new HashSet<ulong>(statics.Constructors.Count);
        nint tagType;
        fixed (byte* name = "AOT Atlas statics\0"u8)
        fixed (byte* icon = "📦\0"u8) {
            tagType = Core.BNGetTagType(view, name);
            if (tagType == 0) {
                tagType = Core.BNCreateTagType(view);
                Core.BNTagTypeSetName(tagType, name);
                Core.BNTagTypeSetIcon(tagType, icon);
                Core.BNAddTagType(view, tagType);
            }
        }

        try {
            Span<byte> identifier = stackalloc byte[80], name = stackalloc byte[32];
            for (int i = 0; i < allocations.Length; ++i) {
                ref readonly var entry = ref allocations[i];
                uint rva = checked((uint)(entry.Address - imageBase));
                Utf8.TryWrite(identifier, $"aot-atlas:static-object:v1:{rva:X8}", out int idLength);
                Utf8.TryWrite(name, $"object_{rva:X8}", out int nameLength);
                nint objectType = DefineType(view, identifier[..idLength], name[..nameLength],
                    StaticTypes.Storage(entry, runs, descriptorPointer, voidPointer, false));
                Core.BNFreeType(objectType);
                DefineData(symbols, variables, view, entry.Address, imageBase, "allocation"u8, header, ref stats);
                Reference(view, entry.Address + 8, entry.RelatedType, imageBase, ref stats);
                Tag(ownership, view, entry.Address, imageBase, tagType, extraction, StaticRecord.Allocation, i, text, task, ref stats);

                if (entry.Runs.Count != 0) {
                    if (!gcTypes.TryGetValue(entry.Runs.Count, out nint gcType)) {
                        Utf8.TryWrite(identifier, $"aot-atlas:static-gcdesc:v1:{entry.Runs.Count}", out idLength);
                        Utf8.TryWrite(name, $"gcdesc_{entry.Runs.Count}", out nameLength);
                        gcType = DefineType(view, identifier[..idLength], name[..nameLength], StaticTypes.GcDesc(entry.Runs.Count, i64));
                        gcTypes.Add(entry.Runs.Count, gcType);
                    }
                    ulong gcAddress = entry.Address - 8 - (uint)entry.Runs.Count * 16UL;
                    DefineData(symbols, variables, view, gcAddress, imageBase, "gcdesc"u8, gcType, ref stats);
                    Reference(view, entry.Address, gcAddress, imageBase, ref stats);
                }
            }

            ulong region = extraction.Header.Find(201).Start;
            for (int i = 0; i < statics.GcCells.Count; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.GcCells)[i];
                ulong source = region + (uint)i * 4UL;
                DefineData(symbols, variables, view, source, imageBase, "gc_region_entry"u8, i32, ref stats);
                Reference(view, source, entry.Cell, imageBase, ref stats);
                DefineData(symbols, variables, view, entry.Cell, imageBase, "gc_cell"u8, entry.PreinitData == 0 ? cell : preinitCell, ref stats);
                Reference(view, entry.Cell, entry.Descriptor, imageBase, ref stats);
                Tag(ownership, view, entry.Cell, imageBase, tagType, extraction, StaticRecord.Cell, i, text, task, ref stats);
                if (entry.PreinitData == 0)
                    continue;

                Reference(view, entry.Cell + 4, entry.PreinitData, imageBase, ref stats);
                if (!preinitAddresses.Add(entry.PreinitData))
                    continue;
                int allocation = statics.AllocationIndex[entry.Descriptor];
                ref readonly var layout = ref allocations[allocation];
                if (payloadTypes[allocation] == 0) {
                    uint rva = checked((uint)(entry.Descriptor - imageBase));
                    Utf8.TryWrite(identifier, $"aot-atlas:static-payload:v1:{rva:X8}", out int idLength);
                    Utf8.TryWrite(name, $"payload_{rva:X8}", out int nameLength);
                    payloadTypes[allocation] = DefineType(view, identifier[..idLength], name[..nameLength],
                        StaticTypes.Storage(layout, runs, descriptorPointer, voidPointer, true));
                }
                DefineData(symbols, variables, view, entry.PreinitData, imageBase, "preinit_payload"u8, payloadTypes[allocation], ref stats);
                var bytes = extraction.Memory.Read(entry.PreinitData, checked((int)(layout.BaseSize - 16)));
                for (int j = layout.Runs.Start; j < layout.Runs.End; ++j) {
                    ref readonly var run = ref runs[j];
                    for (uint k = 0; k < run.Count; ++k) {
                        uint offset = run.Offset - 8 + k * 8;
                        ulong target = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(int)offset..]);
                        if (target != 0 && !extraction.Frozen.Index.ContainsKey(target))
                            throw new InvalidDataException("A preinitialized static reference does not identify a frozen object.");
                        Reference(view, entry.PreinitData + offset, target, imageBase, ref stats);
                    }
                }
            }

            region = extraction.Header.Find(202).Start;
            for (int i = 0; i < statics.ThreadDescriptors.Count; ++i) {
                ulong source = region + (uint)i * 8UL;
                DefineData(symbols, variables, view, source, imageBase, "thread_region_entry"u8, descriptorPointer, ref stats);
                Reference(view, source, statics.ThreadDescriptors[i], imageBase, ref stats);
            }
            for (int i = 0; i < statics.ThreadIndices.Count; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.ThreadIndices)[i];
                DefineData(symbols, variables, view, entry.Address, imageBase, "thread_index"u8, threadIndex, ref stats);
                Reference(view, entry.Address, entry.TypeManager, imageBase, ref stats);
                Reference(view, entry.Address + 8, region + (uint)Math.Max(entry.Index, 0) * 8UL, imageBase, ref stats);
                Reference(view, entry.Address + 8, entry.Descriptor, imageBase, ref stats);
                Tag(ownership, view, entry.Address, imageBase, tagType, extraction, StaticRecord.ThreadIndex, i, text, task, ref stats);
            }

            region = extraction.Header.Find(310).Start;
            for (int i = 0; i < statics.Constructors.Count; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Constructors)[i];
                ulong witness = region + (uint)entry.Vertex;
                DefineData(symbols, variables, view, witness, imageBase, "cctor_record"u8, 0, ref stats);
                Reference(view, witness, entry.Type, imageBase, ref stats);
                Reference(view, witness, entry.NonGcBase, imageBase, ref stats);
                ulong context = entry.NonGcBase - 8;
                Reference(view, witness, context, imageBase, ref stats);
                if (constructorAddresses.Add(context)) {
                    DefineData(symbols, variables, view, context, imageBase, "cctor_context"u8, constructorContext, ref stats);
                    Reference(view, context, entry.Descriptor != 0 ? entry.Descriptor : entry.Entrypoint, imageBase, ref stats);
                }
                if (entry.Descriptor != 0 && functionDescriptors.Add(entry.Descriptor)) {
                    DefineData(symbols, variables, view, entry.Descriptor, imageBase, "function_descriptor"u8, functionDescriptor, ref stats);
                    Reference(view, entry.Descriptor, entry.Entrypoint, imageBase, ref stats);
                    Reference(view, entry.Descriptor + 8, entry.GenericContext, imageBase, ref stats);
                }
                Tag(ownership, view, witness, imageBase, tagType, extraction, StaticRecord.Constructor, i, text, task, ref stats);
            }
            region = extraction.Header.Find(334).Start;
            for (int i = 0; i < statics.Generics.Count; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Generics)[i];
                ulong witness = region + (uint)entry.Vertex;
                DefineData(symbols, variables, view, witness, imageBase, "generic_record"u8, 0, ref stats);
                Reference(view, witness, entry.Type, imageBase, ref stats);
                Reference(view, witness, entry.NonGcBase, imageBase, ref stats);
                Reference(view, witness, entry.GcCell, imageBase, ref stats);
                Reference(view, witness, entry.ThreadIndex, imageBase, ref stats);
                Tag(ownership, view, witness, imageBase, tagType, extraction, StaticRecord.Generic, i, text, task, ref stats);
            }
            region = extraction.Header.Find(309).Start;
            for (int i = 0; i < statics.Fields.Count; ++i) {
                ref readonly var entry = ref CollectionsMarshal.AsSpan(statics.Fields)[i];
                ref readonly var field = ref CollectionsMarshal.AsSpan(extraction.Maps.Fields)[entry.FieldMapIndex];
                ulong witness = region + (uint)field.Vertex;
                DefineData(symbols, variables, view, witness, imageBase, "field_record"u8, 0, ref stats);
                Reference(view, witness, field.DeclaringType, imageBase, ref stats);
                Reference(view, witness, entry.Address, imageBase, ref stats);
                Reference(view, witness, entry.Descriptor, imageBase, ref stats);
                Tag(ownership, view, witness, imageBase, tagType, extraction, StaticRecord.Field, i, text, task, ref stats);
                if (entry.Location != StaticLocation.NonGcAddress)
                    continue;

                nint type = fieldTypes[entry.FieldMapIndex];
                uint size = extraction.Fields.FieldTypes[entry.FieldMapIndex].Size;
                if (size == 0)
                    type = 0;
                else if (Core.BNGetTypeWidth(type) != size)
                    throw new InvalidDataException("The native static field type disagrees with its proven storage width.");
                else if (!extraction.Image.IsMapped(entry.Address, size))
                    throw new InvalidDataException("A static field type exceeds mapped storage.");
                string owner = extraction.Names.Values[extraction.Types.Index[field.DeclaringType]];
                Utf8.TryWrite(text, $"statics::nongc::{owner}::{field.Name}::{witness - imageBase:X8}", out int length);
                text[length] = 0;
                DefineData(symbols, variables, view, entry.Address, imageBase, default, type, ref stats, text.AsSpan(0, length + 1));
            }
        } finally {
            foreach (nint type in payloadTypes) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            foreach (nint type in gcTypes.Values)
                Core.BNFreeType(type);
            Core.BNFreeTagType(tagType);
            Core.BNFreeType(descriptorPointer);
            Core.BNFreeType(functionDescriptor);
            Core.BNFreeType(constructorContext);
            Core.BNFreeType(threadIndex);
            Core.BNFreeType(preinitCell);
            Core.BNFreeType(cell);
            Core.BNFreeType(header);
            Core.BNFreeType(i64);
            Core.BNFreeType(u32);
            Core.BNFreeType(i32);
        }
    }

    private static nint DefineType(nint view, ReadOnlySpan<byte> identifier, ReadOnlySpan<byte> name, nint type) {
        Span<byte> id = stackalloc byte[96], text = stackalloc byte[48];
        identifier.CopyTo(id);
        id[identifier.Length] = 0;
        name.CopyTo(text);
        text[name.Length] = 0;
        fixed (byte* idBytes = id)
        fixed (byte* nameBytes = text)
        fixed (byte* atlas = "atlas\0"u8)
        fixed (byte* storage = "static_storage\0"u8)
        fixed (byte* join = "::\0"u8) {
            byte** parts = stackalloc byte*[3] { atlas, storage, nameBytes };
            QualifiedName qualified = new() { Names = parts, Join = join, Count = 3 };
            var actual = Core.BNDefineAnalysisType(view, idBytes, &qualified, type);
            nint reference = Core.BNCreateNamedTypeReferenceFromTypeAndId(idBytes, &actual, type);
            Core.BNFreeQualifiedName(&actual);
            Core.BNFreeType(type);
            return reference;
        }
    }

    private static void DefineData(Symbols symbols, DataVariables variables, nint view, ulong address, ulong originalBase, ReadOnlySpan<byte> category,
        nint type, ref ApplyStats stats, ReadOnlySpan<byte> fullName = default) {
        Span<byte> text = stackalloc byte[96];
        if (fullName.IsEmpty) {
            "statics::"u8.CopyTo(text);
            category.CopyTo(text[9..]);
            Utf8.TryWrite(text[(9 + category.Length)..], $"::{address - originalBase:X8}", out int length);
            text[9 + category.Length + length] = 0;
        }
        ulong rebased = stats.ImageBase + (address - originalBase);
        fixed (byte* name = fullName.IsEmpty ? text : fullName) {
            symbols.Define(rebased, 3, name);
        }
        ++stats.Symbols;
        if (type != 0) {
            variables.Define(rebased, type);
            ++stats.DataVariables;
        }
    }

    private static void Reference(nint view, ulong source, ulong target, ulong originalBase, ref ApplyStats stats) {
        if (target != 0) {
            Core.BNAddUserDataReference(view, stats.ImageBase + (source - originalBase), stats.ImageBase + (target - originalBase));
            ++stats.DataReferences;
        }
    }

    private static void Tag(TagOwnership ownership, nint view, ulong address, ulong originalBase, nint tagType, Extraction extraction,
        StaticRecord kind, int index, Span<byte> output, nint task, ref ApplyStats stats) {
        if (task != 0 && (index & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
            throw new OperationCanceledException();
        int length = StaticText.Write(extraction, kind, index, output);
        ulong rebased = stats.ImageBase + (address - originalBase);
        DataTags.Set(ownership, view, tagType, rebased, output[..(length + 1)]);
    }
}
