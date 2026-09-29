using System.Buffers;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal static unsafe class FrozenAnnotations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, DataVariables variables, nint view, Extraction extraction, ReadOnlySpan<nint> runtimeTypes, nint headerPointer,
        ref ApplyStats stats, nint task) {
        var frozen = extraction.Frozen;
        var objects = CollectionsMarshal.AsSpan(frozen.Objects);
        if (objects.IsEmpty)
            return;

        ownership.Reserve(objects.Length);

        var tables = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var references = CollectionsMarshal.AsSpan(frozen.References);
        ulong region = stats.ImageBase + (frozen.Start - extraction.Image.ImageBase);
        bool hydrated = extraction.Memory.Regions[extraction.Memory.Find(frozen.Start)].Hydrated;
        int maximumName = 0, maximumString = 0, maximumShapes = 0, maximumPointers = 0;
        foreach (ref readonly var entry in objects) {
            maximumName = Math.Max(maximumName, extraction.Names.Values[entry.TypeIndex].Length);
            if (entry.Kind == FrozenKind.String)
                maximumString = Math.Max(maximumString, entry.Count);
            if (entry.Kind != FrozenKind.Object)
                ++maximumShapes;
            if (entry.Kind == FrozenKind.Array)
                ++maximumPointers;
        }

        byte[] symbolText = new byte[checked(Encoding.UTF8.GetMaxByteCount(maximumName) + 64)];
        byte[] tagText = new byte[checked(symbolText.Length + 6 * maximumString + 64)];
        var shapes = new Dictionary<(int Type, int Count), nint>(maximumShapes);
        var pointers = new Dictionary<int, nint>(maximumPointers);
        Span<byte> typeId = stackalloc byte[64];
        Span<byte> displayText = stackalloc byte[256];
        byte empty = 0;
        BoolConfidence signed = new() { Value = 1, Confidence = 255 }, qualifier = default;
        nint integer = Core.BNCreateIntegerType(4, &signed, &empty);
        nint character = Core.BNCreateWideCharType(2, &empty);
        nint tagType;
        fixed (byte* name = "AOT Atlas frozen\0"u8)
        fixed (byte* icon = "❄️\0"u8) {
            tagType = Core.BNGetTagType(view, name);
            if (tagType == 0) {
                tagType = Core.BNCreateTagType(view);
                Core.BNTagTypeSetName(tagType, name);
                Core.BNTagTypeSetIcon(tagType, icon);
                Core.BNAddTagType(view, tagType);
            }
        }

        try {
            fixed (byte* symbolName = symbolText)
            fixed (byte* identifier = typeId)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* storage = "frozen\0"u8)
            fixed (byte* join = "::\0"u8) {
                ReadOnlySpan<byte> typePrefix = "aot-atlas:frozen-sequence:v1:"u8;
                byte** parts = stackalloc byte*[3] { atlas, storage, identifier + typePrefix.Length };
                QualifiedName name = new() { Names = parts, Join = join, Count = 3 };
                for (int index = 0; index < objects.Length; ++index) {
                    if (task != 0 && (index & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ref readonly var entry = ref objects[index];
                    ref readonly var table = ref tables[entry.TypeIndex];
                    ulong address = region + (uint)entry.Offset;
                    nint nativeType = runtimeTypes[entry.TypeIndex];
                    if (entry.Kind != FrozenKind.Object) {
                        var key = (entry.TypeIndex, entry.Count);
                        if (!shapes.TryGetValue(key, out nativeType)) {
                            uint typeRva = checked((uint)(table.Address - extraction.Image.ImageBase));
                            if (entry.Kind == FrozenKind.Box) {
                                nativeType = ObjectTypes.DefineBox(view, typeRva, table.BaseSize - 8, runtimeTypes[entry.TypeIndex], headerPointer);
                            } else {
                                nint element = character;
                                if (entry.Kind == FrozenKind.Array) {
                                    int elementIndex = extraction.Types.Index[table.RelatedType];
                                    ref readonly var elementType = ref tables[elementIndex];
                                    element = runtimeTypes[elementIndex];
                                    if (elementType.ElementType is >= 0x14 and <= 0x18) {
                                        if (!pointers.TryGetValue(elementIndex, out element)) {
                                            var target = new TypeConfidence(runtimeTypes[elementIndex]);
                                            element = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
                                            pointers.Add(elementIndex, element);
                                        }
                                    } else if (!elementType.IsValueType && elementType.Kind != 1 && elementType.ElementType is not (0x19 or 0x1A)) {
                                        throw new NotSupportedException("The frozen array's element storage cant be represented by a proven runtime type.");
                                    }
                                }

                                nint type = ObjectTypes.Sequence(entry, table, element, headerPointer, integer);
                                typePrefix.CopyTo(typeId);
                                Utf8Formatter.TryFormat(typeRva, typeId[typePrefix.Length..], out _, new StandardFormat('X', 8));
                                typeId[typePrefix.Length + 8] = (byte)'_';
                                Utf8Formatter.TryFormat((uint)entry.Count, typeId[(typePrefix.Length + 9)..], out _, new StandardFormat('X', 8));
                                typeId[typePrefix.Length + 17] = 0;
                                var actual = Core.BNDefineAnalysisType(view, identifier, &name, type);
                                nativeType = Core.BNCreateNamedTypeReferenceFromTypeAndId(identifier, &actual, type);
                                Core.BNFreeQualifiedName(&actual);
                                Core.BNFreeType(type);
                            }
                            shapes.Add(key, nativeType);
                        }
                    }

                    variables.Define(address, nativeType);
                    ++stats.DataVariables;
                    Core.BNAddUserDataReference(view, address, stats.ImageBase + (table.Address - extraction.Image.ImageBase));
                    ++stats.DataReferences;
                    for (int i = entry.References.Start; i < entry.References.End; ++i) {
                        ref readonly var reference = ref references[i];
                        Core.BNAddUserDataReference(view, address + reference.Offset, region + (uint)objects[reference.Target].Offset);
                        ++stats.DataReferences;
                    }

                    ReadOnlySpan<byte> kind = entry.Kind switch {
                        FrozenKind.String => "string"u8,
                        FrozenKind.Array => "array"u8,
                        FrozenKind.Box => "box"u8,
                        _ => "object"u8
                    };
                    "frozen::"u8.CopyTo(symbolText);
                    ReadOnlySpan<byte> source = hydrated ? "rehydrated::"u8 : "file::"u8;
                    source.CopyTo(symbolText.AsSpan(8));
                    int position = 8 + source.Length;
                    kind.CopyTo(symbolText.AsSpan(position));
                    position += kind.Length;
                    "::"u8.CopyTo(symbolText.AsSpan(position));
                    position += 2;
                    position += Encoding.UTF8.GetBytes(extraction.Names.Values[entry.TypeIndex], symbolText.AsSpan(position));
                    int descriptorEnd = position;
                    "::"u8.CopyTo(symbolText.AsSpan(position));
                    uint rva = checked((uint)(address - stats.ImageBase));
                    Utf8Formatter.TryFormat(rva, symbolText.AsSpan(position + 2), out _, new StandardFormat('X', 8));
                    symbolText[position + 10] = 0;
                    if (entry.Kind == FrozenKind.String) {
                        "frozen::"u8.CopyTo(displayText);
                        source.CopyTo(displayText[8..]);
                        var characters = frozen.Data.Span.Slice(entry.Data.Start, entry.Data.Count);
                        int visible = Math.Min(characters.Length, 48);
                        int displayLength = 8 + source.Length;
                        displayLength += FrozenText.Quote(characters[..visible], displayText[displayLength..]);
                        if (visible != characters.Length) {
                            "..."u8.CopyTo(displayText[displayLength..]);
                            displayLength += 3;
                        }
                        displayText[displayLength++] = (byte)'_';
                        Utf8Formatter.TryFormat(rva, displayText[displayLength..], out int digits, new StandardFormat('X', 8));
                        displayText[displayLength + digits] = 0;
                        fixed (byte* display = displayText)
                            symbols.Define(address, 3, symbolName, display);
                    } else {
                        symbols.Define(address, 3, symbolName);
                    }
                    ++stats.Symbols;

                    "rtr::206::"u8.CopyTo(tagText);
                    symbolText.AsSpan(8, descriptorEnd - 8).CopyTo(tagText.AsSpan(10));
                    position = descriptorEnd + 2;
                    if (entry.Kind is FrozenKind.String or FrozenKind.Array) {
                        ReadOnlySpan<byte> prefix = entry.Kind == FrozenKind.String ? "::utf16["u8 : "::count["u8;
                        prefix.CopyTo(tagText.AsSpan(position));
                        position += prefix.Length;
                        Utf8Formatter.TryFormat(entry.Count, tagText.AsSpan(position), out int digits);
                        position += digits;
                        tagText[position++] = (byte)']';
                        if (entry.Kind == FrozenKind.String) {
                            "::"u8.CopyTo(tagText.AsSpan(position));
                            position += 2;
                            position += FrozenText.Quote(frozen.Data.Span.Slice(entry.Data.Start, entry.Data.Count), tagText.AsSpan(position));
                        }
                    }
                    tagText[position] = 0;

                    DataTags.Set(ownership, view, tagType, address, tagText.AsSpan(0, position + 1));
                }
            }
        } finally {
            foreach (nint shape in shapes.Values)
                Core.BNFreeType(shape);
            foreach (nint pointer in pointers.Values)
                Core.BNFreeType(pointer);
            Core.BNFreeType(character);
            Core.BNFreeType(integer);
            Core.BNFreeTagType(tagType);
        }
    }
}
