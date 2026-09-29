using System.Buffers;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal readonly record struct PropertyApplyStats(int Types, int Tags, int References);

internal static unsafe class PropertyTypes {
    // Each nonzero output owns a new reference
    // The caller keeps runtime types alive alongside these views and frees both after their consumers finish
    internal static PropertyApplyStats Apply(TagOwnership ownership, nint view, Extraction extraction, PropertyProjections properties,
        ReadOnlySpan<nint> runtimeTypes, nint voidPointer, Span<nint> references, nint task) {
        var projections = CollectionsMarshal.AsSpan(properties.Projections);
        if (projections.IsEmpty) {
            return default;
        }

        var ranges = new IndexRange[runtimeTypes.Length];
        var names = new QualifiedName[runtimeTypes.Length];
        int maximumName = 0, typeCount = 0, referenceCount = 0;
        for (int start = 0; start < projections.Length;) {
            int end = start + 1;
            int owner = projections[start].Owner;
            while (end < projections.Length && projections[end].Owner == owner) {
                ++end;
            }
            ranges[owner] = new IndexRange(start, end - start);
            ++typeCount;
            start = end;
        }
        foreach (ref readonly var projection in projections) {
            string name = properties.Members.Properties[projection.Property].Name;
            string owner = extraction.Names.Values[projection.Owner];
            string contract = extraction.Names.Values[projection.Contract];
            if (name.Contains('\0') || owner.Contains('\0') || contract.Contains('\0')) {
                throw new InvalidDataException("A property name contains a NUL and cant be represented by a native type.");
            }
            maximumName = Math.Max(maximumName, Math.Max(owner.Length, name.Length + contract.Length + 32));
        }

        byte[] textBuffer = new byte[Encoding.UTF8.GetMaxByteCount(maximumName) + 1];
        char[] characters = new char[maximumName];
        var text = new StringBuilder(maximumName);
        var pointers = new Dictionary<nint, nint>();
        BoolConfidence qualifier = default;
        Span<byte> id = stackalloc byte[64];
        ReadOnlySpan<byte> prefix = "aot-atlas:property-view:v1:"u8;
        prefix.CopyTo(id);
        id[prefix.Length + 8] = 0;
        nint tagType;
        fixed (byte* tagName = "AOT Atlas properties\0"u8)
        fixed (byte* icon = "🔎\0"u8) {
            tagType = Core.BNGetTagType(view, tagName);
            if (tagType == 0) {
                tagType = Core.BNCreateTagType(view);
                Core.BNTagTypeSetName(tagType, tagName);
                Core.BNTagTypeSetIcon(tagType, icon);
                Core.BNAddTagType(view, tagType);
            }
        }
        ownership.Reserve(typeCount);

        try {
            fixed (byte* identifier = id)
            fixed (byte* nameBytes = textBuffer)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* propertyNamespace = "properties\0"u8)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[3] { atlas, propertyNamespace, nameBytes };
                QualifiedName name = new() { Names = parts, Join = join, Count = 3 };
                for (int owner = 0; owner < ranges.Length; ++owner) {
                    if (ranges[owner].Count == 0) {
                        continue;
                    }
                    uint rva = checked((uint)(extraction.Types.Types[owner].Address - extraction.Image.ImageBase));
                    Utf8Formatter.TryFormat(rva, id[prefix.Length..], out _, new StandardFormat('X', 8));
                    int length = Encoding.UTF8.GetBytes(extraction.Names.Values[owner], textBuffer);
                    textBuffer[length] = 0;
                    nint builder = Core.BNCreateStructureBuilder();
                    Core.BNSetStructureBuilderPacked(builder, 1);
                    Core.BNSetStructureBuilderWidth(builder, extraction.Fields.Layouts[owner].Length);
                    nint structure = Core.BNFinalizeStructureBuilder(builder);
                    nint type = Core.BNCreateStructureType(structure);
                    Core.BNFreeStructure(structure);
                    Core.BNFreeStructureBuilder(builder);
                    names[owner] = Core.BNDefineAnalysisType(view, identifier, &name, type);
                    var actual = names[owner];
                    references[owner] = Core.BNCreateNamedTypeReferenceFromTypeAndId(identifier, &actual, type);
                    Core.BNFreeType(type);
                }

                for (int owner = 0; owner < ranges.Length; ++owner) {
                    var range = ranges[owner];
                    if (range.Count == 0) {
                        continue;
                    }
                    if (task != 0 && Core.BNIsBackgroundTaskCancelled(task) != 0) {
                        throw new OperationCanceledException();
                    }
                    uint rva = checked((uint)(extraction.Types.Types[owner].Address - extraction.Image.ImageBase));
                    Utf8Formatter.TryFormat(rva, id[prefix.Length..], out _, new StandardFormat('X', 8));
                    nint builder = Core.BNCreateStructureBuilder();
                    try {
                        uint width = extraction.Fields.Layouts[owner].Length;
                        Core.BNSetStructureBuilderPacked(builder, 1);
                        Core.BNSetStructureBuilderWidth(builder, width);
                        BaseStructure original = new() { Type = Core.BNGetTypeNamedTypeReference(runtimeTypes[owner]), Width = width };
                        Core.BNSetBaseStructuresForStructureBuilder(builder, &original, 1);
                        Core.BNFreeNamedTypeReference(original.Type);

                        for (int i = range.Start; i < range.End; ++i) {
                            ref readonly var projection = ref projections[i];
                            nint member = voidPointer;
                            var storage = projection.Storage;
                            if (storage.Binding != 0) {
                                int target = storage.Binding - 1;
                                member = references[target] != 0 ? references[target] : runtimeTypes[target];
                                if (storage.Kind == AbiKind.Reference) {
                                    if (!pointers.TryGetValue(member, out nint pointer)) {
                                        var value = new TypeConfidence(member);
                                        pointer = Core.BNCreatePointerTypeOfWidth(8, &value, &qualifier, &qualifier, 0);
                                        pointers.Add(member, pointer);
                                    }
                                    member = pointer;
                                }
                            }

                            text.Clear();
                            text.Append(projection.Origin switch {
                                PropertyOrigin.Interface => "interface_property",
                                PropertyOrigin.Base => "base_property",
                                PropertyOrigin.Canonical => "canonical_property",
                                _ => "property"
                            });
                            text.Append(projection.Getter == 0 ? "_store::" : "::");
                            if (projection.Owner != projection.Contract) {
                                text.Append(extraction.Names.Values[projection.Contract]).Append("::");
                            }
                            text.Append(properties.Members.Properties[projection.Property].Name);
                            text.CopyTo(0, characters, 0, text.Length);
                            int length = Encoding.UTF8.GetBytes(characters.AsSpan(0, text.Length), textBuffer);
                            textBuffer[length] = 0;
                            var confidence = new TypeConfidence(member);
                            Core.BNAddStructureBuilderMemberAtOffset(builder, &confidence, nameBytes, (uint)projection.Offset, 0, 0, 0, 0, 0);
                        }

                        nint structure = Core.BNFinalizeStructureBuilder(builder);
                        nint type = Core.BNCreateStructureType(structure);
                        Core.BNFreeStructure(structure);
                        var actual = names[owner];
                        var defined = Core.BNDefineAnalysisType(view, identifier, &actual, type);
                        Core.BNFreeQualifiedName(&defined);
                        Core.BNFreeType(type);
                    } finally {
                        Core.BNFreeStructureBuilder(builder);
                    }
                }
            }

            ulong imageBase = Core.BNGetImageBase(view);
            byte[] tagBuffer = new byte[4096];
            for (int owner = 0; owner < ranges.Length; ++owner) {
                var range = ranges[owner];
                if (range.Count == 0) {
                    continue;
                }
                text.Clear();
                ulong address = imageBase + extraction.Types.Types[owner].Address - extraction.Image.ImageBase;
                for (int i = range.Start; i < range.End; ++i) {
                    ref readonly var projection = ref projections[i];
                    text.Append(projection.Origin).Append(projection.Getter == 0 ? " property_store::" : " property::")
                        .Append(extraction.Names.Values[projection.Contract])
                        .Append("::").Append(properties.Members.Properties[projection.Property].Name)
                        .Append(" +0x").Append(projection.Offset.ToString("X")).Append(" size=").Append(projection.Size)
                        .Append(" metadata=0x").Append(projection.Property.ToString("X"));
                    if (projection.Origin == PropertyOrigin.Canonical) {
                        text.Append(" source=").Append(extraction.Names.Values[projection.SourceOwner]);
                    }
                    for (int accessor = 0; accessor < 2; ++accessor) {
                        ulong target = accessor == 0 ? projection.Getter : projection.Setter;
                        if (target == 0) {
                            continue;
                        }
                        ulong translated = imageBase + target - extraction.Image.ImageBase;
                        text.Append(accessor == 0 ? " getter=0x" : " setter=0x").Append(translated.ToString("X"));
                        Core.BNAddUserDataReference(view, address, translated);
                        ++referenceCount;
                    }
                    text.Append('\n');
                }
                if (characters.Length < text.Length) {
                    Array.Resize(ref characters, text.Length);
                }
                text.CopyTo(0, characters, 0, text.Length);
                int capacity = Encoding.UTF8.GetMaxByteCount(text.Length) + 1;
                if (tagBuffer.Length < capacity) {
                    Array.Resize(ref tagBuffer, capacity);
                }
                int bytes = Encoding.UTF8.GetBytes(characters.AsSpan(0, text.Length), tagBuffer);
                tagBuffer[bytes] = 0;
                DataTags.Set(ownership, view, tagType, address, tagBuffer.AsSpan(0, bytes + 1));
            }
        } finally {
            foreach (var pointer in pointers.Values) {
                Core.BNFreeType(pointer);
            }
            foreach (var item in names) {
                if (item.Count != 0) {
                    var name = item;
                    Core.BNFreeQualifiedName(&name);
                }
            }
            Core.BNFreeTagType(tagType);
        }
        return new PropertyApplyStats(typeCount, typeCount, referenceCount);
    }
}
