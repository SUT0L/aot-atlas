using System.Buffers;
using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas.Binja;

internal static unsafe class InstanceTypes {
    internal static void Apply(nint view, Extraction extraction, nint headerType, nint voidPointer,
        Span<nint> references, Span<nint> staticFields, nint task) {
        var tables = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var layouts = extraction.Fields.Layouts.AsSpan();
        var fields = CollectionsMarshal.AsSpan(extraction.Fields.FieldTypes);
        var locations = extraction.Fields.Fields.AsSpan();
        var maps = CollectionsMarshal.AsSpan(extraction.Maps.Fields);
        var gc = CollectionsMarshal.AsSpan(extraction.Gc.Layouts);
        var runs = CollectionsMarshal.AsSpan(extraction.Gc.Runs);
        int count = tables.Length;
        int maxName = 0, maxArguments = 0;
        foreach (string name in extraction.Names.Values)
            maxName = Math.Max(maxName, name.Length);

        foreach (ref readonly var table in tables)
            maxArguments = Math.Max(maxArguments, table.Arguments.Count);

        foreach (ref readonly var field in maps) {
            if (field.Name.Contains('\0'))
                throw new InvalidDataException("A field name contains a NUL and cant be represented by a native type.");

            maxName = Math.Max(maxName, field.Name.Length);
        }

        ReadOnlySpan<byte> idPrefix = "aot-atlas:runtime-type:v1:"u8;
        int idStride = idPrefix.Length + 9;
        byte[] ids = new byte[checked(count * idStride)];
        byte[] nameBuffer = new byte[checked(Encoding.UTF8.GetMaxByteCount(maxName) + 9)];
        nint[] pointers = new nint[count];
        nint[] fieldTypes = new nint[fields.Length];
        nint[] unresolved = new nint[fields.Length];
        QualifiedName[] names = new QualifiedName[count];
        nint[] primitives = new nint[16];
        nint[] enums = new nint[extraction.Enums.Definitions.Count];
        int[] gcIndices = new int[count];
        var prefixes = new TypePrefixes(view);
        nint[] partialScalars = new nint[8];
        BoolConfidence qualifier = default;
        var headerConfidence = new TypeConfidence(headerType);
        nint headerPointer = Core.BNCreatePointerTypeOfWidth(8, &headerConfidence, &qualifier, &qualifier, 0);
        try {
            EnumTypes.Create(extraction.Metadata, extraction.Enums, enums);
            EnumTypes.Apply(view, extraction.Metadata, extraction.Enums, enums);

            byte emptyName = 0;
            primitives[2] = Core.BNCreateBoolType();
            primitives[3] = Core.BNCreateWideCharType(2, &emptyName);
            for (int code = 4; code <= 13; ++code) {
                BoolConfidence sign = new() { Value = (byte)((code & 1) == 0 ? 1 : 0), Confidence = 255 };
                nuint width = code < 12 ? (nuint)(1 << ((code - 4) / 2)) : 8;
                primitives[code] = Core.BNCreateIntegerType(width, &sign, &emptyName);
            }

            primitives[14] = Core.BNCreateFloatType(4, &emptyName);
            primitives[15] = Core.BNCreateFloatType(8, &emptyName);
            for (int i = 0; i < gc.Length; ++i)
                gcIndices[gc[i].TypeIndex] = i + 1;

            fixed (byte* idBytes = ids)
            fixed (byte* text = nameBuffer)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* runtime = "runtime\0"u8)
            fixed (byte* opaque = "opaque\0"u8)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[3] { atlas, runtime, text };
                QualifiedName name = new() { Names = parts, Join = join, Count = 3 };
                for (int i = 0; i < count; ++i) {
                    if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    ref readonly var table = ref tables[i];
                    var identifier = ids.AsSpan(i * idStride, idStride);
                    idPrefix.CopyTo(identifier);
                    Utf8Formatter.TryFormat((uint)(table.Address - extraction.Image.ImageBase), identifier[idPrefix.Length..], out _, new StandardFormat('X', 8));
                    int bytes = Encoding.UTF8.GetBytes(extraction.Names.Values[i], nameBuffer);
                    nameBuffer[bytes] = 0;
                    byte* id = idBytes + i * idStride;
                    bool indirect = table.Kind == 1 || table.ElementType is 0x19 or 0x1A;
                    int enumeration = extraction.Enums.RuntimeIndices[i];
                    if (layouts[i].Length == 0 && !indirect && enumeration == 0) {
                        parts[1] = opaque;
                        nint named = Core.BNCreateNamedType(3, id, &name);
                        references[i] = Core.BNCreateNamedTypeReference(named, 0, 1, &qualifier, &qualifier);
                        Core.BNFreeNamedTypeReference(named);
                        continue;
                    }

                    parts[1] = runtime;
                    nint type;
                    bool scalar = table.IsValueType && table.ElementType is >= 2 and <= 15;
                    if (enumeration != 0) {
                        type = enums[enumeration - 1];
                    } else if (scalar || indirect) {
                        type = scalar ? primitives[table.ElementType] : voidPointer;
                    } else {
                        nint builder = Core.BNCreateStructureBuilder();
                        Core.BNSetStructureBuilderPacked(builder, 1);
                        Core.BNSetStructureBuilderWidth(builder, layouts[i].Length);
                        nint structure = Core.BNFinalizeStructureBuilder(builder);
                        type = Core.BNCreateStructureType(structure);
                        Core.BNFreeStructure(structure);
                        Core.BNFreeStructureBuilder(builder);
                    }

                    // Reserving the actual name and width makes every forward reference usable before any member list is constructed
                    var actual = Core.BNDefineAnalysisType(view, id, &name, type);
                    names[i] = actual;
                    references[i] = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                    if (!scalar && !indirect && enumeration == 0)
                        Core.BNFreeType(type);
                }
            }

            byte** fieldParts = stackalloc byte*[3];
            Span<byte> fieldId = stackalloc byte[64];
            ReadOnlySpan<byte> fieldPrefix = "aot-atlas:field-type:v1:"u8;
            fieldPrefix.CopyTo(fieldId);
            var signature = new StringBuilder(256);
            char[] signatureChars = new char[256];
            byte[] signatureBytes = new byte[Encoding.UTF8.GetMaxByteCount(signatureChars.Length) + 1];
            string[] arguments = new string[maxArguments];
            for (int i = 0; i < fields.Length; ++i) {
                ref readonly var field = ref fields[i];
                if (field.Binding != 0) {
                    int binding = field.Binding - 1;
                    if (field.Storage == FieldStorageKind.Reference) {
                        if (pointers[binding] == 0) {
                            var target = new TypeConfidence(references[binding]);
                            pointers[binding] = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
                        }

                        fieldTypes[i] = pointers[binding];
                    } else {
                        fieldTypes[i] = references[binding];
                    }
                } else {
                    // The field still has a proven name and offset
                    // An opaque member retains both when its runtime identity is absent
                    ref readonly var map = ref maps[field.MapIndex];
                    int owner = field.Owner - 1;
                    var args = map.Location == FieldLocation.Ordinal ? default : tables[owner].Arguments;
                    for (int j = 0; j < args.Count; ++j)
                        arguments[j] = extraction.Names.Values[extraction.Types.Index[extraction.Types.Pointers[args.Start + j]]];

                    signature.Clear();
                    extraction.Metadata.Signatures.AppendType(signature, field.Signature, arguments.AsSpan(0, args.Count));
                    if (signature.Length > signatureChars.Length) {
                        Array.Resize(ref signatureChars, Math.Max(signature.Length, signatureChars.Length * 2));
                        Array.Resize(ref signatureBytes, Encoding.UTF8.GetMaxByteCount(signatureChars.Length) + 1);
                    }

                    signature.CopyTo(0, signatureChars, 0, signature.Length);
                    var characters = signatureChars.AsSpan(0, signature.Length);
                    if (characters.Contains('\0'))
                        throw new InvalidDataException("A field signature contains a NUL and cant be represented by a native type.");

                    int bytes = Encoding.UTF8.GetBytes(characters, signatureBytes);
                    signatureBytes[bytes] = 0;
                    Utf8Formatter.TryFormat((uint)(tables[owner].Address - extraction.Image.ImageBase), fieldId[fieldPrefix.Length..], out _, new StandardFormat('X', 8));
                    fieldId[fieldPrefix.Length + 8] = (byte)':';
                    Utf8Formatter.TryFormat(map.Vertex, fieldId[(fieldPrefix.Length + 9)..], out _, new StandardFormat('X', 8));
                    fieldId[fieldPrefix.Length + 17] = 0;

                    fixed (byte* atlas = "atlas\0"u8)
                    fixed (byte* unknown = "unresolved\0"u8)
                    fixed (byte* join = "::\0"u8)
                    fixed (byte* text = signatureBytes)
                    fixed (byte* id = fieldId) {
                        fieldParts[0] = atlas;
                        fieldParts[1] = unknown;
                        fieldParts[2] = text;
                        QualifiedName name = new() { Names = fieldParts, Join = join, Count = 3 };
                        nint named = Core.BNCreateNamedType(0, id, &name);
                        bool reference = field.Storage == FieldStorageKind.Reference;
                        nint type = Core.BNCreateNamedTypeReference(named, reference ? 0 : field.Size, 1, &qualifier, &qualifier);
                        Core.BNFreeNamedTypeReference(named);
                        if (reference) {
                            var target = new TypeConfidence(type);
                            unresolved[i] = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
                            Core.BNFreeType(type);
                        } else {
                            unresolved[i] = type;
                        }

                        fieldTypes[i] = unresolved[i];
                    }
                }

                if (i < maps.Length && maps[i].Storage == 1)
                    staticFields[i] = Core.BNNewTypeReference(fieldTypes[i]);
            }

            fixed (byte* idBytes = ids)
            fixed (byte* text = nameBuffer)
            fixed (byte* mtName = "__mt\0"u8) {
                var mtConfidence = new TypeConfidence(headerPointer);
                Span<byte> referenceName = stackalloc byte[14];
                "_ref_"u8.CopyTo(referenceName);
                for (int job = 0; job < count + prefixes.Jobs.Count; ++job) {
                    if (task != 0 && (job & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    bool isPrefix = job >= count;
                    var prefix = isPrefix ? prefixes.Jobs[job - count] : default;
                    int i = isPrefix ? prefix.TypeIndex : job;
                    if (i < 0)
                        continue;

                    ref readonly var table = ref tables[i];
                    ref readonly var layout = ref layouts[i];
                    uint width = isPrefix ? prefix.Width : layout.Length;
                    var name = isPrefix ? prefix.Name : names[i];
                    if (table.Kind == 2 && table.ElementType is 0x19 or 0x1A) {
                        int related = extraction.Types.Index[table.RelatedType];
                        nint element = references[related];
                        if (tables[related].ElementType is >= 0x14 and <= 0x18) {
                            // A reference slot contains an object pointer
                            // A byref to that slot therefore needs one more indirection
                            if (pointers[related] == 0) {
                                var objectType = new TypeConfidence(element);
                                pointers[related] = Core.BNCreatePointerTypeOfWidth(8, &objectType, &qualifier, &qualifier, 0);
                            }
                            element = pointers[related];
                        }

                        var target = new TypeConfidence(element);
                        nint type = Core.BNCreatePointerTypeOfWidth(8, &target, &qualifier, &qualifier, 0);
                        var actual = Core.BNDefineAnalysisType(view, idBytes + i * idStride, &name, type);
                        Core.BNFreeQualifiedName(&actual);
                        Core.BNFreeType(type);
                        continue;
                    }

                    if (layout.Length == 0 || extraction.Enums.RuntimeIndices[i] != 0 || (table.IsValueType && table.ElementType is >= 2 and <= 15))
                        continue;

                    byte* identifier = idBytes + i * idStride;
                    if (isPrefix) {
                        nint reference = Core.BNGetTypeNamedTypeReference(prefix.Reference);
                        identifier = Core.BNGetTypeReferenceId(reference);
                        Core.BNFreeNamedTypeReference(reference);
                    }

                    nint builder = Core.BNCreateStructureBuilder();
                    try {
                        Core.BNSetStructureBuilderPacked(builder, 1);
                        Core.BNSetStructureBuilderWidth(builder, width);
                        uint baseExtent = 0;
                        if (layout.BaseType != 0) {
                            int parent = layout.BaseType - 1;
                            baseExtent = Math.Min(layouts[parent].Length, width);
                            // Base structures overlay their members into unoccupied offsets; derived fields can reuse the parents padding
                            if (baseExtent != 0) {
                                nint parentReference = references[parent];
                                if (baseExtent < layouts[parent].Length)
                                    parentReference = prefixes.Add(parentReference, parent, baseExtent);

                                BaseStructure parentType = new() {
                                    Type = Core.BNGetTypeNamedTypeReference(parentReference),
                                    Width = baseExtent
                                };
                                Core.BNSetBaseStructuresForStructureBuilder(builder, &parentType, 1);
                                Core.BNFreeNamedTypeReference(parentType.Type);
                            }
                        } else if (!table.IsValueType) {
                            Core.BNAddStructureBuilderMemberAtOffset(builder, &mtConfidence, mtName, 0, 0, 0, 0, 0, 0);
                        }

                        for (int j = layout.Fields.Start; j < layout.Fields.End; ++j) {
                            ref readonly var location = ref locations[j];
                            if (location.Offset >= width)
                                break;

                            ref readonly var field = ref fields[location.FieldIndex];
                            nint nativeType = fieldTypes[location.FieldIndex];
                            bool scalar = field.Storage is FieldStorageKind.Reference or FieldStorageKind.Pointer or FieldStorageKind.ByReference
                                || (field.Binding != 0 && tables[field.Binding - 1].ElementType is >= 2 and <= 15);
                            uint extent = Math.Min(scalar ? field.Size : location.Extent, width - location.Offset);
                            bool cutScalar = scalar && extent < field.Size;
                            if (cutScalar) {
                                if (!isPrefix)
                                    throw new InvalidDataException("A scalar field exceeds the instance layout.");

                                if (partialScalars[extent] == 0) {
                                    var element = new TypeConfidence(primitives[5]);
                                    partialScalars[extent] = Core.BNCreateArrayType(&element, extent);
                                }

                                nativeType = partialScalars[extent];
                            } else if (!scalar && extent < field.Size) {
                                nativeType = prefixes.Add(nativeType, field.Binding - 1, extent);
                            }

                            int nameStart = cutScalar ? 8 : 0;
                            if (cutScalar)
                                "prefix::"u8.CopyTo(nameBuffer);

                            int bytes = Encoding.UTF8.GetBytes(maps[field.MapIndex].Name, nameBuffer.AsSpan(nameStart));
                            nameBuffer[nameStart + bytes] = 0;
                            var type = new TypeConfidence(nativeType);
                            Core.BNAddStructureBuilderMemberAtOffset(builder, &type, text, location.Offset, 0, 0, 0, 0, 0);
                        }

                        int gcIndex = gcIndices[i] - 1;
                        if (gcIndex >= 0) {
                            var range = gc[gcIndex].Runs;
                            var pointerType = new TypeConfidence(voidPointer);
                            bool parentReferences = layout.BaseType != 0 && gcIndices[layout.BaseType - 1] != 0;
                            for (int run = range.Start; run < range.End; ++run) {
                                uint first = runs[run].Offset - (table.IsValueType ? 8U : 0);
                                int member = layout.Fields.Start;
                                for (uint slot = 0; slot < runs[run].Count; ++slot) {
                                    uint offset = first + slot * 8;
                                    if (offset > width || width - offset < 8) {
                                        if (isPrefix)
                                            break;

                                        throw new InvalidDataException("A GC reference exceeds the instance layout.");
                                    }

                                    if (parentReferences && offset + 8 <= baseExtent)
                                        continue;

                                    while (member < layout.Fields.End && locations[member].Offset + locations[member].Extent <= offset)
                                        ++member;

                                    if (member < layout.Fields.End && locations[member].Offset <= offset
                                        && offset + 8 <= locations[member].Offset + locations[member].Extent) {
                                        ref readonly var field = ref fields[locations[member].FieldIndex];
                                        if (field.Storage is FieldStorageKind.Reference or FieldStorageKind.ByReference
                                            || (field.Storage == FieldStorageKind.Value && field.Binding != 0 && gcIndices[field.Binding - 1] != 0))
                                            continue;
                                    }

                                    Utf8Formatter.TryFormat(offset, referenceName[5..], out int bytes, new StandardFormat('X', 2));
                                    referenceName[5 + bytes] = 0;
                                    fixed (byte* memberName = referenceName)
                                        Core.BNAddStructureBuilderMemberAtOffset(builder, &pointerType, memberName, offset, 0, 0, 0, 0, 0);
                                }
                            }
                        }

                        nint structure = Core.BNFinalizeStructureBuilder(builder);
                        nint result = Core.BNCreateStructureType(structure);
                        Core.BNFreeStructure(structure);
                        var actual = Core.BNDefineAnalysisType(view, identifier, &name, result);
                        Core.BNFreeQualifiedName(&actual);
                        Core.BNFreeType(result);
                    } finally {
                        Core.BNFreeStructureBuilder(builder);
                        if (isPrefix)
                            Core.BNFreeString(identifier);
                    }
                }
            }
        } finally {
            prefixes.Free();
            foreach (nint type in enums) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            foreach (nint type in partialScalars) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            foreach (nint type in unresolved) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            foreach (nint type in pointers) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            foreach (ref var name in names.AsSpan()) {
                if (name.Count != 0) {
                    fixed (QualifiedName* pointer = &name)
                        Core.BNFreeQualifiedName(pointer);
                }
            }
            foreach (nint type in primitives) {
                if (type != 0)
                    Core.BNFreeType(type);
            }

            Core.BNFreeType(headerPointer);
        }
    }
}
