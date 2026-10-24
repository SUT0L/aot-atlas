using System.Runtime.InteropServices;

namespace Atlas;

public enum MapFormat : byte {
    Auto,
    Legacy,
    Metadata
}

public enum FieldLocation : byte {
    Unknown,
    Offset,
    StaticAddress,
    StaticBlock,
    Ordinal
}

public struct TypeMapEntry {
    public ulong MethodTable;
    public uint Handle;
    public int Vertex;
    internal int Signature;
    public string Name;
    public MetadataFactStatus NameStatus;
    public bool IsGlobalModule;
}

public readonly struct DerivedTypeEntry(int section, int vertex, ulong methodTable) {
    public readonly int Section = section;
    public readonly int Vertex = vertex;
    public readonly ulong MethodTable = methodTable;
}

public struct InvokeMapEntry {
    public ulong DeclaringType;
    public ulong Entrypoint;
    public ulong InvokeStub;

    public uint Flags;
    public uint SourceFlags;
    public uint MetadataOffset;
    public uint NativeSignatureOffset;

    public int Vertex;
    internal int Signature;
    public string Name;
    public IndexRange GenericArguments;
}

public struct FieldMapEntry {
    public ulong DeclaringType;
    public ulong StaticBase;

    public uint Flags;
    public uint SourceFlags;
    public uint MetadataOffset;
    public uint Value;
    public uint StaticBaseIndex;

    public int Vertex;
    internal int Signature;
    public string Name;
    public FieldLocation Location;

    public int Storage => (int)(Flags & 3);
}

public sealed class ReflectionMaps {
    private SignatureHistory? signatureOrigin;
    private Signatures? publication;

    public MapFormat Format { get; private set; }

    internal readonly List<TypeMapEntry> Types = new();
    internal readonly List<DerivedTypeEntry> DerivedTypes = new();
    internal readonly List<InvokeMapEntry> Methods = new();
    internal readonly List<FieldMapEntry> Fields = new();
    internal readonly List<ulong> GenericArguments = new();

    public ReadOnlySpan<TypeMapEntry> TypeEntries => CollectionsMarshal.AsSpan(Types);
    public ReadOnlySpan<DerivedTypeEntry> DerivedTypeEntries => CollectionsMarshal.AsSpan(DerivedTypes);
    public ReadOnlySpan<InvokeMapEntry> MethodEntries => CollectionsMarshal.AsSpan(Methods);
    public ReadOnlySpan<FieldMapEntry> FieldEntries => CollectionsMarshal.AsSpan(Fields);
    public ReadOnlySpan<ulong> MethodArguments => CollectionsMarshal.AsSpan(GenericArguments);

    public Signatures SignaturePublication => publication
        ?? throw new InvalidOperationException("Reflection map signatures have not been published.");
    public SignatureType TypeSignatureAt(int position) => SignaturePublication.Types[Types[position].Signature];
    public SignatureMethod MethodSignatureAt(int position) => Methods[position].Signature == 0
        ? default
        : SignaturePublication.MethodSignatures[Methods[position].Signature];
    public SignatureType FieldSignatureAt(int position) => Fields[position].Signature == 0
        ? default
        : SignaturePublication.Types[Fields[position].Signature];

    public ReflectionMaps() { }

    internal void ValidateSignatureOrigin(SignatureHistory origin) {
        if (signatureOrigin is not null && !ReferenceEquals(signatureOrigin, origin))
            throw new ArgumentException("Reflection map signatures belong to a different metadata namespace.");
    }

    internal void RequireSignaturePublication(Signatures publication) {
        if (signatureOrigin is null && (Types.Count != 0 || Methods.Count != 0 || Fields.Count != 0))
            throw new ArgumentException("Reflection maps must be decoded or constructed with their signature publication.");

        ValidateSignatureOrigin(publication.Origin);

        if (this.publication is not null
            && !ReferenceEquals(this.publication, publication)
            && !publication.Extends(this.publication))
            throw new ArgumentException("Reflection map signatures are not an unchanged prefix of the binding publication.");
    }

    internal void SetSignatureOrigin(Signatures publication) {
        ValidateSignatureOrigin(publication.Origin);
        signatureOrigin = publication.Origin;
        this.publication = publication;
    }

    internal static ReflectionMaps Decode(
        PeImage image,
        ReadyToRun header,
        MetadataBuilder metadata,
        ReadOnlySpan<ulong> fixups,
        MapFormat format = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        var result = new ReflectionMaps();
        result.Read(image, header, metadata, fixups, format, cancellationToken);

        return result;
    }

    internal static MapFormat SelectFormat(
        int major,
        ReadOnlySpan<byte> invokes,
        ReadOnlySpan<byte> fields,
        ReadOnlySpan<byte> nativeLayout,
        MetadataBuilder metadata,
        MapFormat requested = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        if (requested is MapFormat.Legacy or MapFormat.Metadata)
            return requested;

        if (requested != MapFormat.Auto)
            throw new ArgumentOutOfRangeException(nameof(requested));

        var grammar = NativeAotFormat.MapGrammar(major);

        if (grammar != MapFormat.Auto)
            return grammar;

        bool legacy = true;
        bool modern = true;
        bool any = false;

        for (int which = 0; which < 2; ++which) {
            var data = which == 0 ? invokes : fields;
            var table = new NativeTable(data);

            while (table.MoveNext()) {
                cancellationToken.ThrowIfCancellationRequested();

                any = true;

                var reader = new NativeReader(data, table.Vertex);
                uint flags = reader.Unsigned();

                if ((flags & (which == 0 ? 4U : 8U)) != 0) {
                    modern = false;
                    continue;
                }

                if (which != 0)
                    reader.Unsigned();

                int namePosition = reader.Position;
                uint handle = reader.Unsigned();

                // Membership in the decoded definition index proves record kind and signature together; plausible bytes do not
                if (modern)
                    modern = which == 0
                        ? metadata.MethodIndex.ContainsKey(handle)
                        : metadata.FieldIndex.ContainsKey(handle);

                if (legacy) {
                    try {
                        if (which == 0) {
                            if (handle == 0 || handle >= nativeLayout.Length)
                                legacy = false;
                            else {
                                var signature = new NativeReader(nativeLayout, (int)handle);
                                legacy = signature.String().Length != 0;

                                int origin = signature.Position;
                                long target = (long)origin + signature.Signed();
                                legacy &= target > 0 && target < nativeLayout.Length;
                            }
                        } else {
                            var name = new NativeReader(data, namePosition);
                            legacy = name.String().Length != 0 && name.Remaining != 0;
                        }
                    } catch (Exception error) when (
                        error is InvalidDataException or OverflowException or System.Text.DecoderFallbackException) {
                        legacy = false;
                    }
                }
            }
        }

        if (!any)
            return MapFormat.Auto;

        if (legacy != modern)
            return legacy ? MapFormat.Legacy : MapFormat.Metadata;

        throw new InvalidDataException("RTR 12 reflection map grammar is unresolved; specify --map-format legacy or --map-format metadata.");
    }

    internal static void RequireGrammar(MapFormat format) {
        if (format == MapFormat.Auto)
            throw new InvalidDataException("NativeLayout grammar is unresolved; specify --map-format legacy or --map-format metadata.");

        if (format is not (MapFormat.Legacy or MapFormat.Metadata))
            throw new ArgumentOutOfRangeException(nameof(format));
    }

    internal void Read(
        PeImage image,
        ReadyToRun rtr,
        MetadataBuilder metadata,
        ReadOnlySpan<ulong> fixups,
        MapFormat requested = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        rtr = rtr.ValidateSource(image);

        ValidateSignatureOrigin(metadata.SignatureBuilder.Origin);

        ReadCore(image, rtr, metadata, fixups, requested, cancellationToken);
        SetSignatureOrigin(metadata.SignatureBuilder.Publish());
    }

    private void ReadCore(
        PeImage image,
        ReadyToRun rtr,
        MetadataBuilder metadata,
        ReadOnlySpan<ulong> fixups,
        MapFormat requested,
        CancellationToken cancellationToken) {
        signatureOrigin = metadata.SignatureBuilder.Origin;

        var invokeSection = rtr.Find(RtrSectionId.InvokeMap);
        var fieldSection = rtr.Find(RtrSectionId.FieldAccessMap);
        var layoutSection = rtr.Find(RtrSectionId.NativeLayoutInfo);

        var invokes = invokeSection.Length == 0
            ? default
            : image.FileSpan(invokeSection.Start, checked((int)invokeSection.Length));
        var fields = fieldSection.Length == 0
            ? default
            : image.FileSpan(fieldSection.Start, checked((int)fieldSection.Length));
        var nativeLayout = layoutSection.Length == 0
            ? default
            : image.FileSpan(layoutSection.Start, checked((int)layoutSection.Length));

        Format = SelectFormat(rtr.Major, invokes, fields, nativeLayout, metadata, requested, cancellationToken);
        bool legacy = Format == MapFormat.Legacy;

        var globalModules = new HashSet<uint>();
        foreach (var id in metadata.ReadRecordIds()) {
            if (id.Kind != MetadataRecordKind.ScopeDefinition)
                continue;
            var module = metadata.RecordField(id, MetadataFieldName.GlobalModuleType).Reference;
            if (module.IsAvailable && module.Value.Kind == MetadataRecordKind.TypeDefinition && !module.Value.IsNil)
                globalModules.Add(module.Value.Offset);
        }

        ReadOnlySpan<RtrSectionId> typeMaps = [
            RtrSectionId.TypeMap,
            RtrSectionId.ArrayMap,
            RtrSectionId.PointerTypeMap,
            RtrSectionId.FunctionPointerTypeMap,
            RtrSectionId.ByRefTypeMap
        ];

        foreach (var id in typeMaps) {
            cancellationToken.ThrowIfCancellationRequested();

            var section = rtr.Find(id);
            if (section.Length == 0)
                continue;

            var data = image.FileSpan(section.Start, checked((int)section.Length));
            var table = new NativeTable(data);

            while (table.MoveNext()) {
                cancellationToken.ThrowIfCancellationRequested();

                var reader = new NativeReader(data, table.Vertex);
                uint index = reader.Unsigned();

                if (index >= fixups.Length)
                    throw new InvalidDataException($"Type map {(int)id} refers outside CommonFixups.");

                if (id != RtrSectionId.TypeMap) {
                    DerivedTypes.Add(new DerivedTypeEntry((int)id, table.Vertex, fixups[(int)index]));
                    continue;
                }

                uint handle = reader.Unsigned();
                int offsetBits = 32 - metadata.HandleBits;
                uint kind = handle >> offsetBits;

                if (kind is not (0x3A or 0x3D))
                    throw new InvalidDataException($"TypeMap contains an invalid metadata handle kind 0x{kind:X}.");

                uint offset = handle & ((1U << offsetBits) - 1);

                if (offset == 0)
                    throw new InvalidDataException("TypeMap contains a nil metadata handle.");

                uint metadataHandle = (offset << metadata.HandleBits) | kind;
                int signature = 0;
                string name = "";
                MetadataFactStatus nameStatus;
                var typeId = new MetadataRecordId((MetadataRecordKind)kind, offset);
                try {
                    signature = metadata.TypeSignature(metadataHandle);
                    name = metadata.SignatureBuilder.Nodes[signature].Name;
                    nameStatus = metadata.TypeNameStatus(typeId);
                } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
                    metadata.RecordFailure(metadataHandle, "reflection type", error);
                    name = metadata.Name(typeId, kind == 0x3D ? MetadataFieldName.TypeName : MetadataFieldName.Name);
                    nameStatus = MetadataFactStatus.Incomplete;
                }

                Types.Add(new TypeMapEntry {
                    MethodTable = fixups[(int)index],
                    Handle = handle,
                    Vertex = table.Vertex,
                    Signature = signature,
                    IsGlobalModule = kind == (uint)MetadataRecordKind.TypeDefinition && globalModules.Contains(offset),
                    Name = kind == 0x3D ? "typeref::" + name : name,
                    NameStatus = nameStatus
                });
            }
        }

        var invokeTable = new NativeTable(invokes);
        uint invokeMask = Format == MapFormat.Auto ? 0 : rtr.Format.InvokeMapFlags(Format);

        while (invokeTable.MoveNext()) {
            cancellationToken.ThrowIfCancellationRequested();

            var reader = new NativeReader(invokes, invokeTable.Vertex);

            InvokeMapEntry entry = new() {
                Vertex = invokeTable.Vertex,
                Flags = reader.Unsigned()
            };

            entry.SourceFlags = entry.Flags;
            entry.Flags = rtr.Format.NormalizeInvokeFlags(entry.SourceFlags);

            if ((entry.SourceFlags & ~invokeMask) != 0)
                throw new InvalidDataException($"Unknown InvokeMap flags 0x{entry.SourceFlags:X}.");

            uint handle = reader.Unsigned();
            uint type = reader.Unsigned();

            if (type >= fixups.Length)
                throw new InvalidDataException("InvokeMap declaring type refers outside CommonFixups.");

            entry.DeclaringType = fixups[(int)type];

            if ((entry.Flags & 0x20) != 0) {
                uint index = reader.Unsigned();

                if (index >= fixups.Length)
                    throw new InvalidDataException("InvokeMap entrypoint refers outside CommonFixups.");

                entry.Entrypoint = fixups[(int)index];

                if (!image.IsExecutable(entry.Entrypoint))
                    throw new InvalidDataException("InvokeMap entrypoint is outside executable sections.");
            }

            if ((entry.Flags & 0x80) == 0) {
                uint index = reader.Unsigned();

                if (index >= fixups.Length)
                    throw new InvalidDataException("InvokeMap invoke stub refers outside CommonFixups.");

                entry.InvokeStub = fixups[(int)index];

                if (!image.IsExecutable(entry.InvokeStub))
                    throw new InvalidDataException("InvokeMap invoke stub is outside executable sections.");
            }

            if (!legacy || (entry.Flags & 4) != 0)
                entry.MetadataOffset = handle;
            else
                entry.NativeSignatureOffset = handle;

            if ((entry.Flags & 2) != 0) {
                if (legacy && (entry.Flags & 0x10) != 0)
                    entry.NativeSignatureOffset = reader.Unsigned();

                if (!(rtr.Format.UniversalCanonicalMethods && (entry.Flags & 0x40) != 0)) {
                    int count = checked((int)reader.Unsigned());

                    if (count > reader.Remaining)
                        throw new InvalidDataException("InvokeMap generic arguments exceed storage.");

                    entry.GenericArguments = new IndexRange(GenericArguments.Count, count);
                    GenericArguments.EnsureCapacity(checked(GenericArguments.Count + count));

                    for (int i = 0; i < count; ++i) {
                        uint index = reader.Unsigned();

                        if (index >= fixups.Length)
                            throw new InvalidDataException("InvokeMap generic argument refers outside CommonFixups.");

                        GenericArguments.Add(fixups[(int)index]);
                    }
                }
            }

            if (entry.MetadataOffset != 0) {
                var methodId = new MetadataRecordId(MetadataRecordKind.Method, entry.MetadataOffset);
                try {
                    int index = metadata.ReadMethod(entry.MetadataOffset);
                    var method = metadata.Methods[index];
                    entry.Name = method.Name;
                    if (method.SignatureOffset == 0)
                        throw new InvalidDataException("Metadata method has no signature.");
                    if (method.Signature == 0)
                        method.Signature = metadata.MethodSignature(method.SignatureOffset);
                    metadata.Methods[index] = method;
                    entry.Signature = method.Signature;
                } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
                    uint metadataHandle = (entry.MetadataOffset << metadata.HandleBits) | (uint)MetadataRecordKind.Method;
                    metadata.RecordFailure(metadataHandle, "reflection method", error);
                    entry.Name = metadata.Name(methodId);
                }
            } else {
                if (entry.NativeSignatureOffset == 0 || entry.NativeSignatureOffset >= nativeLayout.Length)
                    throw new InvalidDataException("InvokeMap has no readable metadata or NativeLayout method identity.");

                var name = new NativeReader(nativeLayout, (int)entry.NativeSignatureOffset);
                entry.Name = name.String();

                int origin = name.Position;
                long target = (long)origin + name.Signed();

                if (target <= 0 || target >= nativeLayout.Length)
                    throw new InvalidDataException("InvokeMap NativeLayout signature points outside storage.");
            }

            Methods.Add(entry);
        }

        var fieldTable = new NativeTable(fields);
        uint fieldMask = Format == MapFormat.Auto ? 0 : rtr.Format.FieldMapFlags(Format);

        while (fieldTable.MoveNext()) {
            cancellationToken.ThrowIfCancellationRequested();

            var reader = new NativeReader(fields, fieldTable.Vertex);

            FieldMapEntry entry = new() {
                Vertex = fieldTable.Vertex,
                Flags = reader.Unsigned()
            };

            entry.SourceFlags = entry.Flags;
            entry.Flags = rtr.Format.NormalizeFieldFlags(entry.SourceFlags);

            if ((entry.SourceFlags & ~fieldMask) != 0)
                throw new InvalidDataException($"Unknown FieldAccessMap flags 0x{entry.SourceFlags:X}.");

            uint type = reader.Unsigned();

            if (type >= fixups.Length)
                throw new InvalidDataException("FieldAccessMap declaring type refers outside CommonFixups.");

            entry.DeclaringType = fixups[(int)type];

            if (!legacy || (entry.Flags & 8) != 0) {
                entry.MetadataOffset = reader.Unsigned();
                var fieldId = new MetadataRecordId(MetadataRecordKind.Field, entry.MetadataOffset);
                try {
                    int index = metadata.ReadField(entry.MetadataOffset);
                    var field = metadata.Fields[index];
                    entry.Name = field.Name;
                    if (field.Signature == 0) {
                        var signature = new MetadataRecordId(MetadataRecordKind.FieldSignature, field.SignatureOffset);
                        field.Signature = metadata.TypeSignature(metadata.Handle(signature, MetadataFieldName.Type));
                    }
                    metadata.Fields[index] = field;
                    entry.Signature = field.Signature;
                } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
                    uint metadataHandle = (entry.MetadataOffset << metadata.HandleBits) | (uint)MetadataRecordKind.Field;
                    metadata.RecordFailure(metadataHandle, "reflection field", error);
                    entry.Name = metadata.Name(fieldId);
                }
            } else
                entry.Name = reader.String();

            if (rtr.Format.OrdinalFields && (entry.Flags & 4) != 0) {
                entry.Location = FieldLocation.Ordinal;
                entry.Value = reader.Unsigned();
            } else if (entry.Storage == 0 || (entry.Flags & 0x20) != 0) {
                entry.Location = FieldLocation.Offset;
                entry.Value = reader.Unsigned();
            } else {
                entry.StaticBaseIndex = reader.Unsigned();

                if (entry.StaticBaseIndex >= fixups.Length)
                    throw new InvalidDataException("FieldAccessMap static storage refers outside CommonFixups.");

                entry.StaticBase = fixups[(int)entry.StaticBaseIndex];
                entry.Location = entry.Storage == 1
                    ? FieldLocation.StaticAddress
                    : FieldLocation.StaticBlock;

                if (entry.Storage != 1)
                    entry.Value = reader.Unsigned();
            }

            Fields.Add(entry);
        }
    }
}
