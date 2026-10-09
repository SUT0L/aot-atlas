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
    private sealed class State {
        internal MapFormat Format;
        internal SignatureHistory? Origin;
        internal Signatures? Publication;

        internal readonly List<TypeMapEntry> Types;
        internal readonly List<DerivedTypeEntry> DerivedTypes;
        internal readonly List<InvokeMapEntry> Methods;
        internal readonly List<FieldMapEntry> Fields;
        internal readonly List<ulong> GenericArguments;

        internal State() {
            Types = new();
            DerivedTypes = new();
            Methods = new();
            Fields = new();
            GenericArguments = new();
        }

        internal State(State source) {
            Format = source.Format;
            Origin = source.Origin;
            Publication = source.Publication;

            Types = new(source.Types);
            DerivedTypes = new(source.DerivedTypes);
            Methods = new(source.Methods);
            Fields = new(source.Fields);
            GenericArguments = new(source.GenericArguments);
        }
    }

    private State state;

    public MapFormat Format {
        get => state.Format;
        private set => state.Format = value;
    }

    private SignatureHistory? signatureOrigin {
        get => state.Origin;
        set => state.Origin = value;
    }

    internal List<TypeMapEntry> Types => state.Types;
    internal List<DerivedTypeEntry> DerivedTypes => state.DerivedTypes;
    internal List<InvokeMapEntry> Methods => state.Methods;
    internal List<FieldMapEntry> Fields => state.Fields;
    internal List<ulong> GenericArguments => state.GenericArguments;

    public ReadOnlySpan<TypeMapEntry> TypeEntries => CollectionsMarshal.AsSpan(Types);
    public ReadOnlySpan<DerivedTypeEntry> DerivedTypeEntries => CollectionsMarshal.AsSpan(DerivedTypes);
    public ReadOnlySpan<InvokeMapEntry> MethodEntries => CollectionsMarshal.AsSpan(Methods);
    public ReadOnlySpan<FieldMapEntry> FieldEntries => CollectionsMarshal.AsSpan(Fields);
    public ReadOnlySpan<ulong> MethodArguments => CollectionsMarshal.AsSpan(GenericArguments);

    public Signatures SignaturePublication => state.Publication
        ?? throw new InvalidOperationException("Reflection map signatures have not been published.");
    public SignatureType TypeSignatureAt(int position) => SignaturePublication.Types[Types[position].Signature];
    public SignatureMethod MethodSignatureAt(int position) => Methods[position].Signature == 0
        ? default
        : SignaturePublication.MethodSignatures[Methods[position].Signature];
    public SignatureType FieldSignatureAt(int position) => Fields[position].Signature == 0
        ? default
        : SignaturePublication.Types[Fields[position].Signature];

    public ReflectionMaps() {
        state = new();
    }

    // Numeric prefixes are preserved only after the source namespace has
    // been checked. The private extraction branch receives a fresh namespace.
    private ReflectionMaps(ReflectionMaps source, SignatureHistory? origin) {
        state = new(source.state);

        if (origin is not null) {
            signatureOrigin = origin;
            state.Publication = null;
        }
    }

    internal ReflectionMaps Fork(SignatureHistory? origin) => new(this, origin);

    internal void ValidateSignatureOrigin(SignatureHistory origin) {
        if (signatureOrigin is not null && !ReferenceEquals(signatureOrigin, origin))
            throw new ArgumentException("Reflection map signatures belong to a different metadata namespace.");
    }

    internal void RequireSignaturePublication(Signatures publication) {
        if (signatureOrigin is null && (Types.Count != 0 || Methods.Count != 0 || Fields.Count != 0))
            throw new ArgumentException("Reflection maps must be decoded or constructed with their signature publication.");

        ValidateSignatureOrigin(publication.Origin);

        if (state.Publication is not null
            && !ReferenceEquals(state.Publication, publication)
            && !publication.Extends(state.Publication))
            throw new ArgumentException("Reflection map signatures are not an unchanged prefix of the binding publication.");
    }

    internal void SetSignatureOrigin(Signatures publication) {
        ValidateSignatureOrigin(publication.Origin);
        signatureOrigin = publication.Origin;
        state.Publication = publication;
    }

    public static ReflectionMaps Decode(
        PeImage image,
        ReadyToRun header,
        Metadata metadata,
        ReadOnlySpan<ulong> fixups,
        MapFormat format = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        var result = new ReflectionMaps();
        result.Read(image, header, metadata, fixups, format, cancellationToken);

        return result;
    }

    public static MapFormat SelectFormat(
        int major,
        ReadOnlySpan<byte> invokes,
        ReadOnlySpan<byte> fields,
        ReadOnlySpan<byte> nativeLayout,
        Metadata metadata,
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
        Metadata metadata,
        ReadOnlySpan<ulong> fixups,
        MapFormat requested = MapFormat.Auto,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        rtr = rtr.ValidateSource(image);

        ValidateSignatureOrigin(metadata.SignatureBuilder.Origin);

        var workingMetadata = metadata.WorkingCopy();
        var workingMaps = new ReflectionMaps(this, workingMetadata.SignatureBuilder.Origin);
        workingMaps.ReadCore(image, rtr, workingMetadata, fixups, requested, cancellationToken);
        workingMaps.SetSignatureOrigin(workingMetadata.SignatureBuilder.Publish());
        cancellationToken.ThrowIfCancellationRequested();

        metadata.Adopt(workingMetadata);
        state = workingMaps.state;
    }

    private void ReadCore(
        PeImage image,
        ReadyToRun rtr,
        Metadata metadata,
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

                int signature = metadata.TypeSignature((offset << metadata.HandleBits) | kind);
                string name = metadata.SignatureBuilder.Nodes[signature].Name;

                Types.Add(new TypeMapEntry {
                    MethodTable = fixups[(int)index],
                    Handle = handle,
                    Vertex = table.Vertex,
                    Signature = signature,
                    Name = kind == 0x3D ? "typeref::" + name : name
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

            if ((entry.Flags & ~invokeMask) != 0)
                throw new InvalidDataException($"Unknown InvokeMap flags 0x{entry.Flags:X}.");

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
                int index = metadata.ReadMethod(entry.MetadataOffset);
                ref var method = ref CollectionsMarshal.AsSpan(metadata.Methods)[index];

                if (method.Signature == 0)
                    method.Signature = metadata.MethodSignature(method.SignatureOffset);

                entry.Name = method.Name;
                entry.Signature = method.Signature;
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

            if ((entry.Flags & ~fieldMask) != 0)
                throw new InvalidDataException($"Unknown FieldAccessMap flags 0x{entry.Flags:X}.");

            uint type = reader.Unsigned();

            if (type >= fixups.Length)
                throw new InvalidDataException("FieldAccessMap declaring type refers outside CommonFixups.");

            entry.DeclaringType = fixups[(int)type];

            if (!legacy || (entry.Flags & 8) != 0) {
                entry.MetadataOffset = reader.Unsigned();
                int index = metadata.ReadField(entry.MetadataOffset);
                ref var field = ref CollectionsMarshal.AsSpan(metadata.Fields)[index];

                if (field.Signature == 0) {
                    var signature = metadata.Reader(field.SignatureOffset);
                    field.Signature = metadata.TypeSignature(signature.Unsigned());
                }

                entry.Name = field.Name;
                entry.Signature = field.Signature;
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
