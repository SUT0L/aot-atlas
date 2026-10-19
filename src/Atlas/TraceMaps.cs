using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public struct TraceMethod {
    public int Offset;
    internal int DeclaringType;
    internal int Signature;

    public uint TypeToken;
    public uint NameOffset;
    public uint SignatureOffset;
    public uint ParameterNamesOffset;

    public ulong Entrypoint;
    public string Name;
    public IndexRange ParameterNames;
    public IndexRange TypeParameterNames;
    public bool Hidden;
    public MetadataFactStatus DeclaringTypeStatus;
    public MetadataFactStatus NameStatus;
    public MetadataFactStatus SignatureStatus;
    public MetadataFactStatus ParameterNamesStatus;
    public MetadataFactStatus TypeParameterNamesStatus;

    public readonly MetadataFactStatus MetadataStatus => DeclaringTypeStatus | NameStatus | SignatureStatus
        | ParameterNamesStatus | TypeParameterNamesStatus;
}

public readonly struct TracePoint(int nativeOffset, int line, int document) {
    public readonly int NativeOffset = nativeOffset;
    public readonly int Line = line;
    public readonly int Document = document;
}

public readonly struct TraceLines(int vertex, ulong entrypoint, IndexRange points) {
    public readonly int Vertex = vertex;
    public readonly ulong Entrypoint = entrypoint;
    public readonly IndexRange Points = points;
}

public sealed class TraceMaps {
    private readonly SignatureHistory signatureOrigin;
    private readonly CancellationToken cancellationToken;
    private Signatures? signatures;
    public Signatures Signatures => signatures
        ?? throw new InvalidOperationException("Trace signatures have not been published.");

    internal readonly List<TraceMethod> Methods = new();
    internal readonly List<string> ParameterNames = new();
    private readonly List<MetadataFactStatus> parameterNameStatuses = new();
    internal readonly List<string> Documents = new();
    internal readonly List<TraceLines> Lines = new();
    internal readonly List<TracePoint> Points = new();

    public ReadOnlySpan<TraceMethod> MethodEntries => CollectionsMarshal.AsSpan(Methods);
    public ReadOnlySpan<string> GenericParameterNames => CollectionsMarshal.AsSpan(ParameterNames);
    public ReadOnlySpan<MetadataFactStatus> GenericParameterNameStatuses => CollectionsMarshal.AsSpan(parameterNameStatuses);
    public ReadOnlySpan<string> DocumentNames => CollectionsMarshal.AsSpan(Documents);
    public ReadOnlySpan<TraceLines> LineEntries => CollectionsMarshal.AsSpan(Lines);
    public ReadOnlySpan<TracePoint> PointEntries => CollectionsMarshal.AsSpan(Points);
    public SignatureType DeclaringTypeAt(int position) => Signatures.Types[Methods[position].DeclaringType];
    public SignatureMethod MethodSignatureAt(int position) => Signatures.MethodSignatures[Methods[position].Signature];

    internal TraceMaps(
        PeImage image,
        ReadyToRun rtr,
        MetadataBuilder metadata,
        ReadOnlySpan<ulong> fixups,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        this.cancellationToken = cancellationToken;

        rtr = rtr.ValidateSource(image);
        signatureOrigin = metadata.SignatureBuilder.Origin;

        var section = rtr.Find(RtrSectionId.StackTraceMethodMapping);
        if (section.Length != 0) {
            ReadMethods(
                image.FileSpan(section.Start, checked((int)section.Length)),
                section.Start,
                image,
                metadata);
        }

        section = rtr.Find(RtrSectionId.StackTraceDocuments);
        if (section.Length != 0) {
            ReadDocuments(image.FileSpan(section.Start, checked((int)section.Length)));
        }

        section = rtr.Find(RtrSectionId.StackTraceLineMapping);
        if (section.Length != 0) {
            ReadLines(image.FileSpan(section.Start, checked((int)section.Length)), image, fixups);
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    internal void Publish(Signatures publication, CancellationToken cancellationToken = default) {
        if (signatures is not null) {
            throw new InvalidOperationException("Trace signatures have already been published.");
        }
        ValidateSignatures(publication, cancellationToken);
        signatures = publication;
    }

    internal void ValidateSignatures(Signatures signatures, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(signatureOrigin, signatures.Origin))
            throw new ArgumentException("Trace signatures must belong to the same graph namespace.", nameof(signatures));

        foreach (ref readonly var method in CollectionsMarshal.AsSpan(Methods)) {
            cancellationToken.ThrowIfCancellationRequested();

            if ((uint)method.DeclaringType >= signatures.Nodes.Length
                || (uint)method.Signature >= signatures.Methods.Length)
                throw new ArgumentException("Published signature graph does not contain the trace identities.", nameof(signatures));
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private void ReadMethods(ReadOnlySpan<byte> data, ulong address, PeImage image, MetadataBuilder metadata) {
        var reader = new NativeReader(data);
        int count = BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4));
        if (count < 0 || count > reader.Remaining / 5) {
            throw new InvalidDataException("Stack-trace entry count exceeds its storage.");
        }
        Methods.EnsureCapacity(count);

        TraceMethod current = new() {
            Name = "",
            DeclaringTypeStatus = MetadataFactStatus.Absent,
            NameStatus = MetadataFactStatus.Absent,
            SignatureStatus = MetadataFactStatus.Absent
        };
        var parameterIndex = new Dictionary<uint, (IndexRange Names, MetadataFactStatus Status)>();
        int offsetBits = 32 - metadata.HandleBits;
        uint offsetMask = (1U << offsetBits) - 1;

        for (int i = 0; i < count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            current.Offset = reader.Position;
            byte command = reader.Take(1)[0];
            if ((command & ~31) != 0 || (command & 12) == 12) {
                throw new InvalidDataException("Invalid stack-trace command flags.");
            }

            if ((command & 1) != 0) {
                current.TypeToken = BinaryPrimitives.ReadUInt32LittleEndian(reader.Take(4));
                uint kind = current.TypeToken >> offsetBits;
                if (current.TypeToken != 0 && kind is not (0x3A or 0x3D or 0x3E)) {
                    throw new InvalidDataException("Stack-trace owner is not a metadata type handle.");
                }
                uint handle = ((current.TypeToken & offsetMask) << metadata.HandleBits) | kind;
                current.DeclaringType = ReadDeclaringType(metadata, handle, out current.DeclaringTypeStatus);
                current.TypeParameterNames = default;
                current.TypeParameterNamesStatus = MetadataFactStatus.Valid;

                if (kind == 0x3A) {
                    current.TypeParameterNames = ReadTypeParameterNames(
                        metadata, current.TypeToken & offsetMask, out current.TypeParameterNamesStatus);
                }
            }

            if ((command & 2) != 0) {
                current.NameOffset = reader.Unsigned();
                var name = ReadName(metadata, current.NameOffset, "trace name");
                current.Name = name.Value;
                current.NameStatus = name.Status;
            }

            if ((command & 12) != 0) {
                current.SignatureOffset = reader.Unsigned();
                current.Signature = ReadMethodSignature(metadata, current.SignatureOffset, out current.SignatureStatus);
                current.ParameterNames = default;
                current.ParameterNamesOffset = 0;
                current.ParameterNamesStatus = MetadataFactStatus.Valid;
            }

            if ((command & 8) != 0) {
                current.ParameterNamesOffset = reader.Unsigned();
                if (!parameterIndex.TryGetValue(current.ParameterNamesOffset, out var names)) {
                    names.Names = ReadParameterNames(metadata, current.ParameterNamesOffset, out names.Status);
                    parameterIndex.Add(current.ParameterNamesOffset, names);
                }
                current.ParameterNames = names.Names;
                current.ParameterNamesStatus = names.Status;

                if (names.Names.Count == 0 || (current.Signature != 0
                    && names.Names.Count != metadata.SignatureBuilder.Methods[current.Signature].GenericParameterCount)) {
                    current.ParameterNamesStatus |= MetadataFactStatus.Incomplete;
                    metadata.RecordFailure(
                        RawHandle(metadata, current.SignatureOffset, MetadataRecordKind.MethodSignature),
                        "trace generic parameter names",
                        new InvalidDataException("Stack-trace generic parameter names do not match the signature arity."));
                }
            }

            ulong cell = checked(address + (uint)reader.Position);
            int delta = BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4));
            current.Entrypoint = checked((ulong)((long)cell + delta));
            if (!image.IsExecutable(current.Entrypoint)) {
                throw new InvalidDataException("Stack-trace entrypoint is outside executable storage.");
            }
            current.Hidden = (command & 16) != 0;
            if (!current.Hidden) {
                if (current.DeclaringType == 0 && current.DeclaringTypeStatus == MetadataFactStatus.Absent) {
                    current.DeclaringTypeStatus |= MetadataFactStatus.Unresolved;
                    metadata.RecordFailure(0, "trace declaring type", new InvalidDataException(
                        $"Visible stack-trace entry at 0x{current.Offset:X} has no declaring type."));
                }
                if (current.Name.Length == 0 && current.NameStatus is MetadataFactStatus.Valid or MetadataFactStatus.Absent) {
                    current.NameStatus |= MetadataFactStatus.InvalidName;
                    metadata.RecordFailure(RawHandle(metadata, current.NameOffset, MetadataRecordKind.ConstantStringValue),
                        "trace name", new InvalidDataException($"Visible stack-trace entry at 0x{current.Offset:X} has no name."));
                }
                if (current.Signature == 0 && current.SignatureStatus == MetadataFactStatus.Absent) {
                    current.SignatureStatus |= MetadataFactStatus.Unresolved;
                    metadata.RecordFailure(0, "trace method signature", new InvalidDataException(
                        $"Visible stack-trace entry at 0x{current.Offset:X} has no signature."));
                }
            }
            Methods.Add(current);
        }
        if (reader.Remaining != 0) {
            throw new InvalidDataException("Stack-trace data extends beyond its declared entry count.");
        }
    }

    private static uint RawHandle(MetadataBuilder metadata, uint offset, MetadataRecordKind kind) =>
        offset <= uint.MaxValue >> metadata.HandleBits ? (offset << metadata.HandleBits) | (uint)kind : 0;

    private static void ValidateOffset(MetadataBuilder metadata, uint offset) {
        if (offset > uint.MaxValue >> metadata.HandleBits) {
            throw new InvalidDataException($"Stack-trace metadata offset 0x{offset:X} exceeds the handle width.");
        }
    }

    private static int ReadDeclaringType(MetadataBuilder metadata, uint handle, out MetadataFactStatus status) {
        status = handle >> metadata.HandleBits == 0 ? MetadataFactStatus.Absent : MetadataFactStatus.Valid;
        try {
            if (status != MetadataFactStatus.Absent) {
                metadata.AddRoot(metadata.Encoding.DecodeHandle(handle));
            }
            return metadata.TypeSignature(handle);
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            metadata.RecordFailure(handle, "trace declaring type", error);
            status = MetadataFactStatus.Unresolved;
            return 0;
        }
    }

    private static int ReadMethodSignature(MetadataBuilder metadata, uint offset, out MetadataFactStatus status) {
        status = offset == 0 ? MetadataFactStatus.Absent : MetadataFactStatus.Valid;
        try {
            ValidateOffset(metadata, offset);
            if (offset != 0) {
                metadata.AddRoot(new(MetadataRecordKind.MethodSignature, offset));
            }
            if (offset == 0) {
                return 0;
            }
            if (!metadata.TryMethodSignature(offset, out int signature)) {
                status = MetadataFactStatus.Unresolved;
            }
            return signature;
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            metadata.RecordFailure(RawHandle(metadata, offset, MetadataRecordKind.MethodSignature), "trace method signature", error);
            status = MetadataFactStatus.Unresolved;
            return 0;
        }
    }

    private static MetadataFact<string> ReadName(MetadataBuilder metadata, uint offset, string projection) {
        if (offset == 0) {
            return new("", MetadataFactStatus.Absent, MetadataSourceRange.Unavailable);
        }
        try {
            ValidateOffset(metadata, offset);
            var name = metadata.RecordName(new(offset));
            if (!name.IsAvailable) {
                metadata.RecordFailure(RawHandle(metadata, offset, MetadataRecordKind.ConstantStringValue), projection,
                    new InvalidDataException($"Stack-trace metadata name at 0x{offset:X} is unavailable ({name.Status})."));
                return name with { Value = "" };
            }
            return name with { Value = metadata.String(offset) };
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            metadata.RecordFailure(RawHandle(metadata, offset, MetadataRecordKind.ConstantStringValue), projection, error);
            return new("", MetadataFactStatus.Unresolved, MetadataSourceRange.Unavailable);
        }
    }

    private void AddParameterName(MetadataBuilder metadata, uint offset, string projection, ref MetadataFactStatus status) {
        var name = ReadName(metadata, offset, projection);
        if (name.Value.Length == 0 && name.Status is MetadataFactStatus.Valid or MetadataFactStatus.Absent) {
            name = name with { Status = name.Status | MetadataFactStatus.InvalidName };
            metadata.RecordFailure(RawHandle(metadata, offset, MetadataRecordKind.ConstantStringValue), projection,
                new InvalidDataException("Stack-trace generic parameter has no name."));
        }
        ParameterNames.Add(name.Value);
        parameterNameStatuses.Add(name.Status);
        status |= name.Status;
    }

    private IndexRange ReadTypeParameterNames(MetadataBuilder metadata, uint typeOffset, out MetadataFactStatus status) {
        var owner = new MetadataRecordId(MetadataRecordKind.TypeDefinition, typeOffset);
        var parameters = metadata.RecordField(owner, MetadataFieldName.GenericParameters).Items;
        int start = ParameterNames.Count;
        status = parameters.Status;
        if (status != MetadataFactStatus.Valid) {
            status |= MetadataFactStatus.Incomplete;
            metadata.RecordFailure(metadata.Encoding.EncodeHandle(owner), "trace type parameters",
                new InvalidDataException($"Stack-trace type parameter collection is partial ({parameters.Status})."));
        }

        // Declaration recovery filters missing references. Substitutions must retain the raw slots.
        for (int i = 0; i < parameters.Count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            var reference = parameters[i].Reference;
            var parameterStatus = reference.Status;
            uint nameOffset = 0;
            if (!reference.IsAvailable || reference.Value.IsNil) {
                parameterStatus |= MetadataFactStatus.InvalidHandle;
                metadata.RecordFailure(metadata.Encoding.EncodeHandle(owner), $"trace type parameter {i}",
                    new InvalidDataException($"Stack-trace type parameter {i} is unavailable ({parameterStatus})."));
            } else {
                var parameter = reference.Value;
                uint handle = metadata.Encoding.EncodeHandle(parameter);
                var number = metadata.RecordField(parameter, MetadataFieldName.Number).UInt32;
                var kind = metadata.RecordField(parameter, MetadataFieldName.Kind).UInt32;
                if (!number.IsAvailable || number.Value != i || !kind.IsAvailable || kind.Value != 0) {
                    parameterStatus |= number.Status | kind.Status | MetadataFactStatus.InvalidNumeric;
                    metadata.RecordFailure(handle, "trace type parameter number",
                        new InvalidDataException($"Stack-trace type parameter {i} has an unavailable or inconsistent ordinal or kind."));
                } else {
                    var name = metadata.RecordField(parameter, MetadataFieldName.Name).Reference;
                    parameterStatus |= name.Status;
                    if (!name.IsAvailable) {
                        metadata.RecordFailure(handle, "trace type parameter name",
                            new InvalidDataException($"Stack-trace type parameter name is unavailable ({name.Status})."));
                    } else {
                        nameOffset = name.Value.Offset;
                    }
                }
            }
            if (parameterStatus == MetadataFactStatus.Valid) {
                AddParameterName(metadata, nameOffset, "trace type parameter name", ref status);
            } else {
                parameterStatus |= MetadataFactStatus.Incomplete;
                ParameterNames.Add("");
                parameterNameStatuses.Add(parameterStatus);
                status |= parameterStatus;
            }
        }
        return new(start, ParameterNames.Count - start);
    }

    private IndexRange ReadParameterNames(MetadataBuilder metadata, uint offset, out MetadataFactStatus status) {
        int start = ParameterNames.Count;
        status = MetadataFactStatus.Valid;
        try {
            var parameters = metadata.Reader(offset);
            int length = checked((int)parameters.Unsigned());
            if (length > parameters.Remaining) {
                throw new InvalidDataException("Stack-trace generic parameter names exceed their storage.");
            }
            ParameterNames.EnsureCapacity(checked(start + length));
            parameterNameStatuses.EnsureCapacity(checked(start + length));
            uint kindMask = (1U << metadata.HandleBits) - 1;
            for (int i = 0; i < length; ++i) {
                cancellationToken.ThrowIfCancellationRequested();
                uint handle = parameters.Unsigned();
                uint kind = handle & kindMask;
                if (kind != (uint)MetadataRecordKind.ConstantStringValue) {
                    if (kind is >= 1 and <= 63) {
                        metadata.AddRoot(metadata.Encoding.DecodeHandle(handle));
                    }
                    throw new InvalidDataException("Stack-trace generic parameter name is not a string handle.");
                }
                AddParameterName(metadata, handle >> metadata.HandleBits, "trace generic parameter name", ref status);
            }
        } catch (Exception error) when (error is InvalidDataException or OverflowException or NotSupportedException) {
            metadata.RecordFailure(0, $"trace generic parameter names at 0x{offset:X}", error);
            status |= MetadataFactStatus.Incomplete | MetadataFactStatus.Unresolved;
        }
        return new(start, ParameterNames.Count - start);
    }

    private void ReadDocuments(ReadOnlySpan<byte> data) {
        if (data.Length < 4)
            throw new InvalidDataException("Truncated stack-trace document table.");

        uint first = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (first == 0 || first % 4 != 0 || first > data.Length)
            throw new InvalidDataException("Invalid stack-trace document table extent.");

        int count = (int)(first / 4);
        Documents.EnsureCapacity(count);

        var utf8 = new UTF8Encoding(false, true);

        for (int i = 0; i < count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(data[(i * 4)..]);
            if (offset < first || offset >= data.Length)
                throw new InvalidDataException("Stack-trace document offset exceeds string storage.");

            var bytes = data[(int)offset..];
            int end = bytes.IndexOf((byte)0);
            if (end < 0)
                throw new InvalidDataException("Unterminated stack-trace document name.");

            Documents.Add(utf8.GetString(bytes[..end]));
        }
    }

    private void ReadLines(ReadOnlySpan<byte> data, PeImage image, ReadOnlySpan<ulong> fixups) {
        var table = new NativeTable(data);

        while (table.MoveNext()) {
            cancellationToken.ThrowIfCancellationRequested();

            var reader = new NativeReader(data, table.Vertex);
            uint index = reader.Unsigned();
            if (index >= fixups.Length || !image.IsExecutable(fixups[(int)index]))
                throw new InvalidDataException("Stack-trace line map has no executable CommonFixups entrypoint.");

            ulong entrypoint = fixups[(int)index];
            int count = checked((int)reader.Unsigned());
            if (count == 0 || count > reader.Remaining / 2)
                throw new InvalidDataException("Stack-trace sequence points exceed their storage.");

            var range = new IndexRange(Points.Count, count);
            Points.EnsureCapacity(checked(Points.Count + count));

            int document = 0;
            int offset = 0;
            int line = 0;

            for (int i = 0; i < count; ++i) {
                int delta = reader.Signed();
                if (i == 0) {
                    document = delta;
                    delta = reader.Signed();
                } else if (delta == 0) {
                    document = reader.Signed();
                    delta = reader.Signed();
                }

                offset = checked(offset + delta);
                line = checked(line + reader.Signed());
                if ((uint)document >= Documents.Count || offset < 0 || line < 0)
                    throw new InvalidDataException("Invalid stack-trace sequence point.");

                Points.Add(new TracePoint(offset, line, document));
            }

            Lines.Add(new TraceLines(table.Vertex, entrypoint, range));
        }
    }
}
