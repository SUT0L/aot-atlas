namespace Atlas;

[Flags]
public enum MetadataFactStatus : ushort {
    Valid = 0,
    Truncated = 1,
    InvalidEncoding = 2,
    InvalidHandle = 4,
    InvalidNumeric = 8,
    InvalidUtf8 = 16,
    InvalidName = 32,
    Incomplete = 64,
    Unresolved = 128,
    ContainerCycle = 256,
    LimitExceeded = 512,
    InvalidHeader = 1024,
    Absent = 2048
}

// Half-open byte range relative to the owning metadata blob.
public readonly record struct MetadataSourceRange(int Offset, int Length) {
    public bool IsAvailable => Offset >= 0;
    public int End => checked(Offset + Length);
    public static MetadataSourceRange Unavailable => new(-1, 0);
}

public readonly record struct MetadataFact<T>(T Value, MetadataFactStatus Status, MetadataSourceRange Source) {
    public bool IsAvailable => (Status & (MetadataFactStatus.Truncated | MetadataFactStatus.InvalidEncoding |
        MetadataFactStatus.InvalidHandle | MetadataFactStatus.InvalidNumeric | MetadataFactStatus.InvalidUtf8 |
        MetadataFactStatus.Unresolved | MetadataFactStatus.LimitExceeded | MetadataFactStatus.InvalidHeader |
        MetadataFactStatus.Absent)) == 0;
}

// Identities are scoped to one owned source.
public readonly record struct MetadataRecordId {
    public uint Value { get; }
    public MetadataRecordKind Kind => (MetadataRecordKind)(Value >> 25);
    public uint Offset => Value & 0x01FFFFFF;
    public bool IsNil => Offset == 0;

    public MetadataRecordId(MetadataRecordKind kind, uint offset) {
        if ((byte)kind > 63 || offset > 0x01FFFFFF) {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }
        Value = (uint)kind << 25 | offset;
    }

    internal MetadataRecordId(uint value) {
        Value = value;
    }
}

public readonly record struct MetadataMethodId(uint Offset) {
    public MetadataRecordId Record => new(MetadataRecordKind.Method, Offset);
}

public readonly record struct MetadataTypeId(uint Offset) {
    public MetadataRecordId Record => new(MetadataRecordKind.TypeDefinition, Offset);
}

public readonly record struct MetadataNameId(uint Offset) {
    public MetadataRecordId Record => new(MetadataRecordKind.ConstantStringValue, Offset);
}

public readonly record struct MetadataEncoding(int HandleBits, bool LegacyConstants = false, bool CombinedTypeOwnership = false) {
    internal MetadataRecordKind CanonicalKind(byte sourceKind) {
        if (LegacyConstants && sourceKind is >= 5 and <= 12) {
            sourceKind = sourceKind == 5 ? (byte)12 : (byte)(sourceKind - 1);
        }
        return (MetadataRecordKind)sourceKind;
    }

    public MetadataRecordId DecodeHandle(uint sourceHandle) {
        Validate();
        byte sourceKind = (byte)(sourceHandle & ((1U << HandleBits) - 1));
        var kind = CanonicalKind(sourceKind);
        uint offset = sourceHandle >> HandleBits;
        if ((byte)kind > 63 || kind == MetadataRecordKind.Root && offset != 0) {
            throw new InvalidDataException($"Metadata handle 0x{sourceHandle:X8} has an invalid record kind.");
        }
        return new(kind, offset);
    }

    public uint EncodeHandle(MetadataRecordId id) {
        Validate();
        uint kind = (byte)id.Kind;
        if (LegacyConstants && kind is >= 5 and <= 12) {
            kind = kind == 12 ? 5 : kind + 1;
        }
        if (id.Offset > uint.MaxValue >> HandleBits) {
            throw new ArgumentOutOfRangeException(nameof(id));
        }
        return id.Offset << HandleBits | kind;
    }

    internal void Validate() {
        if (HandleBits is not (7 or 8)) {
            throw new ArgumentOutOfRangeException(nameof(HandleBits));
        }
    }
}

public readonly record struct MetadataReadLimits(int MaxRecords, int MaxFields, int MaxItems) {
    public static MetadataReadLimits Default => new(2_000_000, 12_000_000, 16_000_000);

    internal void Validate() {
        if (MaxRecords < 0 || MaxFields < 1 || MaxItems < 0) {
            throw new ArgumentOutOfRangeException("limits");
        }
    }
}

public readonly record struct MetadataRecordFacts(
    MetadataRecordId Id,
    MetadataFactStatus Status,
    MetadataSourceRange Source);

public readonly ref struct MetadataNameFacts {
    public MetadataNameId Id { get; }
    public MetadataFact<string> Text { get; }
    public ReadOnlySpan<byte> Bytes { get; }
    public MetadataSourceRange Source { get; }

    internal MetadataNameFacts(MetadataNameId id, MetadataFact<string> text, ReadOnlySpan<byte> bytes, MetadataSourceRange source) {
        Id = id;
        Text = text;
        Bytes = bytes;
        Source = source;
    }
}

public readonly record struct MetadataDeclarationOccurrence(
    MetadataRecordId Owner,
    MetadataFieldName Field,
    int Ordinal,
    MetadataFact<MetadataRecordId> Declaration);

// All arrays and source bytes are owned by this snapshot. Queries inspect frozen
// facts and never parse, cache, publish, or adopt another reader's state.
public sealed partial class MetadataFacts {
    private readonly ReadOnlyMemory<byte> _source;
    private readonly FactRecord[] _records;
    private readonly FactCell[] _fields;
    private readonly FactCell[] _items;
    private readonly Dictionary<uint, int> _index;
    private readonly MetadataRecordId[] _recordIds;
    private readonly string?[] _texts;

    public MetadataEncoding Encoding { get; }
    public MetadataFactStatus Status { get; }
    public ReadOnlySpan<byte> Bytes => _source.Span;
    public ReadOnlySpan<MetadataRecordId> Records => _recordIds;

    private MetadataFacts(ReadOnlyMemory<byte> source, MetadataEncoding encoding,
        FactRecord[] records, FactCell[] fields, FactCell[] items,
        Dictionary<uint, int> index, MetadataFactStatus status,
        Dictionary<int, string> decodedNames, CancellationToken cancellationToken) {
        _source = source;
        Encoding = encoding;
        _records = records;
        _fields = fields;
        _items = items;
        _index = index;
        Status = status;
        _recordIds = new MetadataRecordId[records.Length];
        _texts = new string?[records.Length];

        for (int i = 0; i < records.Length; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            var record = records[i];
            _recordIds[i] = new(record.Handle);
            if (record.Kind != (byte)MetadataRecordKind.ConstantStringValue || record.FieldCount == 0) {
                continue;
            }
            var text = fields[record.FieldStart];
            if ((text.Status & (MetadataFactStatus.Truncated | MetadataFactStatus.InvalidEncoding |
                MetadataFactStatus.InvalidUtf8 | MetadataFactStatus.Unresolved)) == 0) {
                _texts[i] = decodedNames.TryGetValue(i, out string? decoded)
                    ? decoded
                    : System.Text.Encoding.UTF8.GetString(source.Span.Slice(text.DataStart, text.DataLength));
            }
        }
    }

    public static MetadataFacts Read(ReadOnlySpan<byte> source, MetadataEncoding encoding,
        MetadataReadLimits? limits = null, CancellationToken cancellationToken = default,
        ReadOnlySpan<MetadataRecordId> additionalRoots = default) {
        encoding.Validate();
        cancellationToken.ThrowIfCancellationRequested();
        var readLimits = limits ?? MetadataReadLimits.Default;
        readLimits.Validate();
        var builder = new Builder(source.ToArray(), encoding, readLimits, cancellationToken);
        foreach (var root in additionalRoots) {
            builder.AddRoot(root);
        }
        return builder.Build();
    }

    public uint RawHandle(MetadataRecordId id) => Encoding.EncodeHandle(id);

    public bool Contains(MetadataRecordId id) => _index.ContainsKey(id.Value);

    public MetadataRecordFacts Record(MetadataRecordId id) {
        if (!_index.TryGetValue(id.Value, out int index)) {
            return new(id, MetadataFactStatus.Unresolved, MetadataSourceRange.Unavailable);
        }
        var row = _records[index];
        var source = id.Value == 0
            ? (_source.Length >= 4 ? new MetadataSourceRange(4, row.ByteLength) : MetadataSourceRange.Unavailable)
            : (row.Offset <= _source.Length ? new MetadataSourceRange(row.Offset, row.ByteLength) : MetadataSourceRange.Unavailable);
        return new(id, row.Status, source);
    }

    public MetadataFieldValue Field(MetadataRecordId id, MetadataFieldName name) {
        if (!_index.TryGetValue(id.Value, out int index)) {
            return new(this, name, new FactCell { SourceOffset = -1, Status = MetadataFactStatus.Unresolved });
        }
        var record = _records[index];
        var schema = MetadataSchema.Get(Encoding, record.Kind);
        for (int i = 0; i < schema.Fields.Length; i++) {
            if (schema.Fields[i].Name != name) {
                continue;
            }
            if (i < record.FieldCount) {
                return new(this, name, _fields[record.FieldStart + i]);
            }
            return new(this, name, new FactCell { SourceOffset = -1, Status = record.Status | MetadataFactStatus.Unresolved });
        }
        return new(this, name, new FactCell { SourceOffset = -1, Status = MetadataFactStatus.Absent });
    }

    public MetadataNameFacts Name(MetadataNameId id) {
        if (id.Offset == 0) {
            return new(id, new("", MetadataFactStatus.Valid, MetadataSourceRange.Unavailable), [], MetadataSourceRange.Unavailable);
        }
        var field = Field(id.Record, MetadataFieldName.Value);
        string text = _index.TryGetValue(id.Record.Value, out int recordIndex) ? _texts[recordIndex] ?? "" : "";
        return new(id, new(text, field.Status, field.Source), field.Payload, field.PayloadSource);
    }

    public MetadataFact<int> GenericArity(MetadataMethodId method) {
        var signature = Field(method.Record, MetadataFieldName.Signature).Reference;
        if (!signature.IsAvailable || signature.Value.IsNil) {
            return new(0, signature.Status | MetadataFactStatus.Unresolved, signature.Source);
        }
        return Field(signature.Value, MetadataFieldName.GenericParameterCount).Int32;
    }

    public IEnumerable<MetadataDeclarationOccurrence> Declarations(MetadataRecordId owner) {
        if (!_index.TryGetValue(owner.Value, out int index)) {
            yield break;
        }
        var record = _records[index];
        var schema = MetadataSchema.Get(Encoding, record.Kind);
        for (int fieldIndex = 0; fieldIndex < record.FieldCount; fieldIndex++) {
            var spec = schema.Fields[fieldIndex];
            if (!spec.Child || spec.Wire is not (WireKind.Handle or WireKind.TypedHandle)) {
                continue;
            }
            var field = _fields[record.FieldStart + fieldIndex];
            if (!spec.Collection) {
                yield return new(owner, spec.Name, -1, Reference(field));
                continue;
            }
            for (int ordinal = 0; ordinal < field.ItemCount; ordinal++) {
                yield return new(owner, spec.Name, ordinal, Reference(_items[field.ItemStart + ordinal]));
            }
        }
    }

    internal MetadataFact<MetadataRecordId> Reference(in FactCell atom) {
        var status = atom.Status;
        if ((atom.Handle & 0x01FFFFFF) != 0 && !_index.ContainsKey(atom.Handle)) {
            status |= MetadataFactStatus.Unresolved;
        }
        return new(new MetadataRecordId(atom.Handle), status, new(atom.SourceOffset, atom.ByteLength));
    }

    internal MetadataFieldValue Item(int index) => new(this, MetadataFieldName.Value, _items[index]);

    internal MetadataFieldValue FieldAt(int recordIndex, int fieldIndex, MetadataFieldName name) {
        var record = _records[recordIndex];
        if (fieldIndex < record.FieldCount) {
            return new(this, name, _fields[record.FieldStart + fieldIndex]);
        }
        return new(this, name, new FactCell { SourceOffset = -1, Status = record.Status | MetadataFactStatus.Unresolved });
    }

    public MetadataRecordFields Fields(MetadataRecordId id) {
        if (!_index.TryGetValue(id.Value, out int recordIndex)) {
            return default;
        }
        return new(this, recordIndex, MetadataSchema.Get(Encoding, _records[recordIndex].Kind).Fields);
    }
}

// Raw values are available for diagnostics without exposing mutable backing arrays.
// Feature code uses the named record facts below rather than interpreting Bits.
public readonly struct MetadataFieldValue {
    private readonly MetadataFacts _facts;
    private readonly FactCell _atom;

    public MetadataFieldName Name { get; }
    public bool IsAvailable => UInt64.IsAvailable;
    public MetadataFactStatus Status => _atom.Status |
        (_atom.Handle != 0 ? _atom.NameStatus : MetadataFactStatus.Valid);
    public MetadataSourceRange Source => new(_atom.SourceOffset, _atom.ByteLength);
    public MetadataSourceRange PayloadSource => _atom.SourceOffset >= 0 && _atom.DataStart >= 0
        ? new(_atom.DataStart, _atom.DataLength)
        : MetadataSourceRange.Unavailable;
    public ulong Bits => _atom.Value;
    public MetadataFact<uint> UInt32 => new(unchecked((uint)Bits), Status, Source);
    public MetadataFact<int> Int32 => new(unchecked((int)Bits), Status, Source);
    public MetadataFact<ulong> UInt64 => new(Bits, Status, Source);
    public MetadataFact<long> Int64 => new(unchecked((long)Bits), Status, Source);
    public MetadataFact<bool> Boolean => new(Bits != 0, Status, Source);
    public MetadataFact<char> Character => new(unchecked((char)Bits), Status, Source);
    public MetadataFact<float> Single => new(BitConverter.Int32BitsToSingle(unchecked((int)Bits)), Status, Source);
    public MetadataFact<double> Double => new(BitConverter.Int64BitsToDouble(unchecked((long)Bits)), Status, Source);
    public MetadataFact<MetadataRecordId> Reference => _facts.Reference(_atom);
    public MetadataFieldItems Items => new(_facts, _atom.ItemStart, _atom.ItemCount, Status, Source, Bits);
    public ReadOnlySpan<byte> EncodedBytes => Source.IsAvailable ? _facts.Bytes.Slice(Source.Offset, Source.Length) : [];
    public ReadOnlySpan<byte> Payload => _atom.DataStart >= 0
        ? _facts.Bytes.Slice(_atom.DataStart, _atom.DataLength)
        : [];

    internal MetadataFieldValue(MetadataFacts facts, MetadataFieldName name, FactCell atom) {
        _facts = facts;
        Name = name;
        _atom = atom;
    }
}

public readonly struct MetadataFieldItems {
    private readonly MetadataFacts _facts;
    private readonly int _start;

    public int Count { get; }
    public bool IsAvailable => new MetadataFact<int>(Count, Status, Source).IsAvailable;
    public ulong DeclaredCount { get; }
    public MetadataFactStatus Status { get; }
    public MetadataSourceRange Source { get; }

    internal MetadataFieldItems(MetadataFacts facts, int start, int count,
        MetadataFactStatus status, MetadataSourceRange source, ulong declaredCount) {
        _facts = facts;
        _start = start;
        Count = count;
        Status = status;
        Source = source;
        DeclaredCount = declaredCount;
    }

    public MetadataFieldValue this[int index] {
        get {
            if ((uint)index >= (uint)Count) {
                throw new ArgumentOutOfRangeException(nameof(index));
            }
            return _facts.Item(_start + index);
        }
    }

    public Enumerator GetEnumerator() => new(this);

    public struct Enumerator {
        private readonly MetadataFieldItems _items;
        private int _position;
        public MetadataFieldValue Current => _items[_position];

        internal Enumerator(MetadataFieldItems items) {
            _items = items;
            _position = -1;
        }

        public bool MoveNext() => ++_position < _items.Count;
    }
}

public readonly struct MetadataRecordFields {
    private readonly MetadataFacts _facts;
    private readonly int _recordIndex;
    private readonly FieldSpec[] _schema;
    public int Count => _schema?.Length ?? 0;

    internal MetadataRecordFields(MetadataFacts facts, int recordIndex, FieldSpec[] schema) {
        _facts = facts;
        _recordIndex = recordIndex;
        _schema = schema;
    }

    public MetadataFieldValue this[int index] {
        get {
            if ((uint)index >= (uint)Count) {
                throw new ArgumentOutOfRangeException(nameof(index));
            }
            return _facts.FieldAt(_recordIndex, index, _schema[index].Name);
        }
    }

    public Enumerator GetEnumerator() => new(this);

    public struct Enumerator {
        private readonly MetadataRecordFields _fields;
        private int _position;
        public MetadataFieldValue Current => _fields[_position];

        internal Enumerator(MetadataRecordFields fields) {
            _fields = fields;
            _position = -1;
        }

        public bool MoveNext() => ++_position < _fields.Count;
    }
}

