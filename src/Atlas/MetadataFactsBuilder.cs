using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Atlas;

public sealed partial class MetadataFacts {
    internal sealed class Builder {
        private readonly ReadOnlyMemory<byte> _source;
        private readonly MetadataEncoding _encoding;
        private readonly MetadataReadLimits _limits;
        private readonly CancellationToken _cancellationToken;

        private readonly List<FactRecord> _records = [];
        private readonly List<FactCell> _fields = [];
        private readonly List<FactCell> _items = [];
        private readonly Dictionary<uint, int> _index = [];
        private readonly Dictionary<int, string> _decodedNames = [];

        private MetadataFactStatus _status;
        private int _readRecordCount;
        private bool _started;
        private bool _built;

        public Builder(ReadOnlyMemory<byte> source, MetadataEncoding encoding, MetadataReadLimits limits, CancellationToken cancellationToken) {
            encoding.Validate();
            limits.Validate();
            _source = source;
            _encoding = encoding;
            _limits = limits;
            _cancellationToken = cancellationToken;
            Start();
        }

        public void AddRoot(MetadataRecordId id) {
            if (_built) {
                throw new InvalidOperationException("Metadata facts have already been published.");
            }
            _cancellationToken.ThrowIfCancellationRequested();
            if (id.Offset == 0 || _index.ContainsKey(id.Value)) {
                return;
            }
            if ((byte)id.Kind > 63 || id.Kind == MetadataRecordKind.Root) {
                throw new ArgumentOutOfRangeException(nameof(id));
            }
            if (_records.Count - 1 >= _limits.MaxRecords) {
                _status |= MetadataFactStatus.LimitExceeded;
                return;
            }
            _index.Add(id.Value, _records.Count);
            _records.Add(new FactRecord { Handle = id.Value });
        }

        private void Start() {
            if (_started) {
                return;
            }
            _started = true;
            _records.Add(new FactRecord { Handle = 0, FieldStart = 0, FieldCount = 1 });
            _fields.Add(new FactCell { SourceOffset = -1, Status = MetadataFactStatus.Unresolved });
            _index.Add(0, 0);
            if (_source.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(_source.Span) != 0xDEADDFFD) {
                _status = _source.Length == 0 ? MetadataFactStatus.Absent : MetadataFactStatus.InvalidHeader;
                var root = _records[0];
                root.Status = _status;
                _records[0] = root;
                _fields[0] = new FactCell { Status = _status | MetadataFactStatus.Unresolved, SourceOffset = -1 };
                _readRecordCount = 1;
                return;
            }
            ReadRecord(0, 4);
            _readRecordCount = 1;
        }

        public void ReadRoots() {
            Start();
            while (_readRecordCount < _records.Count) {
                _cancellationToken.ThrowIfCancellationRequested();
                int recordIndex = _readRecordCount++;
                ReadRecord(recordIndex, _records[recordIndex].Offset);
            }
        }

        public MetadataFacts Build() {
            if (_built) {
                throw new InvalidOperationException("Metadata facts have already been published.");
            }
            _cancellationToken.ThrowIfCancellationRequested();
            ReadRoots();
            ValidateNames();
            ValidateContainerCycles(false);
            ValidateContainerCycles(true);
            _cancellationToken.ThrowIfCancellationRequested();
            _built = true;
            return Finish();
        }

        internal IEnumerable<MetadataRecordId> ReadRecordIds() {
            for (int i = 0; i < _records.Count; i++) {
                _cancellationToken.ThrowIfCancellationRequested();
                yield return new MetadataRecordId(_records[i].Handle);
            }
        }

        internal MetadataDecodedField Field(MetadataRecordId id, MetadataFieldName name) {
            if (!_index.TryGetValue(id.Value, out int index)) {
                return new(this, new FactCell { SourceOffset = -1, Status = MetadataFactStatus.Unresolved });
            }
            var record = _records[index];
            var schema = MetadataSchema.Get(_encoding, record.Kind);
            for (int i = 0; i < schema.Fields.Length; i++) {
                if (schema.Fields[i].Name != name) {
                    continue;
                }
                if (i < record.FieldCount) {
                    return new(this, _fields[record.FieldStart + i]);
                }
                return new(this, new FactCell { SourceOffset = -1, Status = record.Status | MetadataFactStatus.Unresolved });
            }
            return new(this, new FactCell { SourceOffset = -1, Status = MetadataFactStatus.Absent });
        }

        internal MetadataFact<MetadataRecordId> TypeOwner(MetadataRecordId id) {
            if (id.Kind != MetadataRecordKind.TypeDefinition) {
                throw new ArgumentException("Expected a type definition.", nameof(id));
            }
            return Owner(id);
        }

        internal MetadataFact<MetadataRecordId> ReferenceOwner(MetadataRecordId id) {
            if (id.Kind != MetadataRecordKind.TypeReference) {
                throw new ArgumentException("Expected a type reference.", nameof(id));
            }
            return Owner(id);
        }

        private MetadataFact<MetadataRecordId> Owner(MetadataRecordId id) {
            var fields = MetadataSchema.OwnerFields(_encoding, id.Kind);
            var owner = Field(id, fields.Primary).Reference;
            if (owner.IsAvailable && owner.Value.IsNil && fields.Fallback is MetadataFieldName fallback) {
                return Field(id, fallback).Reference;
            }
            return owner;
        }

        internal MetadataFact<string> Name(MetadataNameId id) {
            if (id.Offset == 0) {
                return new("", MetadataFactStatus.Valid, MetadataSourceRange.Unavailable);
            }
            var value = Field(id.Record, MetadataFieldName.Value);
            if (!_index.TryGetValue(id.Record.Value, out int recordIndex)) {
                return new("", value.Status, value.Source);
            }
            if (!value.IsAvailable) {
                return new("", value.Status, value.Source);
            }
            if (!_decodedNames.TryGetValue(recordIndex, out string? text)) {
                text = System.Text.Encoding.UTF8.GetString(value.Payload);
                _decodedNames.Add(recordIndex, text);
            }
            return new(text, value.Status, value.Source);
        }

        internal MetadataDecodedField Item(int index) => new(this, _items[index]);

        internal ReadOnlySpan<byte> SourceBytes => _source.Span;

        internal MetadataFact<MetadataRecordId> Reference(in FactCell atom) {
            var status = atom.Status;
            if ((atom.Handle & 0x01FFFFFF) != 0 && !_index.ContainsKey(atom.Handle)) {
                status |= MetadataFactStatus.Unresolved;
            }
            return new(new MetadataRecordId(atom.Handle), status, new(atom.SourceOffset, atom.ByteLength));
        }

        private MetadataFacts Finish() {
            return new MetadataFacts(_source, _encoding, _records.ToArray(), _fields.ToArray(), _items.ToArray(), _index, _status, _decodedNames, _cancellationToken);
        }

        private void ReadRecord(int recordIndex, int position) {
            var row = _records[recordIndex];
            var spec = MetadataSchema.Get(_encoding, row.Kind);
            if (recordIndex != 0) {
                row.FieldStart = _fields.Count;
                if (spec.Fields.Length > _limits.MaxFields - _fields.Count) {
                    row.Status = MetadataFactStatus.LimitExceeded | MetadataFactStatus.Unresolved;
                    _records[recordIndex] = row;
                    _status |= row.Status;
                    return;
                }
                row.FieldCount = (ushort)spec.Fields.Length;
                for (int i = 0; i < spec.Fields.Length; i++) {
                    _fields.Add(new FactCell { SourceOffset = -1, Status = MetadataFactStatus.Unresolved });
                }
            }
            if (position > _source.Length || position == _source.Length && row.Kind != 20) {
                row.Status = MetadataFactStatus.InvalidHandle | MetadataFactStatus.Unresolved;
                _records[recordIndex] = row;
                _status |= row.Status;
                return;
            }
            int start = position;
            for (int fieldIndex = 0; fieldIndex < spec.Fields.Length; fieldIndex++) {
                var fieldSpec = spec.Fields[fieldIndex];
                var field = new FactAtom { SourceOffset = position };
                bool complete = fieldSpec.Collection
                    ? ReadCollection(fieldSpec, ref position, ref field)
                    : ReadScalar(fieldSpec, ref position, ref field);
                field.ByteLength = position - field.SourceOffset;
                _fields[row.FieldStart + fieldIndex] = FactCell.Pack(field, fieldSpec.Wire, fieldSpec.Collection);
                row.Status |= field.Status;
                if (!complete) {
                    row.Status |= MetadataFactStatus.Incomplete;
                    break;
                }
            }
            row.ByteLength = position - start;
            _records[recordIndex] = row;
            _status |= row.Status;
        }

        private bool ReadCollection(FieldSpec spec, ref int position, ref FactAtom field) {
            if (!ReadInteger(ref position, false, false, out ulong count, out MetadataFactStatus fault)) {
                field.Status |= fault;
                return false;
            }
            field.Value = count;
            field.ItemStart = _items.Count;
            ulong availableItems = (ulong)(_limits.MaxItems - _items.Count);
            ulong boundedCount = Math.Min(count, availableItems);
            if (count > availableItems) {
                field.Status |= MetadataFactStatus.LimitExceeded;
            }
            for (ulong i = 0; i < boundedCount; i++) {
                var item = new FactAtom { SourceOffset = position };
                bool complete = ReadScalar(spec, ref position, ref item);
                item.ByteLength = position - item.SourceOffset;
                field.Status |= item.Status;
                _items.Add(FactCell.Pack(item, spec.Wire, collection: false));
                field.ItemCount++;
                if (!complete) {
                    return false;
                }
            }
            if (count > boundedCount) {
                return false;
            }
            return true;
        }

        private bool ReadScalar(FieldSpec spec, ref int position, ref FactAtom atom) {
            _cancellationToken.ThrowIfCancellationRequested();
            var bytes = _source.Span;
            int fixedSize = FixedSize(spec.Wire);
            if (fixedSize != 0) {
                if (position > bytes.Length - fixedSize) {
                    atom.Status |= MetadataFactStatus.Truncated;
                    position = bytes.Length;
                    return false;
                }
                var encoded = bytes.Slice(position, fixedSize);
                atom.Value = fixedSize switch {
                    1 => spec.Wire == WireKind.SByte ? unchecked((ulong)(sbyte)encoded[0]) : encoded[0],
                    4 => BinaryPrimitives.ReadUInt32LittleEndian(encoded),
                    8 => BinaryPrimitives.ReadUInt64LittleEndian(encoded),
                    _ => throw new InvalidOperationException()
                };
                position += fixedSize;
                if (spec.Wire == WireKind.Boolean && atom.Value > 1) {
                    atom.Status |= MetadataFactStatus.InvalidNumeric;
                }
                return true;
            }
            if (spec.Wire == WireKind.String) {
                atom.DataStart = -1;
            }
            bool signed = spec.Wire is WireKind.Int16 or WireKind.Int32 or WireKind.Int64;
            bool wide = spec.Wire is WireKind.Int64 or WireKind.UInt64;
            if (!ReadInteger(ref position, signed, wide, out atom.Value, out MetadataFactStatus fault)) {
                atom.Status |= fault;
                return false;
            }
            if (spec.Wire == WireKind.String) {
                atom.DataStart = position;
                if (atom.Value > (ulong)(bytes.Length - position)) {
                    atom.DataLength = bytes.Length - position;
                    position = bytes.Length;
                    atom.Status |= MetadataFactStatus.Truncated;
                    return false;
                }
                atom.DataLength = (int)atom.Value;
                position += atom.DataLength;
                ValidateString(bytes.Slice(atom.DataStart, atom.DataLength), ref atom);
                return true;
            }
            if (spec.Wire is WireKind.TypedHandle or WireKind.Handle) {
                DecodeReference(spec, ref atom);
                return true;
            }
            if (spec.Wire is WireKind.Char or WireKind.UInt16 && atom.Value > ushort.MaxValue ||
                spec.Wire == WireKind.Int16 && unchecked((long)atom.Value) is < short.MinValue or > short.MaxValue ||
                spec.Wire == WireKind.Enum && atom.Value > EnumMaximum(spec.ValueType) ||
                spec.Name == MetadataFieldName.GenericParameterCount && unchecked((long)atom.Value) < 0) {
                atom.Status |= MetadataFactStatus.InvalidNumeric;
            }
            return true;
        }

        private void DecodeReference(FieldSpec spec, ref FactAtom atom) {
            uint raw = (uint)atom.Value;
            byte kind = spec.Wire == WireKind.TypedHandle
                ? spec.TargetKind
                : (byte)_encoding.CanonicalKind((byte)(raw & ((1U << _encoding.HandleBits) - 1)));
            uint offset = spec.Wire == WireKind.TypedHandle ? raw : raw >> _encoding.HandleBits;
            if (offset > 0x01FFFFFF || kind > 63 || kind == 0 && offset != 0 ||
                offset != 0 && spec.AllowedKinds != 0 && (spec.AllowedKinds & 1UL << kind) == 0) {
                atom.Status |= MetadataFactStatus.InvalidHandle;
                return;
            }
            atom.Handle = (uint)kind << 25 | offset;
            if (offset == 0) {
                return;
            }
            if (offset > _source.Length || offset == _source.Length && kind != 20) {
                atom.Status |= MetadataFactStatus.InvalidHandle | MetadataFactStatus.Unresolved;
                return;
            }
            if (!_index.ContainsKey(atom.Handle)) {
                if (_records.Count - 1 >= _limits.MaxRecords) {
                    atom.Status |= MetadataFactStatus.LimitExceeded | MetadataFactStatus.Unresolved;
                    return;
                }
                _index.Add(atom.Handle, _records.Count);
                _records.Add(new FactRecord { Handle = atom.Handle });
            }
        }

        private bool ReadInteger(ref int position, bool signed, bool wide, out ulong value, out MetadataFactStatus fault) {
            value = 0;
            fault = MetadataFactStatus.Valid;
            var bytes = _source.Span;
            if (position >= bytes.Length) {
                fault = MetadataFactStatus.Truncated;
                return false;
            }
            byte first = bytes[position];
            int length = (first & 1) == 0 ? 1 : (first & 2) == 0 ? 2 : (first & 4) == 0 ? 3 :
                (first & 8) == 0 ? 4 : (first & 16) == 0 ? 5 : wide && (first & 32) == 0 ? 9 : 0;
            if (length == 0) {
                position++;
                fault = MetadataFactStatus.InvalidEncoding;
                return false;
            }
            if (position > bytes.Length - length) {
                position = bytes.Length;
                fault = MetadataFactStatus.Truncated;
                return false;
            }
            if (length == 9) {
                value = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(position + 1, 8));
            } else if (length == 5) {
                uint raw = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(position + 1, 4));
                value = signed ? unchecked((ulong)(int)raw) : raw;
            } else {
                uint raw = (uint)(first >> length);
                for (int i = 1; i < length; i++) {
                    raw |= (uint)bytes[position + i] << (8 - length + (i - 1) * 8);
                }
                if (signed) {
                    int bits = length * 7;
                    value = unchecked((ulong)((int)(raw << (32 - bits)) >> (32 - bits)));
                } else {
                    value = raw;
                }
            }
            position += length;
            return true;
        }

        private static int FixedSize(WireKind kind) {
            return kind switch {
                WireKind.Boolean or WireKind.Byte or WireKind.SByte => 1,
                WireKind.Single => 4,
                WireKind.Double => 8,
                _ => 0
            };
        }

        private static ulong EnumMaximum(string type) {
            return type switch {
                "SignatureCallingConvention" or "GenericParameterKind" or "NamedArgumentMemberKind" => byte.MaxValue,
                "AssemblyFlags" or "AssemblyHashAlgorithm" or "TypeAttributes" => uint.MaxValue,
                _ => ushort.MaxValue
            };
        }

        private void ValidateString(ReadOnlySpan<byte> bytes, ref FactAtom atom) {
            int sinceCancellationCheck = 0;
            while (!bytes.IsEmpty) {
                if (Rune.DecodeFromUtf8(bytes, out var rune, out int consumed) != OperationStatus.Done) {
                    atom.Status |= MetadataFactStatus.InvalidUtf8;
                    atom.NameStatus |= MetadataFactStatus.InvalidUtf8;
                    return;
                }
                if (Rune.IsControl(rune)) {
                    atom.NameStatus |= MetadataFactStatus.InvalidName;
                }
                bytes = bytes[consumed..];
                sinceCancellationCheck += consumed;
                if (sinceCancellationCheck >= 4096) {
                    _cancellationToken.ThrowIfCancellationRequested();
                    sinceCancellationCheck = 0;
                }
            }
        }

        private void ValidateNames() {
            for (int i = 0; i < _records.Count; i++) {
                _cancellationToken.ThrowIfCancellationRequested();
                var row = _records[i];
                var spec = MetadataSchema.Get(_encoding, row.Kind);
                if ((row.Status & MetadataFactStatus.Unresolved) != 0) {
                    continue;
                }
                for (int j = 0; j < spec.Fields.Length; j++) {
                    if (!spec.Fields[j].NameValue) {
                        continue;
                    }
                    int fieldIndex = row.FieldStart + j;
                    var field = _fields[fieldIndex];
                    if ((field.Status & (MetadataFactStatus.Unresolved | MetadataFactStatus.InvalidHandle)) != 0 ||
                        !_index.TryGetValue(field.Handle, out int stringIndex)) {
                        continue;
                    }
                    var stringRow = _records[stringIndex];
                    if ((stringRow.Status & MetadataFactStatus.Unresolved) != 0) {
                        continue;
                    }
                    var text = _fields[stringRow.FieldStart];
                    field.NameStatus |= text.Status | text.NameStatus;
                    _fields[fieldIndex] = field;
                    row.Status |= field.Status | field.NameStatus;
                }
                _records[i] = row;
                _status |= row.Status;
            }
        }

        private void ValidateContainerCycles(bool downward) {
            // Iterative Tarjan traversal classifies complete strongly connected
            // components. A finished DFS branch may still belong to an active
            // component reached again from another branch.
            var discovery = new int[_records.Count];
            var lowlink = new int[_records.Count];
            var state = new byte[_records.Count];
            var componentStack = new List<int>();
            var frames = new List<(int Row, int Edge)>();
            int nextDiscovery = 0;
            const byte OnComponentStack = 1;
            const byte HasSelfEdge = 2;

            for (int start = 1; start < _records.Count; start++) {
                if (discovery[start] != 0 || !IsContainer(_records[start].Kind)) {
                    continue;
                }
                Enter(start);
                while (frames.Count != 0) {
                    _cancellationToken.ThrowIfCancellationRequested();
                    var frame = frames[^1];
                    uint target = ContainerEdge(frame.Row, frame.Edge, downward);
                    if (target != uint.MaxValue) {
                        frames[^1] = (frame.Row, frame.Edge + 1);
                        if ((target & 0x01FFFFFF) == 0 || !_index.TryGetValue(target, out int next) ||
                            !IsContainer(_records[next].Kind)) {
                            continue;
                        }
                        if (next == frame.Row) {
                            state[next] |= HasSelfEdge;
                        }
                        if (discovery[next] == 0) {
                            Enter(next);
                        } else if ((state[next] & OnComponentStack) != 0) {
                            lowlink[frame.Row] = Math.Min(lowlink[frame.Row], discovery[next]);
                        }
                        continue;
                    }

                    frames.RemoveAt(frames.Count - 1);
                    if (lowlink[frame.Row] == discovery[frame.Row]) {
                        int componentStart = componentStack.Count - 1;
                        while (componentStack[componentStart] != frame.Row) {
                            componentStart--;
                        }
                        int componentSize = componentStack.Count - componentStart;
                        bool cyclic = componentSize > 1 || (state[frame.Row] & HasSelfEdge) != 0;
                        for (int i = componentStart; i < componentStack.Count; i++) {
                            int member = componentStack[i];
                            state[member] &= unchecked((byte)~OnComponentStack);
                            if (cyclic) {
                                var row = _records[member];
                                row.Status |= MetadataFactStatus.ContainerCycle;
                                _records[member] = row;
                            }
                        }
                        componentStack.RemoveRange(componentStart, componentSize);
                        if (cyclic) {
                            _status |= MetadataFactStatus.ContainerCycle;
                        }
                    }
                    if (frames.Count != 0) {
                        int parent = frames[^1].Row;
                        lowlink[parent] = Math.Min(lowlink[parent], lowlink[frame.Row]);
                    }
                }
            }

            void Enter(int row) {
                discovery[row] = ++nextDiscovery;
                lowlink[row] = discovery[row];
                state[row] = OnComponentStack;
                componentStack.Add(row);
                frames.Add((row, 0));
            }
        }

        private static bool IsContainer(byte kind) => kind is 47 or 48 or 58 or 59 or 61;

        private uint ContainerEdge(int rowIndex, int ordinal, bool downward) {
            var row = _records[rowIndex];
            if ((row.Status & MetadataFactStatus.Unresolved) != 0) {
                return uint.MaxValue;
            }
            if (downward) {
                var spec = MetadataSchema.Get(_encoding, row.Kind);
                for (int i = 0; i < row.FieldCount; i++) {
                    if (spec.Fields[i].Name is not (MetadataFieldName.NamespaceDefinitions or MetadataFieldName.TypeDefinitions or MetadataFieldName.TypeForwarders or MetadataFieldName.NestedTypes)) {
                        continue;
                    }
                    var collection = _fields[row.FieldStart + i];
                    if (ordinal < collection.ItemCount) {
                        var item = _items[collection.ItemStart + ordinal];
                        return (item.Status & (MetadataFactStatus.InvalidHandle | MetadataFactStatus.Unresolved)) == 0 ? item.Handle : 0;
                    }
                    ordinal -= collection.ItemCount;
                }
                return uint.MaxValue;
            }
            // Parent pointers detect container cycles without treating a normal
            // parent-to-child collection and its backlink as a cycle.
            int fieldIndex = row.Kind switch {
                47 or 48 or 61 => ordinal == 0 ? 0 : -1,
                58 when _encoding.CombinedTypeOwnership => ordinal == 0 ? 2 : -1,
                58 => ordinal == 0 ? 6 : ordinal == 1 ? 2 : -1,
                _ => -1
            };
            if (fieldIndex < 0) {
                return uint.MaxValue;
            }
            var field = _fields[row.FieldStart + fieldIndex];
            if ((field.Status & (MetadataFactStatus.InvalidHandle | MetadataFactStatus.Unresolved)) != 0) {
                return 0;
            }
            return field.Handle;
        }
    }
}

internal struct FactRecord {
    internal uint Handle;
    internal int FieldStart;
    internal ushort FieldCount;
    internal int ByteLength;
    internal MetadataFactStatus Status;

    internal readonly byte Kind => (byte)(Handle >> 25);
    internal readonly int Offset => (int)(Handle & 0x01FFFFFF);
}

// An owned cell retains only the payload used by its shape. Wide numeric bits
// share storage with the two collection counts; references, strings and
// collections share the auxiliary slot. Expanded atoms exist only during decoding.
internal struct FactCell {
    private ulong value;
    private int auxiliary;
    internal int SourceOffset;
    internal int ByteLength;
    private ushort statusAndShape;
    internal MetadataFactStatus NameStatus;

    private const ushort ShapeMask = 0xC000;
    private const ushort ReferenceShape = 0x4000;
    private const ushort StringShape = 0x8000;
    private const ushort CollectionShape = 0xC000;
    private readonly ushort Shape => (ushort)(statusAndShape & ShapeMask);

    internal MetadataFactStatus Status {
        readonly get => (MetadataFactStatus)(statusAndShape & ~ShapeMask);
        set => statusAndShape = (ushort)((ushort)value | Shape);
    }
    internal readonly ulong Value => Shape == CollectionShape ? (uint)value : value;
    internal readonly uint Handle => Shape == ReferenceShape ? unchecked((uint)auxiliary) : 0;
    internal readonly int DataStart => Shape == StringShape ? auxiliary : 0;
    internal readonly int DataLength => Shape == StringShape && auxiliary >= 0
        ? ByteLength - (auxiliary - SourceOffset) : 0;
    internal readonly int ItemStart => Shape == CollectionShape ? auxiliary : 0;
    internal readonly int ItemCount => Shape == CollectionShape ? (int)(value >> 32) : 0;

    internal static FactCell Pack(in FactAtom atom, WireKind wire, bool collection) {
        System.Diagnostics.Debug.Assert(((ushort)atom.Status & ShapeMask) == 0);
        ushort shape;
        int auxiliary;
        ulong payload = atom.Value;
        if (wire == WireKind.String && !collection) {
            shape = StringShape;
            auxiliary = atom.DataStart;
        } else if (collection) {
            shape = CollectionShape;
            auxiliary = atom.ItemStart;
            // NativeFormat collection counts are encoded as UInt32.
            System.Diagnostics.Debug.Assert(atom.Value <= uint.MaxValue);
            payload = (uint)atom.Value | (ulong)(uint)atom.ItemCount << 32;
        } else if (wire is WireKind.TypedHandle or WireKind.Handle) {
            shape = ReferenceShape;
            auxiliary = unchecked((int)atom.Handle);
        } else {
            shape = 0;
            auxiliary = 0;
        }
        return new FactCell {
            value = payload,
            auxiliary = auxiliary,
            SourceOffset = atom.SourceOffset,
            ByteLength = atom.ByteLength,
            statusAndShape = (ushort)((ushort)atom.Status | shape),
            NameStatus = atom.NameStatus
        };
    }
}

// SourceOffset/ByteLength include the complete encoded value; DataStart/DataLength
// identify a string's raw UTF-8 payload, including invalid or truncated bytes.
internal struct FactAtom {
    internal ulong Value;
    internal uint Handle;
    internal int SourceOffset;
    internal int ByteLength;
    internal int DataStart;
    internal int DataLength;
    internal int ItemStart;
    internal int ItemCount;
    internal MetadataFactStatus Status;
    // Strings retain name-quality checks here; name references retain their
    // target's quality without making a known pointer unavailable.
    internal MetadataFactStatus NameStatus;
}

// This reader exists only while an explicit construction owner is adding roots.
// Published metadata never retains it or consults its mutable lists.
internal readonly struct MetadataDecodedField {
    private readonly MetadataFacts.Builder _builder;
    private readonly FactCell _atom;

    internal MetadataFactStatus Status => _atom.Status |
        (_atom.Handle != 0 ? _atom.NameStatus : MetadataFactStatus.Valid);
    internal MetadataFactStatus NameStatus => _atom.NameStatus;
    internal bool IsAvailable => UInt64.IsAvailable;
    internal MetadataSourceRange Source => new(_atom.SourceOffset, _atom.ByteLength);
    internal ulong Bits => _atom.Value;
    internal MetadataFact<uint> UInt32 => new(unchecked((uint)Bits), Status, Source);
    internal MetadataFact<int> Int32 => new(unchecked((int)Bits), Status, Source);
    internal MetadataFact<ulong> UInt64 => new(Bits, Status, Source);
    internal MetadataFact<long> Int64 => new(unchecked((long)Bits), Status, Source);
    internal MetadataFact<bool> Boolean => new(Bits != 0, Status, Source);
    internal MetadataFact<char> Character => new(unchecked((char)Bits), Status, Source);
    internal MetadataFact<float> Single => new(BitConverter.Int32BitsToSingle(unchecked((int)Bits)), Status, Source);
    internal MetadataFact<double> Double => new(BitConverter.Int64BitsToDouble(unchecked((long)Bits)), Status, Source);
    internal MetadataFact<MetadataRecordId> Reference => _builder.Reference(_atom);
    internal MetadataDecodedItems Items => new(_builder, _atom.ItemStart, _atom.ItemCount, Status, Source, Bits);
    internal ReadOnlySpan<byte> Payload => _atom.DataStart >= 0
        ? _builder.SourceBytes.Slice(_atom.DataStart, _atom.DataLength)
        : [];

    internal MetadataDecodedField(MetadataFacts.Builder builder, FactCell atom) {
        _builder = builder;
        _atom = atom;
    }
}

internal readonly struct MetadataDecodedItems {
    private readonly MetadataFacts.Builder _builder;
    private readonly int _start;

    internal int Count { get; }
    internal ulong DeclaredCount { get; }
    internal MetadataFactStatus Status { get; }
    internal MetadataSourceRange Source { get; }

    internal MetadataDecodedItems(MetadataFacts.Builder builder, int start, int count,
        MetadataFactStatus status, MetadataSourceRange source, ulong declaredCount) {
        _builder = builder;
        _start = start;
        Count = count;
        Status = status;
        Source = source;
        DeclaredCount = declaredCount;
    }

    public Enumerator GetEnumerator() => new(this);

    public struct Enumerator {
        private readonly MetadataDecodedItems _items;
        private int _position;
        internal Enumerator(MetadataDecodedItems items) {
            _items = items;
            _position = -1;
        }
        public MetadataDecodedField Current => _items[_position];
        public bool MoveNext() => ++_position < _items.Count;
    }

    internal MetadataDecodedField this[int index] {
        get {
            if ((uint)index >= (uint)Count) {
                throw new ArgumentOutOfRangeException(nameof(index));
            }
            return _builder.Item(_start + index);
        }
    }
}
