using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct IndexRange(int start, int count) {
    public readonly int Start = start;
    public readonly int Count = count;

    public int End => Start + Count;
}

public struct MetadataScope {
    public uint Offset, Flags, RootNamespace;
    public string Name;
    public ushort Major, Minor, Build, Revision;
}

public struct MetadataType {
    public uint Offset, Scope, Flags, BaseType, Namespace, EnclosingType, Size, Packing;
    public string Name;
    public IndexRange NestedTypes, Methods, Fields, Properties, Events, GenericParameters, Interfaces, Attributes;
}

public struct MetadataMethod {
    public uint Offset, Flags, ImplementationFlags, SignatureOffset;
    public string Name;
    public IndexRange Parameters, GenericParameters, Attributes;
    public int Signature;
    public uint UniqueOwner;
    public bool Shared;
}

public struct MetadataField {
    public uint Offset, Flags, SignatureOffset, DefaultValue, ExplicitOffset;
    public string Name;
    public IndexRange Attributes;
    public int Signature;
}

public readonly struct MetadataForwarder(uint offset, uint sourceScope, string name, string assembly) {
    public readonly uint Offset = offset;
    public readonly uint SourceScope = sourceScope;
    public readonly string Name = name;
    public readonly string Assembly = assembly;
}

public readonly struct MetadataAttribute(uint ownerType, uint ownerMethod, uint offset, uint constructor, int type) {
    public readonly uint OwnerType = ownerType;
    public readonly uint OwnerMethod = ownerMethod;
    public readonly uint Offset = offset;
    public readonly uint Constructor = constructor;
    public readonly int Type = type;
}

public sealed partial class Metadata {
    public readonly ReadOnlyMemory<byte> Data;
    public readonly int HandleBits;
    public readonly bool LegacyConstants;

    public readonly List<MetadataScope> Scopes = new(128);
    public readonly List<MetadataType> Types = new(8192);
    public readonly List<MetadataMethod> Methods = new(32768);
    public readonly List<MetadataField> Fields = new(16384);
    public readonly List<MetadataForwarder> Forwarders = new(1024);
    public readonly List<MetadataAttribute> Attributes = new(16384);
    public readonly List<uint> Handles = new(131072);

    public readonly Dictionary<uint, int> TypeIndex = new(8192);
    public readonly Dictionary<uint, int> MethodIndex = new(32768);
    public readonly Dictionary<uint, int> FieldIndex = new(16384);

    private readonly Dictionary<uint, int> scopeIndex = new(128);
    private readonly Dictionary<uint, string> strings = new(16384);
    private readonly Dictionary<uint, (uint Scope, string Name)> namespaces = new(2048);

    public Metadata(ReadOnlyMemory<byte> data, int handleBits, bool legacyConstants = false) {
        if (handleBits is not (7 or 8))
            throw new ArgumentOutOfRangeException(nameof(handleBits));

        Data = data;
        HandleBits = handleBits;
        LegacyConstants = legacyConstants;
    }

    public NativeReader Reader(uint offset) {
        if (offset == 0 || offset >= Data.Length)
            throw new InvalidDataException($"Metadata record offset 0x{offset:X} is outside the blob.");

        return new NativeReader(Data.Span, (int)offset);
    }

    public string String(uint offset) {
        if (offset == 0)
            return "";
        if (strings.TryGetValue(offset, out string? result))
            return result;

        var reader = Reader(offset);
        result = reader.String();
        strings.Add(offset, result);
        return result;
    }

    private IndexRange Collection(ref NativeReader reader) {
        int count = checked((int)reader.Unsigned());
        if (count > reader.Remaining)
            throw new InvalidDataException("Metadata collection cant fit in the remaining bytes.");

        int start = Handles.Count;
        Handles.EnsureCapacity(checked(start + count));
        for (int i = 0; i < count; ++i)
            Handles.Add(reader.Unsigned());

        return new IndexRange(start, count);
    }

    public void ReadDefinitions() {
        if (Data.IsEmpty)
            return;
        if (Data.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(Data.Span) != 0xDEADDFFD)
            throw new InvalidDataException("Invalid EmbeddedMetadata signature.");
        if (Scopes.Count != 0)
            throw new InvalidOperationException("Metadata definitions were already read.");

        var header = new NativeReader(Data.Span, 4);
        IndexRange scopeHandles = Collection(ref header);
        var work = new List<(byte Kind, uint Offset, uint Scope, uint Parent, string Prefix)>(8192);
        var forwarderWork = new List<(uint Offset, string Prefix, bool Leave)>();
        var activeForwarders = new HashSet<uint>();

        for (int i = scopeHandles.Start; i < scopeHandles.End; ++i) {
            uint offset = Handles[i];
            var reader = Reader(offset);
            MetadataScope scope = new() {
                Offset = offset,
                Flags = reader.Unsigned()
            };
            scope.Name = String(reader.Unsigned());
            reader.Unsigned();
            scope.Major = checked((ushort)reader.Unsigned());
            scope.Minor = checked((ushort)reader.Unsigned());
            scope.Build = checked((ushort)reader.Unsigned());
            scope.Revision = checked((ushort)reader.Unsigned());
            reader.Take(checked((int)reader.Unsigned()));
            reader.Unsigned();
            scope.RootNamespace = reader.Unsigned();

            scopeIndex.Add(offset, Scopes.Count);
            Scopes.Add(scope);
            if (scope.RootNamespace != 0)
                work.Add((0x2F, scope.RootNamespace, offset, offset, ""));
        }

        for (int cursor = 0; cursor < work.Count; ++cursor) {
            var item = work[cursor];
            var reader = Reader(item.Offset);

            if (item.Kind == 0x2F) {
                uint parent = reader.Unsigned();
                int parentKind = (int)(parent & ((1U << HandleBits) - 1));
                if (parent >> HandleBits != item.Parent || parentKind is not (0x2F or 0x38))
                    throw new InvalidDataException("Namespace ownership disagrees with its parent collection.");

                string name = String(reader.Unsigned());
                string full = item.Prefix.Length != 0 && name.Length != 0 ? item.Prefix + "." + name : item.Prefix + name;
                if (!namespaces.TryAdd(item.Offset, (item.Scope, full)))
                    throw new InvalidDataException("Repeated or cyclic namespace definition.");

                IndexRange types = Collection(ref reader), forwarders = Collection(ref reader), children = Collection(ref reader);

                for (int i = types.Start; i < types.End; ++i)
                    work.Add((0x3A, Handles[i], item.Scope, 0, full));
                for (int i = forwarders.Start; i < forwarders.End; ++i)
                    work.Add((0x3B, Handles[i], item.Scope, 0, full));
                for (int i = children.Start; i < children.End; ++i)
                    work.Add((0x2F, Handles[i], item.Scope, item.Offset, full));
            } else if (item.Kind == 0x3A) {
                MetadataType type = new() {
                    Offset = item.Offset,
                    Scope = item.Scope,
                    Flags = reader.Unsigned()
                };
                type.BaseType = reader.Unsigned();
                type.Namespace = reader.Unsigned();
                string name = String(reader.Unsigned());
                type.Size = reader.Unsigned();
                type.Packing = checked((ushort)reader.Unsigned());
                type.EnclosingType = reader.Unsigned();

                if (type.EnclosingType != item.Parent || name.Length == 0)
                    throw new InvalidDataException("Type ownership or name disagrees with its definition.");
                if (type.EnclosingType == 0 && (!namespaces.TryGetValue(type.Namespace, out var owner)
                    || owner.Scope != item.Scope || owner.Name != item.Prefix))
                    throw new InvalidDataException("Type namespace disagrees with its parent collection.");

                type.Name = item.Prefix.Length == 0 ? name : item.Prefix + (item.Parent == 0 ? "." : "+") + name;
                type.NestedTypes = Collection(ref reader);
                type.Methods = Collection(ref reader);
                type.Fields = Collection(ref reader);
                type.Properties = Collection(ref reader);
                type.Events = Collection(ref reader);
                type.GenericParameters = Collection(ref reader);
                type.Interfaces = Collection(ref reader);
                type.Attributes = Collection(ref reader);

                if (!TypeIndex.TryAdd(type.Offset, Types.Count))
                    throw new InvalidDataException("Repeated or cyclic type definition.");

                Types.Add(type);
                for (int i = type.NestedTypes.Start; i < type.NestedTypes.End; ++i)
                    work.Add((0x3A, Handles[i], item.Scope, item.Offset, type.Name));
            } else {
                forwarderWork.Add((item.Offset, item.Prefix.Length == 0 ? "" : item.Prefix + ".", false));
                while (forwarderWork.Count != 0) {
                    var next = forwarderWork[^1];
                    forwarderWork.RemoveAt(forwarderWork.Count - 1);
                    if (next.Leave) {
                        activeForwarders.Remove(next.Offset);
                        continue;
                    }

                    // Forwarder records can be shared
                    // Only a record already on this ancestry path proves a cycle
                    if (!activeForwarders.Add(next.Offset))
                        throw new InvalidDataException("Cyclic metadata forwarders.");

                    var forwarder = Reader(next.Offset);
                    uint targetScope = forwarder.Unsigned();
                    string name = String(forwarder.Unsigned());
                    if (name.Length == 0)
                        throw new InvalidDataException("Type forwarder has no name.");

                    IndexRange nested = Collection(ref forwarder);
                    var scopeReader = Reader(targetScope);
                    scopeReader.Unsigned();
                    string assembly = String(scopeReader.Unsigned());
                    string full = next.Prefix + name;

                    Forwarders.Add(new MetadataForwarder(next.Offset, item.Scope, full, assembly));
                    forwarderWork.Add((next.Offset, "", true));
                    string prefix = nested.Count == 0 ? "" : full + "+";
                    for (int i = nested.End - 1; i >= nested.Start; --i)
                        forwarderWork.Add((Handles[i], prefix, false));
                }
            }
        }

        var names = new Dictionary<string, uint>(Types.Count, StringComparer.Ordinal);
        var collisions = new HashSet<string>(StringComparer.Ordinal);

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(Types)) {
            if (!names.TryAdd(type.Name, type.Scope) && names[type.Name] != type.Scope)
                collisions.Add(type.Name);
        }

        foreach (ref var type in CollectionsMarshal.AsSpan(Types)) {
            if (collisions.Contains(type.Name))
                type.Name = $"[{Scopes[scopeIndex[type.Scope]].Name}@scope_{type.Scope:X}]{type.Name}";

            for (int i = type.Methods.Start; i < type.Methods.End; ++i) {
                int index = ReadMethod(Handles[i]);
                ref var method = ref CollectionsMarshal.AsSpan(Methods)[index];
                if (method.UniqueOwner == 0)
                    method.UniqueOwner = type.Offset;
                else if (method.UniqueOwner != type.Offset)
                    method.Shared = true;
            }

            for (int i = type.Fields.Start; i < type.Fields.End; ++i)
                ReadField(Handles[i]);
        }

        foreach (ref var method in CollectionsMarshal.AsSpan(Methods))
            method.Signature = MethodSignature(method.SignatureOffset);

        foreach (ref var field in CollectionsMarshal.AsSpan(Fields)) {
            var reader = Reader(field.SignatureOffset);
            field.Signature = TypeSignature(reader.Unsigned());
        }

        foreach (ref readonly var type in CollectionsMarshal.AsSpan(Types)) {
            ReadAttributes(type.Attributes, type.Offset, 0);
            for (int i = type.Methods.Start; i < type.Methods.End; ++i) {
                var method = Methods[MethodIndex[Handles[i]]];
                ReadAttributes(method.Attributes, type.Offset, method.Offset);
            }
        }
    }

    public int ReadMethod(uint offset) {
        if (MethodIndex.TryGetValue(offset, out int index))
            return index;

        var reader = Reader(offset);
        MetadataMethod method = new() {
            Offset = offset,
            Flags = reader.Unsigned(),
            ImplementationFlags = reader.Unsigned()
        };
        if (method.Flags > ushort.MaxValue || method.ImplementationFlags > ushort.MaxValue)
            throw new InvalidDataException("Method flags exceed their runtime field width.");

        method.Name = String(reader.Unsigned());
        method.SignatureOffset = reader.Unsigned();
        method.Parameters = Collection(ref reader);
        method.GenericParameters = Collection(ref reader);
        method.Attributes = Collection(ref reader);

        index = Methods.Count;
        MethodIndex.Add(offset, index);
        Methods.Add(method);
        return index;
    }

    public int ReadField(uint offset) {
        if (FieldIndex.TryGetValue(offset, out int index))
            return index;

        var reader = Reader(offset);
        MetadataField field = new() {
            Offset = offset,
            Flags = reader.Unsigned(),
            Name = String(reader.Unsigned())
        };
        if (field.Flags > ushort.MaxValue)
            throw new InvalidDataException("Field flags exceed their runtime field width.");

        field.SignatureOffset = reader.Unsigned();
        field.DefaultValue = reader.Unsigned();
        field.ExplicitOffset = reader.Unsigned();
        field.Attributes = Collection(ref reader);

        index = Fields.Count;
        FieldIndex.Add(offset, index);
        Fields.Add(field);
        return index;
    }

    private void ReadAttributes(IndexRange range, uint ownerType, uint ownerMethod) {
        for (int i = range.Start; i < range.End; ++i) {
            uint offset = Handles[i];
            var reader = Reader(offset);
            uint constructor = reader.Unsigned();
            int kind = (int)(constructor & ((1U << HandleBits) - 1));
            var ctor = Reader(constructor >> HandleBits);
            uint type;

            if (kind == 0x36) {
                ctor.Unsigned();
                type = checked(ctor.Unsigned() * (1U << HandleBits)) | 0x3A;
            } else if (kind == 0x27)
                type = ctor.Unsigned();
            else
                throw new InvalidDataException($"Invalid custom attribute constructor kind 0x{kind:X}.");

            Attributes.Add(new MetadataAttribute(ownerType, ownerMethod, offset, constructor, TypeSignature(type)));
        }
    }
}
