using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct NativeMethodIdentity(string name, int signature, int end) {
    public readonly string Name = name;
    public readonly int Signature = signature, End = end;
}

public struct NativeMethodEntry {
    public uint Offset, Flags, Token;
    public ulong Entrypoint;
    public int DeclaringType, End;
    public MethodIdentity Identity;
    public IndexRange Arguments;
}

public sealed class NativeLayout(ReadOnlyMemory<byte> data, ulong[] references, Signatures signatures) {
    public readonly Dictionary<ulong, int> ExternalTypes = new(4096);

    private readonly Dictionary<int, (int Index, int End)> types = new(16384);
    private readonly Dictionary<int, (int Index, int End)> methods = new(8192);
    private readonly Dictionary<uint, NativeMethodIdentity> identities = new(8192);

    private static readonly string[] Builtins = [
        "??", "System.Void", "System.Boolean", "System.Char", "System.SByte", "System.Byte",
        "System.Int16", "System.UInt16", "System.Int32", "System.UInt32", "System.Int64", "System.UInt64",
        "System.IntPtr", "System.UIntPtr", "System.Single", "System.Double", "System.ValueType", "System.Enum",
        "System.Nullable`1", "System.Object", "System.String", "System.Array", "System.MulticastDelegate",
        "System.RuntimeTypeHandle", "System.RuntimeMethodHandle", "System.RuntimeFieldHandle",
        "System.Exception", "System.TypedReference"
    ];

    public NativeMethodIdentity Method(uint offset) {
        if (identities.TryGetValue(offset, out var cached))
            return cached;

        var reader = new NativeReader(data.Span, checked((int)offset));
        string name = reader.String();
        int origin = reader.Position;
        long target = (long)origin + reader.Signed();
        int end = reader.Position;
        if (name.Length == 0 || target < 0 || target >= data.Length)
            throw new InvalidDataException("NativeLayout method identity has no name or readable signature.");

        reader.Position = (int)target;
        var identity = new NativeMethodIdentity(name, MethodSignature(ref reader, 0), end);
        identities.Add(offset, identity);
        return identity;
    }

    public NativeMethodEntry MethodEntry(uint offset, Metadata metadata, MapFormat format) {
        var reader = new NativeReader(data.Span, checked((int)offset));
        NativeMethodEntry entry = new() { Offset = offset, Flags = reader.Unsigned() };
        if ((entry.Flags & ~15U) != 0)
            throw new InvalidDataException("NativeLayout method entry contains unknown flags.");

        if ((entry.Flags & 4) != 0) {
            uint index = reader.Unsigned();
            if (index >= references.Length || references[index] == 0)
                throw new InvalidDataException("NativeLayout method entry refers outside NativeReferences or to null.");

            entry.Entrypoint = references[index];
        }

        entry.DeclaringType = TypeSignature(ref reader);
        if (entry.DeclaringType == 0)
            throw new InvalidDataException("NativeLayout method entry has no declaring type.");

        if (format == MapFormat.Legacy) {
            uint nativeOffset = (uint)reader.Position;
            var identity = Method(nativeOffset);
            entry.Identity = new MethodIdentity {
                NativeOffset = nativeOffset,
                Name = identity.Name,
                Signature = identity.Signature
            };
            reader.Position = identity.End;
        } else {
            entry.Token = reader.Unsigned();
            entry.Identity = MethodIdentity.Read(entry.Token, metadata, this, format);
        }

        if ((entry.Flags & 1) != 0) {
            int count = checked((int)reader.Unsigned());
            if (count == 0 || count != signatures.Methods[entry.Identity.Signature].GenericParameterCount)
                throw new InvalidDataException("NativeLayout method entry has a mismatched instantiation arity.");

            entry.Arguments = Arguments(ref reader, count, 0);
        }

        entry.End = reader.Position;
        return entry;
    }

    public int TypeSignature(ref NativeReader reader, int depth = 0) {
        int start = reader.Position;
        if (types.TryGetValue(start, out var cached)) {
            if (cached.Index < 0)
                throw new InvalidDataException("Cyclic NativeLayout type signature.");

            reader.Position = cached.End;
            return cached.Index;
        }

        if (depth > 256)
            throw new InvalidDataException("NativeLayout type signature exceeds the supported nesting depth.");

        types.Add(start, (-1, 0));
        uint value = reader.Unsigned();
        uint argument = value >> 4;
        SignatureNode node = default;
        int index = -1;

        switch (value & 15) {
            case 0:
                if (argument != 0)
                    throw new InvalidDataException("Invalid NativeLayout null signature.");

                index = 0;
                break;
            case 1:
                uint encoded = argument << 4;
                int size = encoded < 0x80 ? 1 : encoded < 0x4000 ? 2 : encoded < 0x200000 ? 3 : encoded < 0x10000000 ? 4 : 5;
                long target = (long)reader.Position - argument - size - 2;
                if (target < 0 || target >= start)
                    throw new InvalidDataException("NativeLayout lookback does not point to an earlier signature.");

                var lookback = new NativeReader(data.Span, (int)target);
                index = TypeSignature(ref lookback, depth + 1);
                break;
            case 2:
                node.Kind = argument switch {
                    1 => SignatureKind.SzArray,
                    2 => SignatureKind.ByReference,
                    3 => SignatureKind.Pointer,
                    _ => throw new InvalidDataException("Unknown NativeLayout type modifier.")
                };
                node.Element = TypeSignature(ref reader, depth + 1);
                break;
            case 3:
                node.Kind = SignatureKind.Instantiation;
                node.Element = TypeSignature(ref reader, depth + 1);
                node.Arguments = Arguments(ref reader, checked((int)argument), depth);
                break;
            case 4:
                node.Kind = (argument & 1) != 0 ? SignatureKind.MethodVariable : SignatureKind.TypeVariable;
                node.Value = (int)(argument >> 1);
                break;
            case 5:
                if (argument == 0 || argument >= Builtins.Length)
                    throw new InvalidDataException("Unknown NativeLayout built-in type.");

                node.Kind = SignatureKind.Named;
                node.Name = Builtins[argument];
                break;
            case 6:
                if (argument >= references.Length || references[argument] == 0)
                    throw new InvalidDataException("NativeLayout type refers outside NativeReferences or to null.");

                ulong address = references[argument];
                if (ExternalTypes.TryGetValue(address, out int existing)) {
                    index = existing;
                } else {
                    node.Kind = SignatureKind.RuntimeType;
                    node.TypeAddress = address;
                }
                break;
            case 10:
                if (argument is < 1 or > 32)
                    throw new InvalidDataException("NativeLayout array rank exceeds 1..32.");

                node.Kind = SignatureKind.Array;
                node.Value = (int)argument;
                node.Element = TypeSignature(ref reader, depth + 1);

                for (int which = 0; which < 2; ++which) {
                    uint count = reader.Unsigned();
                    if (count > argument || count > reader.Remaining)
                        throw new InvalidDataException("NativeLayout array dimensions exceed its rank or storage.");

                    var range = new IndexRange(signatures.Edges.Count, (int)count);
                    for (int i = 0; i < count; ++i)
                        signatures.Edges.Add(unchecked((int)reader.Unsigned()));

                    if (which == 0)
                        node.Sizes = range;
                    else
                        node.LowerBounds = range;
                }

                break;
            case 11:
                if (argument != 0)
                    throw new InvalidDataException("Invalid NativeLayout function-pointer signature tag.");

                var method = signatures.Methods[MethodSignature(ref reader, depth + 1)];
                if ((method.CallingConvention & 1) != 0)
                    throw new InvalidDataException("NativeLayout function-pointer signature declares generic parameters.");

                node.Kind = SignatureKind.FunctionPointer;
                node.NativeConvention = true;
                node.Value = (int)method.CallingConvention;
                node.Element = method.ReturnType;
                node.Arguments = method.Parameters;
                break;
            default:
                throw new InvalidDataException($"Unknown NativeLayout type signature kind 0x{value & 15:X}.");
        }

        if (index < 0) {
            index = signatures.Nodes.Count;
            signatures.Nodes.Add(node);
            if (node.Kind == SignatureKind.RuntimeType)
                ExternalTypes.Add(node.TypeAddress, index);
        }

        types[start] = (index, reader.Position);
        return index;
    }

    private int MethodSignature(ref NativeReader reader, int depth) {
        int start = reader.Position;
        if (methods.TryGetValue(start, out var cached)) {
            if (cached.Index == 0)
                throw new InvalidDataException("Cyclic NativeLayout method signature.");

            reader.Position = cached.End;
            return cached.Index;
        }

        methods.Add(start, default);
        MethodSignature method = new() {
            Offset = (uint)start,
            CallingConvention = reader.Unsigned(),
            NativeConvention = true
        };
        if ((method.CallingConvention & ~7U) != 0)
            throw new InvalidDataException("Unknown NativeLayout calling convention.");

        if ((method.CallingConvention & 1) != 0) {
            method.GenericParameterCount = checked((int)reader.Unsigned());
            if (method.GenericParameterCount == 0)
                throw new InvalidDataException("NativeLayout generic method signature has no generic parameters.");
        }

        int count = checked((int)reader.Unsigned());
        method.ReturnType = TypeSignature(ref reader, depth + 1);
        method.Parameters = Arguments(ref reader, count, depth);

        int index = signatures.Methods.Count;
        signatures.Methods.Add(method);
        methods[start] = (index, reader.Position);
        return index;
    }

    private IndexRange Arguments(ref NativeReader reader, int count, int depth) {
        if (count > reader.Remaining)
            throw new InvalidDataException("NativeLayout signature arguments exceed storage.");

        var range = new IndexRange(signatures.Edges.Count, count);
        CollectionsMarshal.SetCount(signatures.Edges, checked(signatures.Edges.Count + count));
        for (int i = range.Start; i < range.End; ++i)
            signatures.Edges[i] = TypeSignature(ref reader, depth + 1);

        return range;
    }

    public void BindTypes(MethodTables tables, RuntimeNames names) {
        foreach (var entry in ExternalTypes) {
            ref var node = ref CollectionsMarshal.AsSpan(signatures.Nodes)[entry.Value];
            node.Kind = SignatureKind.Named;
            node.Name = names.Values[tables.Index[entry.Key]];
        }
    }
}
