using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct NativeMethodIdentity {
    public readonly string Name;
    internal readonly int Signature;
    public readonly int End;

    internal NativeMethodIdentity(string name, int signature, int end) {
        Name = name;
        Signature = signature;
        End = end;
    }
}

public struct NativeMethodEntry {
    public uint Offset;
    public uint Flags;
    public uint Token;

    public ulong Entrypoint;
    internal int DeclaringType;
    public int End;

    public MethodIdentity Identity;
    public IndexRange Arguments;
}

public sealed class NativeLayout {
    private readonly ReadOnlyMemory<byte> data;
    private readonly ulong[] references;
    private readonly SignatureBuilder signatures;
    internal readonly Dictionary<ulong, int> ExternalTypes = new(4096);

    public NativeLayout(ReadOnlyMemory<byte> data, ulong[] references, SignatureBuilder signatures)
        : this(data, references, signatures, takeOwnership: false) {
    }

    internal NativeLayout(ReadOnlyMemory<byte> data, ulong[] references, SignatureBuilder signatures, bool takeOwnership) {
        this.data = takeOwnership ? data : data.ToArray();
        this.references = takeOwnership ? references : (ulong[])references.Clone();
        this.signatures = signatures;
    }

    private readonly Dictionary<int, (int Index, int End)> types = new(16384);
    private readonly Dictionary<int, (int Index, int End)> methods = new(8192);
    private readonly Dictionary<uint, NativeMethodIdentity> identities = new(8192);

    private readonly HashSet<int> activeTypes = new();
    private readonly HashSet<int> activeMethods = new();
    private readonly List<(int Offset, bool Method)> addedSignatures = new();

    private SignatureBuilder.Checkpoint BeginSignatures() {
        Debug.Assert(addedSignatures.Count == 0 && activeTypes.Count == 0 && activeMethods.Count == 0);

        return signatures.BeginRead();
    }

    private void RollbackSignatures(SignatureBuilder.Checkpoint checkpoint) {
        foreach (var added in addedSignatures) {
            if (added.Method)
                methods.Remove(added.Offset);
            else
                types.Remove(added.Offset);
        }

        for (int i = checkpoint.Nodes; i < signatures.Nodes.Length; ++i) {
            var node = signatures.Nodes[i];

            if (node.Kind == SignatureKind.RuntimeType)
                ExternalTypes.Remove(node.TypeAddress);
        }

        signatures.RollbackRead(checkpoint);
        addedSignatures.Clear();

        Debug.Assert(activeTypes.Count == 0 && activeMethods.Count == 0);
    }

    private static readonly string[] Builtins = [
        "??",
        "System.Void",
        "System.Boolean",
        "System.Char",
        "System.SByte",
        "System.Byte",
        "System.Int16",
        "System.UInt16",
        "System.Int32",
        "System.UInt32",
        "System.Int64",
        "System.UInt64",
        "System.IntPtr",
        "System.UIntPtr",
        "System.Single",
        "System.Double",
        "System.ValueType",
        "System.Enum",
        "System.Nullable`1",
        "System.Object",
        "System.String",
        "System.Array",
        "System.MulticastDelegate",
        "System.RuntimeTypeHandle",
        "System.RuntimeMethodHandle",
        "System.RuntimeFieldHandle",
        "System.Exception",
        "System.TypedReference"
    ];

    internal NativeMethodIdentity Method(uint offset) {
        if (identities.TryGetValue(offset, out var cached))
            return cached;

        var checkpoint = BeginSignatures();

        try {
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
            addedSignatures.Clear();
            signatures.CompleteRead(checkpoint);

            return identity;
        } catch {
            RollbackSignatures(checkpoint);
            throw;
        }
    }

    internal NativeMethodEntry MethodEntry(uint offset, Metadata metadata, MapFormat format) {
        ReflectionMaps.RequireGrammar(format);

        if (format == MapFormat.Metadata && !ReferenceEquals(metadata.SignatureBuilder, signatures))
            throw new ArgumentException(
                "Metadata method entries must share the NativeLayout signature builder.",
                nameof(metadata));

        var checkpoint = signatures.MarkAppend();
        using Metadata.SignatureOperation? metadataOperation = format == MapFormat.Metadata
            ? new(metadata)
            : null;

        try {
            return ReadMethodEntry(offset, metadata, format);
        } catch {
            metadataOperation?.Rollback();
            RollbackEntry(checkpoint);
            throw;
        }
    }

    private void RollbackEntry(SignatureBuilder.Checkpoint checkpoint) {
        int[] newTypes = types.Where(entry => entry.Value.Index >= checkpoint.Nodes)
            .Select(entry => entry.Key).ToArray();
        int[] newMethods = methods.Where(entry => entry.Value.Index >= checkpoint.Methods)
            .Select(entry => entry.Key).ToArray();
        uint[] newIdentities = identities.Where(entry => entry.Value.Signature >= checkpoint.Methods)
            .Select(entry => entry.Key).ToArray();
        ulong[] newExternalTypes = ExternalTypes.Where(entry => entry.Value >= checkpoint.Nodes)
            .Select(entry => entry.Key).ToArray();

        foreach (int key in newTypes)
            types.Remove(key);

        foreach (int key in newMethods)
            methods.Remove(key);

        foreach (uint key in newIdentities)
            identities.Remove(key);

        foreach (ulong key in newExternalTypes)
            ExternalTypes.Remove(key);

        signatures.RollbackAppend(checkpoint);
    }

    private NativeMethodEntry ReadMethodEntry(uint offset, Metadata metadata, MapFormat format) {

        var reader = new NativeReader(data.Span, checked((int)offset));

        NativeMethodEntry entry = new() {
            Offset = offset,
            Flags = reader.Unsigned()
        };

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

            // This root protects the argument suffix. The enclosing operation
            // also owns the declaring type and independently parsed identity.
            var checkpoint = BeginSignatures();

            try {
                entry.Arguments = Arguments(ref reader, count, 0);
                addedSignatures.Clear();
                signatures.CompleteRead(checkpoint);
            } catch {
                RollbackSignatures(checkpoint);
                throw;
            }
        }

        entry.End = reader.Position;

        return entry;
    }

    // A root native read publishes its graph and caches together. Recursive reads
    // cannot call Metadata, whose independently completed signatures share this graph.
    public SignatureType ReadTypeSignature(int offset) {
        var reader = new NativeReader(data.Span, offset);
        int index = TypeSignature(ref reader);
        return signatures.Publish().Types[index];
    }

    internal int TypeSignature(ref NativeReader reader, int depth = 0) {
        if (!reader.HasSource(data.Span))
            throw new ArgumentException("Reader must cover the NativeLayout source blob.", nameof(reader));

        int start = reader.Position;

        if (types.TryGetValue(start, out var cached)) {
            reader.Position = cached.End;
            return cached.Index;
        }

        var checkpoint = BeginSignatures();

        try {
            int index = ReadTypeSignature(ref reader, depth);
            addedSignatures.Clear();
            signatures.CompleteRead(checkpoint);

            return index;
        } catch {
            reader.Position = start;
            RollbackSignatures(checkpoint);
            throw;
        }
    }

    private int ReadTypeSignature(ref NativeReader reader, int depth) {
        int start = reader.Position;

        if (types.TryGetValue(start, out var cached)) {
            reader.Position = cached.End;
            return cached.Index;
        }

        if (depth > 256)
            throw new InvalidDataException("NativeLayout type signature exceeds the supported nesting depth.");

        if (!activeTypes.Add(start))
            throw new InvalidDataException("Cyclic NativeLayout type signature.");

        try {
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
                    int size = encoded < 0x80 ? 1
                        : encoded < 0x4000 ? 2
                        : encoded < 0x200000 ? 3
                        : encoded < 0x10000000 ? 4
                        : 5;

                    long target = (long)reader.Position - argument - size - 2;

                    if (target < 0 || target >= start)
                        throw new InvalidDataException("NativeLayout lookback does not point to an earlier signature.");

                    var lookback = new NativeReader(data.Span, (int)target);
                    index = ReadTypeSignature(ref lookback, depth + 1);
                    break;

                case 2:
                    node.Kind = argument switch {
                        1 => SignatureKind.SzArray,
                        2 => SignatureKind.ByReference,
                        3 => SignatureKind.Pointer,
                        _ => throw new InvalidDataException("Unknown NativeLayout type modifier.")
                    };

                    node.Element = ReadTypeSignature(ref reader, depth + 1);
                    break;

                case 3:
                    node.Kind = SignatureKind.Instantiation;
                    node.Element = ReadTypeSignature(ref reader, depth + 1);
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
                    node.Element = ReadTypeSignature(ref reader, depth + 1);

                    for (int which = 0; which < 2; ++which) {
                        uint count = reader.Unsigned();

                        if (count > argument || count > reader.Remaining)
                            throw new InvalidDataException("NativeLayout array dimensions exceed its rank or storage.");

                        var range = new IndexRange(signatures.Edges.Length, (int)count);

                        for (int i = 0; i < count; ++i)
                            signatures.AddEdge(unchecked((int)reader.Unsigned()));

                        if (which == 0)
                            node.Sizes = range;
                        else
                            node.LowerBounds = range;
                    }

                    break;

                case 11:
                    if (argument != 0)
                        throw new InvalidDataException("Invalid NativeLayout function-pointer signature tag.");

                    int methodIndex = MethodSignature(ref reader, depth + 1);
                    var method = signatures.Methods[methodIndex];

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
                index = signatures.Nodes.Length;
                signatures.AddNode(node);

                if (node.Kind == SignatureKind.RuntimeType)
                    ExternalTypes.Add(node.TypeAddress, index);
            }

            addedSignatures.Add((start, false));
            types.Add(start, (index, reader.Position));

            return index;
        } finally {
            activeTypes.Remove(start);
        }
    }

    internal int MethodSignature(uint offset) {
        var reader = new NativeReader(data.Span, checked((int)offset));
        if (methods.TryGetValue(reader.Position, out var cached))
            return cached.Index;

        var checkpoint = BeginSignatures();

        try {
            int index = MethodSignature(ref reader, 0);
            addedSignatures.Clear();
            signatures.CompleteRead(checkpoint);
            return index;
        } catch {
            RollbackSignatures(checkpoint);
            throw;
        }
    }

    private int MethodSignature(ref NativeReader reader, int depth) {
        int start = reader.Position;

        if (methods.TryGetValue(start, out var cached)) {
            reader.Position = cached.End;
            return cached.Index;
        }

        if (!activeMethods.Add(start))
            throw new InvalidDataException("Cyclic NativeLayout method signature.");

        try {
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
            method.ReturnType = ReadTypeSignature(ref reader, depth + 1);
            method.Parameters = Arguments(ref reader, count, depth);

            int index = signatures.Methods.Length;
            signatures.AddMethod(method);
            addedSignatures.Add((start, true));
            methods.Add(start, (index, reader.Position));

            return index;
        } finally {
            activeMethods.Remove(start);
        }
    }

    private IndexRange Arguments(ref NativeReader reader, int count, int depth) {
        if (count > reader.Remaining)
            throw new InvalidDataException("NativeLayout signature arguments exceed storage.");

        var range = new IndexRange(signatures.Edges.Length, count);
        signatures.ReserveEdges(count);

        for (int i = range.Start; i < range.End; ++i)
            signatures.SetEdge(i, ReadTypeSignature(ref reader, depth + 1));

        return range;
    }

    internal void BindTypes(MethodTables tables, RuntimeNames names) {
        foreach (var entry in ExternalTypes) {
            var node = signatures.Nodes[entry.Value];
            node.Kind = SignatureKind.Named;
            node.Name = names.Values[tables.Index[entry.Key]];
            signatures.SetNode(entry.Value, node);
        }
    }
}
