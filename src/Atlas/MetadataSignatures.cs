using System.Runtime.InteropServices;

namespace Atlas;

public sealed partial class Metadata {
    internal SignatureBuilder SignatureBuilder => state.Signatures;
    public Signatures PublishedSignatures => SignatureBuilder.Publish();

    private Dictionary<uint, int> signatureIndex => state.SignatureIndex;
    private Dictionary<uint, int> methodSignatureIndex => state.MethodSignatureIndex;

    private Dictionary<uint, (string Name, uint Scope)> referenceNames => state.ReferenceNames;
    private Dictionary<uint, string> otherDefinitionNames => state.OtherDefinitionNames;
    private readonly HashSet<uint> activeNames = new();

    public string DefinitionName(uint offset, int depth = 0) {
        if (TypeIndex.TryGetValue(offset, out int index))
            return Types[index].Name;

        if (otherDefinitionNames.TryGetValue(offset, out string? cached))
            return cached;

        if (depth > 256 || !activeNames.Add((offset << HandleBits) | 0x3A))
            throw new InvalidDataException("Cyclic or excessively nested type definition.");

        try {
            var reader = Reader(offset);
            reader.Unsigned();
            reader.Unsigned();

            uint ns = reader.Unsigned();
            string name = String(reader.Unsigned());

            reader.Unsigned();
            reader.Unsigned();
            uint enclosing = reader.Unsigned();

            string prefix = enclosing != 0
                ? DefinitionName(enclosing, depth + 1)
                : NamespaceName(ns, depth + 1);
            string result = prefix.Length == 0
                ? name
                : prefix + (enclosing != 0 ? "+" : ".") + name;

            if (name.Length == 0)
                throw new InvalidDataException("Type definition has no name.");

            otherDefinitionNames.Add(offset, result);

            return result;
        } finally {
            activeNames.Remove((offset << HandleBits) | 0x3A);
        }
    }

    private string NamespaceName(uint offset, int depth) {
        if (offset == 0)
            return "";

        if (namespaces.TryGetValue(offset, out var known))
            return known.Name;

        if (depth > 256 || !activeNames.Add((offset << HandleBits) | 0x2F))
            throw new InvalidDataException("Cyclic or excessively nested namespace definition.");

        try {
            var reader = Reader(offset);
            uint parent = reader.Unsigned();
            string name = String(reader.Unsigned());

            int kind = (int)(parent & ((1U << HandleBits) - 1));
            uint parentOffset = parent >> HandleBits;

            string prefix;
            uint scope;

            if (kind == 0x38) {
                if (!scopeIndex.ContainsKey(parentOffset))
                    throw new InvalidDataException("Namespace refers to an unknown assembly scope.");

                prefix = "";
                scope = parentOffset;
            } else if (kind == 0x2F) {
                prefix = NamespaceName(parentOffset, depth + 1);
                scope = namespaces[parentOffset].Scope;
            } else
                throw new InvalidDataException("Namespace has an invalid parent kind.");

            string full = prefix.Length != 0 && name.Length != 0
                ? prefix + "." + name
                : prefix + name;

            namespaces.Add(offset, (scope, full));

            return full;
        } finally {
            activeNames.Remove((offset << HandleBits) | 0x2F);
        }
    }

    private (string Name, uint Scope) ReferenceIdentity(uint raw, int depth) {
        if (referenceNames.TryGetValue(raw, out var identity))
            return identity;

        if (depth > 256 || !activeNames.Add(raw))
            throw new InvalidDataException("Cyclic or excessively nested metadata reference.");

        try {
            int kind = (int)(raw & ((1U << HandleBits) - 1));
            var reader = Reader(raw >> HandleBits);

            uint parent = reader.Unsigned();
            string part = String(reader.Unsigned());

            int parentKind = (int)(parent & ((1U << HandleBits) - 1));
            string prefix;
            uint scope;

            if (kind == 0x30 && parentKind == 0x39) {
                ReadScopeReference(parent >> HandleBits);
                prefix = "";
                scope = parent;
            } else if ((kind == 0x30 && parentKind == 0x30)
                || (kind == 0x3D && parentKind is 0x30 or 0x3D)) {
                var parentIdentity = ReferenceIdentity(parent, depth + 1);
                prefix = parentIdentity.Name;
                scope = parentIdentity.Scope;
            } else
                throw new InvalidDataException($"Invalid metadata reference parent 0x{parentKind:X} for 0x{kind:X}.");

            string name = prefix.Length == 0
                ? part
                : part.Length == 0
                    ? prefix
                    : prefix + (parentKind == 0x3D ? "+" : ".") + part;

            referenceNames.Add(raw, (name, scope));

            return (name, scope);
        } finally {
            activeNames.Remove(raw);
        }
    }

    private IndexRange SignatureCollection(
        ref NativeReader reader,
        int depth,
        bool dimensions = false) {
        int count = checked((int)reader.Unsigned());

        if (count > reader.Remaining)
            throw new InvalidDataException("Signature collection exceeds the metadata blob.");

        int start = SignatureBuilder.Edges.Length;

        // Child resolution may append more edges; indices keep the reserved argument range stable across those appends and any buffer growth
        SignatureBuilder.ReserveEdges(count);

        for (int i = 0; i < count; ++i)
            SignatureBuilder.SetEdge(
                start + i,
                dimensions ? reader.Signed() : TypeSignature(reader.Unsigned(), depth + 1));

        return new IndexRange(start, count);
    }

    // Completed caches never contain recursion sentinels. A failed root read
    // discards its graph and cache additions, preserving every previously published ID.
    private readonly HashSet<uint> activeTypeSignatures = new();
    private readonly HashSet<uint> activeMethodSignatures = new();
    private readonly List<(bool Method, uint Value)> addedSignatures = new();
    private int signatureOperations;

    private bool readingSignatures;
    private SignatureBuilder.Checkpoint signatureStart;

    internal int TypeSignature(uint raw, int depth = 0) => ReadSignature(raw, depth, method: false);
    internal int MethodSignature(uint offset, int depth = 0) => ReadSignature(offset, depth, method: true);

    public SignatureType ReadTypeSignature(uint handle) {
        if (signatureIndex.TryGetValue(handle, out int cached))
            return SignatureBuilder.Publish().Types[cached];

        using var operation = new SignatureOperation(this);

        try {
            int index = TypeSignature(handle);
            return SignatureBuilder.Publish().Types[index];
        } catch {
            operation.Rollback();
            throw;
        }
    }

    public SignatureMethod ReadMethodSignature(uint offset) {
        if (methodSignatureIndex.TryGetValue(offset, out int cached))
            return SignatureBuilder.Publish().MethodSignatures[cached];

        using var operation = new SignatureOperation(this);

        try {
            int index = MethodSignature(offset);
            return SignatureBuilder.Publish().MethodSignatures[index];
        } catch {
            operation.Rollback();
            throw;
        }
    }

    private int ReadSignature(uint value, int depth, bool method) {
        if (method ? value == 0 : (value >> HandleBits) == 0)
            return 0;

        if (!method && depth > 256)
            throw new NotSupportedException("Type signature exceeds the supported nesting depth of 256.");

        var cache = method ? methodSignatureIndex : signatureIndex;

        if (cache.TryGetValue(value, out int index))
            return index;

        var active = method ? activeMethodSignatures : activeTypeSignatures;
        bool root = !readingSignatures;
        int signatureChanges = addedSignatures.Count;

        bool started = false;
        bool activeAdded = false;
        bool complete = false;

        try {
            if (root) {
                signatureStart = SignatureBuilder.BeginRead();
                readingSignatures = true;
                started = true;
            }

            if (!(activeAdded = active.Add(value)))
                throw new InvalidDataException(method ? "Cyclic method signature." : "Cyclic type signature.");

            index = method ? ReadMethodSignature(value, depth) : ReadTypeSignature(value, depth);

            addedSignatures.Add((method, value));
            cache.Add(value, index);
            complete = true;

            return index;
        } finally {
            if (activeAdded)
                active.Remove(value);

            if (root && started) {
                if (!complete) {
                    SignatureBuilder.RollbackRead(signatureStart);

                    RemoveSignatureChanges(signatureChanges);
                } else {
                    SignatureBuilder.CompleteRead(signatureStart);
                }

                readingSignatures = false;

                if (signatureOperations == 0)
                    ClearSignatureChanges();
            }
        }
    }

    private int ReadTypeSignature(uint raw, int depth) {
        int kind = (int)(raw & ((1U << HandleBits) - 1));
        uint offset = raw >> HandleBits;
        var reader = Reader(offset);

        SignatureNode node = new();
        int index = -1;

        switch (kind) {
            case 0x3A:
                node.Kind = SignatureKind.Named;
                node.Name = DefinitionName(offset);
                uint scope = DefinitionScope(offset);
                node.MetadataScope = scope == 0 ? 0 : checked(scope << HandleBits) | 0x38;
                break;

            case 0x3D:

                // Stack-trace formals use parentless TypeReferences
                // Their names identify parameters, not resolvable runtime types
                if (reader.Unsigned() == 0) {
                    node.Kind = SignatureKind.ParameterName;
                    node.Name = String(reader.Unsigned());

                    if (node.Name.Length == 0)
                        throw new InvalidDataException("Parentless type reference has no parameter name.");
                } else {
                    node.Kind = SignatureKind.Named;
                    var identity = ReferenceIdentity(raw, depth);
                    node.Name = identity.Name;
                    node.MetadataScope = identity.Scope;
                }

                break;

            case 0x3F:
            case 0x2C:
                node.Kind = kind == 0x3F ? SignatureKind.TypeVariable : SignatureKind.MethodVariable;
                node.Value = reader.Signed();

                if (node.Value < 0)
                    throw new InvalidDataException("Negative generic variable index.");

                break;

            case 0x01:
                node.Kind = SignatureKind.Array;
                node.Element = TypeSignature(reader.Unsigned(), depth + 1);
                node.Value = reader.Signed();

                if (node.Value is < 1 or > 32)
                    throw new InvalidDataException("Array rank exceeds the runtime range 1..32.");

                node.Sizes = SignatureCollection(ref reader, depth, dimensions: true);
                node.LowerBounds = SignatureCollection(ref reader, depth, dimensions: true);

                if (node.Sizes.Count > node.Value || node.LowerBounds.Count > node.Value)
                    throw new InvalidDataException("Array dimensions exceed its rank.");

                break;

            case 0x37:
            case 0x32:
            case 0x02:
                node.Kind = kind == 0x37
                    ? SignatureKind.SzArray
                    : kind == 0x32
                        ? SignatureKind.Pointer
                        : SignatureKind.ByReference;

                node.Element = TypeSignature(reader.Unsigned(), depth + 1);
                break;

            case 0x3C:
                node.Kind = SignatureKind.Instantiation;
                node.Element = TypeSignature(reader.Unsigned(), depth + 1);
                node.Arguments = SignatureCollection(ref reader, depth);
                break;

            case 0x3E:
                index = TypeSignature(reader.Unsigned(), depth + 1);
                break;

            case 0x2D:
                node.Kind = SignatureKind.Modified;
                byte optional = reader.Take(1)[0];

                if (optional > 1)
                    throw new InvalidDataException("Invalid modifier optional flag.");

                node.Optional = optional != 0;
                node.Value = TypeSignature(reader.Unsigned(), depth + 1);
                node.Element = TypeSignature(reader.Unsigned(), depth + 1);
                break;

            case 0x25:
                int signatureId = MethodSignature(reader.Unsigned(), depth + 1);
                var signature = SignatureBuilder.Methods[signatureId];

                node.Kind = SignatureKind.FunctionPointer;
                node.Element = signature.ReturnType;
                node.Arguments = signature.Parameters;
                node.Varargs = signature.Varargs;
                node.Value = checked((int)signature.CallingConvention);
                break;

            default:
                throw new InvalidDataException($"Handle kind 0x{kind:X} is not a type signature.");
        }

        if (index < 0) {
            index = SignatureBuilder.Nodes.Length;
            SignatureBuilder.AddNode(node);
        }

        return index;
    }

    private int ReadMethodSignature(uint offset, int depth) {
        var reader = Reader(offset);

        MethodSignature signature = new() {
            Offset = offset,
            CallingConvention = reader.Unsigned()
        };

        signature.GenericParameterCount = reader.Signed();

        if (signature.GenericParameterCount < 0)
            throw new InvalidDataException("Negative generic parameter count.");

        signature.ReturnType = TypeSignature(reader.Unsigned(), depth + 1);
        signature.Parameters = SignatureCollection(ref reader, depth);
        signature.Varargs = SignatureCollection(ref reader, depth);

        int index = SignatureBuilder.Methods.Length;
        SignatureBuilder.AddMethod(signature);

        return index;
    }
}
