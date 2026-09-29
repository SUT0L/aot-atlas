using System.Runtime.InteropServices;

namespace Atlas;

public sealed partial class Metadata {
    public readonly Signatures Signatures = new();

    private readonly Dictionary<uint, int> signatureIndex = new(32768);
    private readonly Dictionary<uint, int> methodSignatureIndex = new(16384);
    private readonly Dictionary<uint, string> referenceNames = new(4096);
    private readonly Dictionary<uint, string> otherDefinitionNames = new(256);
    private readonly HashSet<uint> activeNames = new();

    public string DefinitionName(uint offset, int depth = 0) {
        if (TypeIndex.TryGetValue(offset, out int index))
            return Types[index].Name;
        if (otherDefinitionNames.TryGetValue(offset, out string? cached))
            return cached;
        if (depth > 256 || !activeNames.Add((offset << HandleBits) | 0x3A))
            throw new InvalidDataException("Cyclic or excessively nested type definition.");

        var reader = Reader(offset);
        reader.Unsigned();
        reader.Unsigned();
        uint ns = reader.Unsigned();
        string name = String(reader.Unsigned());
        reader.Unsigned();
        reader.Unsigned();
        uint enclosing = reader.Unsigned();

        string prefix = enclosing != 0 ? DefinitionName(enclosing, depth + 1) : NamespaceName(ns, depth + 1);
        string result = prefix.Length == 0 ? name : prefix + (enclosing != 0 ? "+" : ".") + name;
        if (name.Length == 0)
            throw new InvalidDataException("Type definition has no name.");

        activeNames.Remove((offset << HandleBits) | 0x3A);
        otherDefinitionNames.Add(offset, result);
        return result;
    }

    private string NamespaceName(uint offset, int depth) {
        if (offset == 0)
            return "";
        if (namespaces.TryGetValue(offset, out var known))
            return known.Name;
        if (depth > 256 || !activeNames.Add((offset << HandleBits) | 0x2F))
            throw new InvalidDataException("Cyclic or excessively nested namespace definition.");

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

        string full = prefix.Length != 0 && name.Length != 0 ? prefix + "." + name : prefix + name;
        activeNames.Remove((offset << HandleBits) | 0x2F);
        namespaces.Add(offset, (scope, full));
        return full;
    }

    private string ReferenceName(uint raw, int depth) {
        if (referenceNames.TryGetValue(raw, out string? name))
            return name;
        if (depth > 256 || !activeNames.Add(raw))
            throw new InvalidDataException("Cyclic or excessively nested metadata reference.");

        int kind = (int)(raw & ((1U << HandleBits) - 1));
        var reader = Reader(raw >> HandleBits);
        uint parent = reader.Unsigned();
        string part = String(reader.Unsigned());
        int parentKind = (int)(parent & ((1U << HandleBits) - 1));
        string prefix;

        if (kind == 0x30 && parentKind == 0x39) {
            Reader(parent >> HandleBits);
            prefix = "";
        } else if ((kind == 0x30 && parentKind == 0x30) || (kind == 0x3D && parentKind is 0x30 or 0x3D))
            prefix = ReferenceName(parent, depth + 1);
        else
            throw new InvalidDataException($"Invalid metadata reference parent 0x{parentKind:X} for 0x{kind:X}.");

        name = prefix.Length == 0 ? part : part.Length == 0 ? prefix : prefix + (parentKind == 0x3D ? "+" : ".") + part;
        activeNames.Remove(raw);
        referenceNames.Add(raw, name);
        return name;
    }

    private IndexRange SignatureCollection(ref NativeReader reader, int depth, bool dimensions = false) {
        int count = checked((int)reader.Unsigned());
        if (count > reader.Remaining)
            throw new InvalidDataException("Signature collection exceeds the metadata blob.");

        int start = Signatures.Edges.Count;
        // Child resolution may append more edges; indices keep the reserved argument range stable across those appends and any buffer growth
        CollectionsMarshal.SetCount(Signatures.Edges, checked(start + count));
        for (int i = 0; i < count; ++i)
            Signatures.Edges[start + i] = dimensions ? reader.Signed() : TypeSignature(reader.Unsigned(), depth + 1);

        return new IndexRange(start, count);
    }

    public int TypeSignature(uint raw, int depth = 0) {
        if ((raw >> HandleBits) == 0)
            return 0;
        if (depth > 256)
            throw new NotSupportedException("Type signature exceeds the supported nesting depth of 256.");

        if (signatureIndex.TryGetValue(raw, out int index)) {
            if (index == -1)
                throw new InvalidDataException("Cyclic type signature.");
            return index;
        }

        signatureIndex.Add(raw, -1);
        int kind = (int)(raw & ((1U << HandleBits) - 1));
        uint offset = raw >> HandleBits;
        var reader = Reader(offset);
        SignatureNode node = new();

        switch (kind) {
            case 0x3A:
                node.Kind = SignatureKind.Named;
                node.Name = DefinitionName(offset);
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
                    node.Name = ReferenceName(raw, depth);
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
                node.Kind = kind == 0x37 ? SignatureKind.SzArray : kind == 0x32 ? SignatureKind.Pointer : SignatureKind.ByReference;
                node.Element = TypeSignature(reader.Unsigned(), depth + 1);
                break;
            case 0x3C:
                node.Kind = SignatureKind.Instantiation;
                node.Element = TypeSignature(reader.Unsigned(), depth + 1);
                node.Arguments = SignatureCollection(ref reader, depth);
                break;
            case 0x3E:
                index = TypeSignature(reader.Unsigned(), depth + 1);
                signatureIndex[raw] = index;
                return index;
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
                var signature = Signatures.Methods[signatureId];
                node.Kind = SignatureKind.FunctionPointer;
                node.Element = signature.ReturnType;
                node.Arguments = signature.Parameters;
                node.Varargs = signature.Varargs;
                node.Value = checked((int)signature.CallingConvention);
                break;
            default:
                throw new InvalidDataException($"Handle kind 0x{kind:X} is not a type signature.");
        }

        index = Signatures.Nodes.Count;
        Signatures.Nodes.Add(node);
        signatureIndex[raw] = index;
        return index;
    }

    public int MethodSignature(uint offset, int depth = 0) {
        if (offset == 0)
            return 0;

        if (methodSignatureIndex.TryGetValue(offset, out int index)) {
            if (index == 0)
                throw new InvalidDataException("Cyclic method signature.");
            return index;
        }

        methodSignatureIndex.Add(offset, 0);
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

        index = Signatures.Methods.Count;
        Signatures.Methods.Add(signature);
        methodSignatureIndex[offset] = index;
        return index;
    }
}
