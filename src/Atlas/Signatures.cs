using System.Text;

namespace Atlas;

public enum SignatureKind : byte {
    Unknown,
    Named,
    TypeVariable,
    MethodVariable,
    Array,
    SzArray,
    Pointer,
    ByReference,
    Instantiation,
    FunctionPointer,
    Modified,
    RuntimeType,
    ParameterName
}

internal struct SignatureNode {
    public SignatureKind Kind;
    public int Element;
    public int Value;

    public string Name;
    public ulong TypeAddress;
    public uint MetadataScope;

    public IndexRange Arguments;
    public IndexRange Varargs;

    public IndexRange Sizes;
    public IndexRange LowerBounds;

    public bool Optional;
    public bool NativeConvention;
}

internal struct MethodSignature {
    public uint Offset;
    public uint CallingConvention;

    public int GenericParameterCount;
    public int ReturnType;

    public IndexRange Parameters;
    public IndexRange Varargs;
    public bool NativeConvention;
}

internal sealed class SignatureHistory { }

public sealed class Signatures {
    private readonly SignatureHistory history;
    private readonly SignatureNode[] nodes;
    private readonly int[] edges;
    private readonly MethodSignature[] methods;
    private bool hasAbbreviatedReferences;

    internal Signatures(
        SignatureHistory history,
        SignatureNode[] nodes,
        int[] edges,
        MethodSignature[] methods,
        bool hasAbbreviatedReferences = false) {
        this.history = history;
        this.nodes = nodes;
        this.edges = edges;
        this.methods = methods;
        this.hasAbbreviatedReferences = hasAbbreviatedReferences;
    }

    internal bool SharesOrigin(Signatures other) => ReferenceEquals(history, other.history);
    internal bool IsOwnedBy(SignatureHistory owner) => ReferenceEquals(history, owner);
    internal SignatureHistory Origin => history;

    // An operation may reuse ID-indexed evidence only when the old payload is
    // unchanged. A shared builder namespace alone also permits rewritten IDs.
    internal bool Extends(Signatures previous) => SharesOrigin(previous) && HasSamePrefix(previous);

    internal bool HasSamePrefix(Signatures previous) =>
        HasSamePrefix(previous.Nodes, previous.Edges, previous.Methods);

    internal bool HasSamePrefix(
        ReadOnlySpan<SignatureNode> previousNodes,
        ReadOnlySpan<int> previousEdges,
        ReadOnlySpan<MethodSignature> previousMethods) {
        if (nodes.Length < previousNodes.Length
            || edges.Length < previousEdges.Length
            || methods.Length < previousMethods.Length)
            return false;

        for (int i = 0; i < previousNodes.Length; ++i) {
            ref readonly var current = ref nodes[i];
            ref readonly var old = ref previousNodes[i];

            if (current.Kind != old.Kind
                || current.Element != old.Element
                || current.Value != old.Value
                || current.Name != old.Name
                || current.TypeAddress != old.TypeAddress
                || current.MetadataScope != old.MetadataScope
                || current.Optional != old.Optional
                || current.NativeConvention != old.NativeConvention
                || !SameRange(current.Arguments, old.Arguments)
                || !SameRange(current.Varargs, old.Varargs)
                || !SameRange(current.Sizes, old.Sizes)
                || !SameRange(current.LowerBounds, old.LowerBounds))
                return false;
        }

        if (!edges.AsSpan(0, previousEdges.Length).SequenceEqual(previousEdges))
            return false;

        for (int i = 0; i < previousMethods.Length; ++i) {
            ref readonly var current = ref methods[i];
            ref readonly var old = ref previousMethods[i];

            if (current.Offset != old.Offset
                || current.CallingConvention != old.CallingConvention
                || current.GenericParameterCount != old.GenericParameterCount
                || current.ReturnType != old.ReturnType
                || current.NativeConvention != old.NativeConvention
                || !SameRange(current.Parameters, old.Parameters)
                || !SameRange(current.Varargs, old.Varargs))
                return false;
        }

        return true;
    }

    private static bool SameRange(IndexRange left, IndexRange right) =>
        left.Start == right.Start && left.Count == right.Count;

    internal ReadOnlySpan<SignatureNode> Nodes => nodes;
    internal ReadOnlySpan<int> Edges => edges;
    internal ReadOnlySpan<MethodSignature> Methods => methods;
    public SignatureTypes Types => new(this);
    public SignatureMethods MethodSignatures => new(this);
    public bool HasAbbreviatedReferences => hasAbbreviatedReferences;

    public SignatureType Continue(SignatureType signature) {
        ValidatePrefix(signature.Publication);
        return Types[signature.Index];
    }

    public SignatureMethod Continue(SignatureMethod signature) {
        ValidatePrefix(signature.Publication);
        return MethodSignatures[signature.Index];
    }

    private void ValidatePrefix(Signatures previous) {
        if (ReferenceEquals(previous, this))
            return;

        if (!Extends(previous))
            throw new ArgumentException("The signature publication is not an unchanged prefix of this graph.");
    }

    internal string RenderType(
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) {
        var builder = new StringBuilder();
        AppendType(builder, index, typeArguments, methodArguments);

        return builder.ToString();
    }

    internal string RenderMethod(
        string name,
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) {
        var builder = new StringBuilder(name);
        AppendMethod(builder, index, typeArguments, methodArguments);

        return builder.ToString();
    }

    internal void AppendType(
        StringBuilder builder,
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) =>
        AppendTypeWithStatus(builder, index, typeArguments, methodArguments);

    internal void AppendMethod(
        StringBuilder builder,
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) =>
        AppendMethodWithStatus(builder, index, typeArguments, methodArguments);

    internal bool AppendTypeWithStatus(
        StringBuilder builder,
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) {
        bool complete = SignatureRendering.AppendType(
            builder, index, Nodes, Edges, Methods, typeArguments, methodArguments);

        if (!complete)
            hasAbbreviatedReferences = true;

        return complete;
    }

    internal bool AppendMethodWithStatus(
        StringBuilder builder,
        int index,
        ReadOnlySpan<string> typeArguments = default,
        ReadOnlySpan<string> methodArguments = default) {
        bool complete = SignatureRendering.AppendMethod(
            builder, index, Nodes, Edges, Methods, typeArguments, methodArguments);

        if (!complete)
            hasAbbreviatedReferences = true;

        return complete;
    }
}

internal static class SignatureRendering {
    [System.Runtime.CompilerServices.SkipLocalsInit]
    internal static bool AppendType(
        StringBuilder builder,
        int index,
        ReadOnlySpan<SignatureNode> nodes,
        ReadOnlySpan<int> edges,
        ReadOnlySpan<MethodSignature> methods,
        ReadOnlySpan<string> typeArguments,
        ReadOnlySpan<string> methodArguments) {
        int start = builder.Length;
        Span<int> path = stackalloc int[256];
        var writer = new SignatureWriter(nodes, edges, methods, builder, typeArguments, methodArguments, path);

        try {
            if (!writer.Type(index)) {
                builder.Length = start;
                builder.Append("sig_ref_").Append(index);

                return false;
            }

            return true;
        } catch {
            builder.Length = start;
            throw;
        }
    }

    [System.Runtime.CompilerServices.SkipLocalsInit]
    internal static bool AppendMethod(
        StringBuilder builder,
        int index,
        ReadOnlySpan<SignatureNode> nodes,
        ReadOnlySpan<int> edges,
        ReadOnlySpan<MethodSignature> methods,
        ReadOnlySpan<string> typeArguments,
        ReadOnlySpan<string> methodArguments) {
        int start = builder.Length;
        Span<int> path = stackalloc int[256];
        var writer = new SignatureWriter(nodes, edges, methods, builder, typeArguments, methodArguments, path);

        try {
            if (!writer.Method(index)) {
                builder.Length = start;
                builder.Append(" [method_sig_ref_").Append(index).Append(']');

                return false;
            }

            return true;
        } catch {
            builder.Length = start;
            throw;
        }
    }

    private ref struct SignatureWriter {
        private readonly ReadOnlySpan<SignatureNode> nodes;
        private readonly ReadOnlySpan<int> edges;
        private readonly ReadOnlySpan<MethodSignature> methods;

        private readonly StringBuilder builder;
        private readonly ReadOnlySpan<string> typeArguments;
        private readonly ReadOnlySpan<string> methodArguments;

        // Only the active prefix is read; every ancestor writes its slot before
        // descending. AppendType/AppendMethod can leave inactive stack slots uninitialized.
        private readonly Span<int> path;
        private int remaining;

        internal SignatureWriter(
            ReadOnlySpan<SignatureNode> nodes,
            ReadOnlySpan<int> edges,
            ReadOnlySpan<MethodSignature> methods,
            StringBuilder builder,
            ReadOnlySpan<string> typeArguments,
            ReadOnlySpan<string> methodArguments,
            Span<int> path) {
            this.nodes = nodes;
            this.edges = edges;
            this.methods = methods;

            this.builder = builder;
            this.typeArguments = typeArguments;
            this.methodArguments = methodArguments;

            this.path = path;
            remaining = 4096;
        }

        private bool Text(string value) {
            if (value.Length > remaining)
                return false;

            remaining -= value.Length;
            builder.Append(value);

            return true;
        }

        private bool Character(char value, int count = 1) {
            if (count < 0)
                throw new InvalidDataException("Negative signature character count.");

            if (count > remaining)
                return false;

            remaining -= count;
            builder.Append(value, count);

            return true;
        }

        internal bool Method(int index) {
            var signature = methods[index];

            if (!Character('(')
                || !Parameters(
                    signature.Parameters,
                    signature.Varargs,
                    signature.NativeConvention ? 0 : signature.CallingConvention,
                    ", ",
                    0)
                || !Text(") -> ")
                || !Type(signature.ReturnType))
                return false;

            if (signature.NativeConvention)
                return Text($" [native_cc=0x{signature.CallingConvention:X}]");

            return (signature.CallingConvention & ~0x20U) == 0
                || Text($" [cc=0x{signature.CallingConvention:X}]");
        }

        private bool Parameters(
            IndexRange arguments,
            IndexRange varargs,
            uint convention,
            string separator,
            int depth) {
            for (int i = arguments.Start; i < arguments.End; ++i) {
                if ((i != arguments.Start && !Text(separator)) || !Type(edges[i], depth))
                    return false;
            }

            if (varargs.Count != 0 || (convention & 15) == 5) {
                if ((arguments.Count != 0 && !Text(separator)) || !Text("..."))
                    return false;

                for (int i = varargs.Start; i < varargs.End; ++i) {
                    if (!Text(separator) || !Type(edges[i], depth))
                        return false;
                }
            }

            return true;
        }

        internal bool Type(int index, int depth = 0) {
            var node = nodes[index];

            switch (node.Kind) {
                case SignatureKind.Unknown:
                    return Text("??");

                case SignatureKind.Named:
                case SignatureKind.ParameterName:
                    return Text(node.Name);

                case SignatureKind.RuntimeType:
                    return Text("mt_ref_") && Text(node.TypeAddress.ToString("X"));

                case SignatureKind.TypeVariable:
                case SignatureKind.MethodVariable:
                    var arguments = node.Kind == SignatureKind.MethodVariable ? methodArguments : typeArguments;

                    if ((uint)node.Value < (uint)arguments.Length && !string.IsNullOrEmpty(arguments[node.Value]))
                        return Text(arguments[node.Value]);

                    return Text(node.Kind == SignatureKind.MethodVariable ? "TM" : "T")
                        && (node.Value == 0 || Text(node.Value.ToString()));

                default:
                    return Composite(index, node, depth);
            }
        }

        private bool Composite(int index, SignatureNode node, int depth) {
            for (int i = 0; i < depth; ++i) {
                if (path[i] == index)
                    throw new InvalidDataException($"Cyclic type signature at sig_ref_{index}.");
            }

            // Metadata and NativeLayout cache shared nodes. Acyclic graphs can
            // still require exponential text; keep the graph ID when bounded
            // rendering cannot spell the full signature.
            if (depth == path.Length)
                return false;

            path[depth] = index;

            switch (node.Kind) {
                case SignatureKind.FunctionPointer:
                    if (!Text("delegate*"))
                        return false;

                    if (node.NativeConvention) {
                        if ((node.Value & 4) != 0 && !Text(" unmanaged"))
                            return false;
                    } else if (node.Value != 0
                        && (!Text("[cc=0x") || !Text(node.Value.ToString("X")) || !Character(']'))) {
                        return false;
                    }

                    if (!Character('<')
                        || !Parameters(
                            node.Arguments,
                            node.Varargs,
                            node.NativeConvention ? 0 : (uint)node.Value,
                            ",",
                            depth + 1))
                        return false;

                    if ((node.Arguments.Count != 0
                            || node.Varargs.Count != 0
                            || (!node.NativeConvention && (node.Value & 15) == 5))
                        && !Character(','))
                        return false;

                    return Type(node.Element, depth + 1) && Character('>');

                case SignatureKind.Array:
                case SignatureKind.SzArray:
                case SignatureKind.Pointer:
                case SignatureKind.ByReference:
                case SignatureKind.Instantiation:
                case SignatureKind.Modified:
                    if (!Type(node.Element, depth + 1))
                        return false;

                    return node.Kind switch {
                        SignatureKind.SzArray => Text("[]"),
                        SignatureKind.Array => Character('[')
                            && (node.Value == 1 ? Character('*') : Character(',', node.Value - 1))
                            && Character(']'),
                        SignatureKind.Pointer => Character('*'),
                        SignatureKind.ByReference => Character('&'),
                        SignatureKind.Instantiation => node.Arguments.Count == 0
                            || (Character('<')
                                && Parameters(node.Arguments, default, 0, ",", depth + 1)
                                && Character('>')),
                        SignatureKind.Modified => Text(node.Optional ? " modopt(" : " modreq(")
                            && Type(node.Value, depth + 1)
                            && Character(')'),
                        _ => throw new InvalidOperationException()
                    };

                default:
                    throw new InvalidDataException($"Unknown signature kind {node.Kind}.");
            }
        }
    }
}
