namespace Atlas;

internal static class SignatureDisplayBounds {
    private const int TextLimit = 4096;
    private const int DepthLimit = 256;

    // Count shared subgraphs once. Rendering every root to discover whether it
    // needs a graph reference would expand DAGs and allocate the discarded text.
    internal static bool RequiresReferences(
        ReadOnlySpan<SignatureNode> nodes,
        ReadOnlySpan<int> edges,
        ReadOnlySpan<MethodSignature> methods) {
        var states = new byte[nodes.Length];
        var lengths = new ushort[nodes.Length];
        var depths = new ushort[nodes.Length];
        var work = new List<(int Index, int NextChild)>();

        for (int root = 0; root < nodes.Length; ++root) {
            if (states[root] == 2)
                continue;

            states[root] = 1;
            work.Add((root, 0));

            while (work.Count != 0) {
                var frame = work[^1];
                ref readonly var node = ref nodes[frame.Index];
                int children = ChildCount(node);

                if (frame.NextChild < children) {
                    int child = Child(node, edges, frame.NextChild);
                    work[^1] = (frame.Index, frame.NextChild + 1);

                    if (states[child] == 1)
                        return true;

                    if (states[child] == 0) {
                        states[child] = 1;
                        work.Add((child, 0));
                    }

                    continue;
                }

                long length = OwnLength(node);
                int depth = children == 0 ? 0 : 1;

                for (int i = 0; i < children; ++i) {
                    int child = Child(node, edges, i);
                    length += lengths[child];
                    depth = Math.Max(depth, depths[child] + 1);

                    if (length > TextLimit || depth > DepthLimit)
                        return true;
                }

                if (length > TextLimit)
                    return true;

                lengths[frame.Index] = (ushort)length;
                depths[frame.Index] = (ushort)depth;
                states[frame.Index] = 2;
                work.RemoveAt(work.Count - 1);
            }
        }

        foreach (ref readonly var method in methods) {
            int length = 6 + lengths[method.ReturnType]
                + ParameterPunctuation(method.Parameters.Count, method.Varargs.Count,
                    !method.NativeConvention && (method.CallingConvention & 15) == 5, 2);

            if (method.NativeConvention)
                length += " [native_cc=0x]".Length + Digits(method.CallingConvention, 16);
            else if ((method.CallingConvention & ~0x20U) != 0)
                length += " [cc=0x]".Length + Digits(method.CallingConvention, 16);

            for (int i = method.Parameters.Start; i < method.Parameters.End && length <= TextLimit; ++i)
                length += lengths[edges[i]];

            for (int i = method.Varargs.Start; i < method.Varargs.End && length <= TextLimit; ++i)
                length += lengths[edges[i]];

            if (length > TextLimit)
                return true;
        }

        return false;
    }

    private static int ChildCount(in SignatureNode node) => node.Kind switch {
        SignatureKind.Array or SignatureKind.SzArray or SignatureKind.Pointer or SignatureKind.ByReference => 1,
        SignatureKind.Modified => 2,
        SignatureKind.Instantiation => 1 + node.Arguments.Count,
        SignatureKind.FunctionPointer => 1 + node.Arguments.Count + node.Varargs.Count,
        _ => 0
    };

    private static int Child(in SignatureNode node, ReadOnlySpan<int> edges, int position) {
        if (position == 0)
            return node.Element;
        if (node.Kind == SignatureKind.Modified)
            return node.Value;

        --position;
        return position < node.Arguments.Count
            ? edges[node.Arguments.Start + position]
            : edges[node.Varargs.Start + position - node.Arguments.Count];
    }

    private static long OwnLength(in SignatureNode node) => node.Kind switch {
        SignatureKind.Unknown => 2,
        SignatureKind.Named or SignatureKind.ParameterName => node.Name?.Length ?? TextLimit + 1,
        SignatureKind.RuntimeType => "mt_ref_".Length + Digits(node.TypeAddress, 16),
        SignatureKind.TypeVariable => 1 + (node.Value == 0 ? 0 : Digits((uint)node.Value, 10)),
        SignatureKind.MethodVariable => 2 + (node.Value == 0 ? 0 : Digits((uint)node.Value, 10)),
        SignatureKind.SzArray => 2,
        SignatureKind.Array => 2L + (node.Value == 1 ? 1 : node.Value - 1),
        SignatureKind.Pointer or SignatureKind.ByReference => 1,
        SignatureKind.Modified => " modreq()".Length,
        SignatureKind.Instantiation => node.Arguments.Count == 0 ? 0 : 2 + node.Arguments.Count - 1,
        SignatureKind.FunctionPointer => FunctionPointerLength(node),
        _ => throw new InvalidOperationException($"Unknown signature kind {node.Kind}.")
    };

    private static int FunctionPointerLength(in SignatureNode node) {
        bool varargs = !node.NativeConvention && (node.Value & 15) == 5;
        int length = "delegate*<>".Length
            + ParameterPunctuation(node.Arguments.Count, node.Varargs.Count, varargs, 1);

        if (node.Arguments.Count != 0 || node.Varargs.Count != 0 || varargs)
            ++length;

        if (node.NativeConvention && (node.Value & 4) != 0)
            length += " unmanaged".Length;
        else if (!node.NativeConvention && node.Value != 0)
            length += "[cc=0x]".Length + Digits((uint)node.Value, 16);

        return length;
    }

    private static int ParameterPunctuation(int parameters, int varargs, bool varargConvention, int separatorLength) {
        int length = Math.Max(0, parameters - 1) * separatorLength;

        if (varargs != 0 || varargConvention)
            length += 3 + (parameters == 0 ? 0 : separatorLength) + varargs * separatorLength;

        return length;
    }

    private static int Digits(ulong value, uint radix) {
        int digits = 1;
        while (value >= radix) {
            value /= radix;
            ++digits;
        }
        return digits;
    }
}
