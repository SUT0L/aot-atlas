using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public enum SharedMethodStatus : byte {
    Unresolved,
    Ambiguous,
    Matched
}

public sealed class SharedMethods {
    private readonly Extraction extraction;
    private readonly Signatures signatures;
    // A template index plus one identifies the runtimes canonical lookup result
    // Zero is unresolved; -1 is ambiguous
    // Neither asserts a callable address
    internal readonly int[] Templates;
    internal readonly ulong[] JumpTargets;
    public ReadOnlySpan<ulong> UnboxedEntrypoints => JumpTargets;

    public SharedMethodStatus StatusAt(int genericMethodPosition) => Templates[genericMethodPosition] switch {
        0 => SharedMethodStatus.Unresolved,
        -1 => SharedMethodStatus.Ambiguous,
        _ => SharedMethodStatus.Matched
    };

    public MethodTemplate? TemplateAt(int genericMethodPosition) {
        int template = Templates[genericMethodPosition];
        return template <= 0 ? null : extraction.Templates.Methods[template - 1];
    }

    public SignatureMethod TemplateSignatureAt(int genericMethodPosition) {
        var template = TemplateAt(genericMethodPosition);
        return template is null ? default : signatures.MethodSignatures[template.Value.Method.Identity.Signature];
    }

    public SignatureType TemplateDeclaringTypeAt(int genericMethodPosition) {
        var template = TemplateAt(genericMethodPosition);
        return template is null ? default : signatures.Types[template.Value.Method.DeclaringType];
    }

    public SignatureTypes TemplateArgumentsAt(int genericMethodPosition) {
        var template = TemplateAt(genericMethodPosition);
        return template is null ? default : new(signatures, template.Value.Method.Arguments);
    }

    public SharedMethods(Extraction extraction) : this(extraction, extraction.Signatures) { }

    public SharedMethods(Extraction extraction, Signatures signatures) {
        this.extraction = extraction;
        this.signatures = signatures;
        var tables = extraction.Types;
        var bindings = extraction.Bindings.WithSignatures(signatures);
        var canonical = extraction.Fields.Canonical;

        var templates = extraction.Templates.Methods;
        SignatureComparison? comparison = null;

        var heads = new Dictionary<(int Owner, string Name, int Arity, ulong Arguments), int>(templates.Count);
        var next = new int[templates.Count];

        Templates = new int[extraction.Generics.Methods.Count];
        JumpTargets = new ulong[templates.Count];

        var reader = new ByteArrayCodeReader(extraction.Image.FileData);
        var decoder = Decoder.Create(64, reader);

        for (int i = 0; i < templates.Count; ++i) {
            ref readonly var template = ref CollectionsMarshal.AsSpan(templates)[i];
            ref readonly var method = ref template.Method;
            if (method.Entrypoint != 0) {
                var image = extraction.Image;
                ref readonly var section = ref image.Sections[image.FindSection(method.Entrypoint)];
                ulong offset = method.Entrypoint - image.ImageBase - section.Rva;
                if (offset < (ulong)section.FileSize) {
                    reader.Position = section.FileOffset + (int)offset;
                    decoder.IP = method.Entrypoint;
                    decoder.Decode(out var instruction);

                    // Address-taken identity stubs can forward into folded code
                    // Preserve that address and expose only the proven jump edge; adapters that change arguments have a different contract
                    if (instruction.Code is Code.Jmp_rel8_64 or Code.Jmp_rel32_64
                        && reader.Position <= section.FileOffset + section.FileSize
                        && !instruction.HasLockPrefix && image.IsExecutable(instruction.NearBranchTarget))
                        JumpTargets[i] = instruction.NearBranchTarget;
                }
            }

            if (template.UniversalCanonical || template.AsyncVariant || template.ReturnDroppingAsyncThunk)
                continue;

            int owner = bindings.Resolve(method.DeclaringType);
            if (owner == 0)
                continue;

            int group = canonical.Groups[owner - 1];

            ulong hash = 14695981039346656037UL;
            bool complete = true;

            for (int j = method.Arguments.Start; j < method.Arguments.End; ++j) {
                int argument = bindings.Resolve(signatures.Edges[j]);
                if (argument == 0) {
                    complete = false;
                    break;
                }

                hash = unchecked(
                    (hash ^ (uint)canonical.Argument(tables, argument - 1))
                    * 1099511628211UL);
            }

            if (!complete)
                continue;

            var key = (group, method.Identity.Name, method.Arguments.Count, hash);
            ref int head = ref CollectionsMarshal.GetValueRefOrAddDefault(heads, key, out _);
            next[i] = head;
            head = i + 1;
        }

        for (int i = 0; i < Templates.Length; ++i) {
            ref readonly var record = ref CollectionsMarshal.AsSpan(extraction.Generics.Methods)[i];
            if (record.Dictionary == 0 || record.AsyncVariant || record.ReturnDroppingAsyncThunk)
                continue;

            int owner = tables.Index[record.DeclaringType] + 1;
            int group = canonical.Groups[owner - 1];

            ulong hash = 14695981039346656037UL;

            for (int j = record.Arguments.Start; j < record.Arguments.End; ++j)
                hash = unchecked(
                    (hash ^ (uint)canonical.Argument(tables, tables.Index[extraction.Generics.Arguments[j]]))
                    * 1099511628211UL);

            var key = (group, record.Name, record.Arguments.Count, hash);
            heads.TryGetValue(key, out int first);

            for (int candidate = first; candidate != 0; candidate = next[candidate - 1]) {
                ref readonly var template = ref CollectionsMarshal.AsSpan(templates)[candidate - 1];
                ref readonly var method = ref template.Method;
                bool identity = record.MetadataOffset != 0 && method.Identity.MetadataOffset != 0
                    ? record.MetadataOffset == method.Identity.MetadataOffset
                    : (comparison ??= new(signatures, bindings)).EqualMethod(record.Signature, method.Identity.Signature);
                if (!identity)
                    continue;

                bool match = true;

                for (int j = 0; j < record.Arguments.Count; ++j) {
                    int argument = bindings.Resolve(signatures.Edges[method.Arguments.Start + j]);
                    int actual = tables.Index[extraction.Generics.Arguments[record.Arguments.Start + j]];
                    if (argument == 0 || canonical.Argument(tables, argument - 1) != canonical.Argument(tables, actual)) {
                        match = false;
                        break;
                    }
                }

                if (match) {
                    if (Templates[i] != 0) {
                        Templates[i] = -1;
                        break;
                    }

                    Templates[i] = candidate;
                }
            }
        }
    }
}

// Scratch belongs to one matching operation over an immutable signature graph.
internal sealed class SignatureComparison(Signatures signatures, TypeBindings bindings) {
    private const byte Active = 1;
    private const byte Equal = 2;
    private const byte Unequal = 3;

    private readonly Dictionary<(int Left, int Right), byte> states = new();
    private ComparisonFrame[] frames = [];

    private struct ComparisonFrame {
        internal int Left;
        internal int Right;
        internal int Child;
    }

    internal bool EqualMethod(int left, int right) {
        var a = signatures.Methods[left];
        var b = signatures.Methods[right];

        uint ac = a.CallingConvention & ~0x10U;
        if (a.NativeConvention)
            ac = (a.CallingConvention & ~3U) != 0
                ? uint.MaxValue
                : (a.CallingConvention & 2) == 0 ? 0x20U : 0U;

        uint bc = b.CallingConvention & ~0x10U;
        if (b.NativeConvention)
            bc = (b.CallingConvention & ~3U) != 0
                ? uint.MaxValue
                : (b.CallingConvention & 2) == 0 ? 0x20U : 0U;

        if (left == 0
            || right == 0
            || ac == uint.MaxValue
            || ac != bc
            || a.GenericParameterCount != b.GenericParameterCount
            || a.Parameters.Count != b.Parameters.Count
            || a.Varargs.Count != 0
            || b.Varargs.Count != 0)
            return false;

        for (int i = -1; i < a.Parameters.Count; ++i) {
            if (!EqualType(
                i == -1 ? a.ReturnType : signatures.Edges[a.Parameters.Start + i],
                i == -1 ? b.ReturnType : signatures.Edges[b.Parameters.Start + i]))
                return false;
        }

        return true;
    }

    private bool EqualType(int left, int right) {
        int depth = 0;

        try {
            while (true) {
                if (left == 0 || right == 0)
                    break;

                if (left != right) {
                    var pair = left < right ? (Left: left, Right: right) : (Left: right, Right: left);

                    if (states.TryGetValue(pair, out byte state)) {
                        if (state == Active)
                            throw new InvalidDataException("Cyclic structural signature comparison.");
                        if (state == Unequal)
                            break;
                    } else {
                        var a = signatures.Nodes[left];
                        var b = signatures.Nodes[right];

                        if (a.Kind is SignatureKind.Named or SignatureKind.RuntimeType
                            && b.Kind is SignatureKind.Named or SignatureKind.RuntimeType) {
                            int binding = bindings.Resolve(left);
                            if (binding == 0 || binding != bindings.Resolve(right))
                                break;
                        } else {
                            // MethodTables do not preserve array bounds or signature modifiers.
                            if (a.Kind != b.Kind
                                || (a.Kind != SignatureKind.Modified && a.Value != b.Value)
                                || a.Optional != b.Optional
                                || a.NativeConvention != b.NativeConvention)
                                break;

                            if (a.Kind is not (SignatureKind.TypeVariable or SignatureKind.MethodVariable)) {
                                if (a.Kind is not (SignatureKind.Instantiation
                                    or SignatureKind.SzArray
                                    or SignatureKind.Array
                                    or SignatureKind.ByReference
                                    or SignatureKind.Pointer
                                    or SignatureKind.FunctionPointer
                                    or SignatureKind.Modified)
                                    || a.Arguments.Count != b.Arguments.Count
                                    || a.Varargs.Count != b.Varargs.Count
                                    || a.Sizes.Count != b.Sizes.Count
                                    || a.LowerBounds.Count != b.LowerBounds.Count)
                                    break;

                                var edges = signatures.Edges;
                                if (!edges.Slice(a.Sizes.Start, a.Sizes.Count)
                                        .SequenceEqual(edges.Slice(b.Sizes.Start, b.Sizes.Count))
                                    || !edges.Slice(a.LowerBounds.Start, a.LowerBounds.Count)
                                        .SequenceEqual(edges.Slice(b.LowerBounds.Start, b.LowerBounds.Count)))
                                    break;

                                if (depth == frames.Length)
                                    Array.Resize(ref frames, checked(Math.Max(16, depth * 2)));

                                states.Add(pair, Active);
                                frames[depth++] = new() { Left = pair.Left, Right = pair.Right };
                                left = a.Element;
                                right = b.Element;
                                continue;
                            }
                        }
                    }
                }

                // Complete children before publishing the pair as equal. Shared
                // DAG edges then reuse proof rather than expanding the same subtree.
                while (depth != 0) {
                    ref var frame = ref frames[depth - 1];
                    var a = signatures.Nodes[frame.Left];
                    var b = signatures.Nodes[frame.Right];
                    int child = frame.Child++;

                    if (a.Kind == SignatureKind.Modified) {
                        if (child == 0) {
                            left = a.Value;
                            right = b.Value;
                            break;
                        }

                        --child;
                    }

                    if (child < a.Arguments.Count) {
                        left = signatures.Edges[a.Arguments.Start + child];
                        right = signatures.Edges[b.Arguments.Start + child];
                        break;
                    }

                    child -= a.Arguments.Count;
                    if (child < a.Varargs.Count) {
                        left = signatures.Edges[a.Varargs.Start + child];
                        right = signatures.Edges[b.Varargs.Start + child];
                        break;
                    }

                    states[(frame.Left, frame.Right)] = Equal;
                    --depth;
                }

                if (depth == 0)
                    return true;
            }

            // A proven unequal child also proves every active ancestor unequal.
            while (depth != 0) {
                ref readonly var frame = ref frames[--depth];
                states[(frame.Left, frame.Right)] = Unequal;
            }

            return false;
        } finally {
            // Exceptions establish no result for their active ancestors.
            while (depth != 0) {
                ref readonly var frame = ref frames[--depth];
                states.Remove((frame.Left, frame.Right));
            }
        }
    }
}
