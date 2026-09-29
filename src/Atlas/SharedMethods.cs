using System.Runtime.InteropServices;
using Iced.Intel;

namespace Atlas;

public sealed class SharedMethods {
    // A template index plus one identifies the runtimes canonical lookup result
    // Zero is unresolved; -1 is ambiguous
    // Neither asserts a callable address
    public readonly int[] Templates;
    public readonly ulong[] JumpTargets;

    public SharedMethods(Extraction extraction) {
        var tables = extraction.Types;
        var signatures = extraction.Metadata.Signatures;
        var bindings = extraction.Fields.Bindings;
        var canonical = extraction.Fields.Canonical;
        var templates = extraction.Templates.Methods;
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

            if (template.UniversalCanonical || template.AsyncVariant)
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
                hash = unchecked((hash ^ (uint)canonical.Argument(tables, argument - 1)) * 1099511628211UL);
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
            if (record.Dictionary == 0 || record.AsyncVariant)
                continue;

            int owner = tables.Index[record.DeclaringType] + 1;
            int group = canonical.Groups[owner - 1];
            ulong hash = 14695981039346656037UL;
            for (int j = record.Arguments.Start; j < record.Arguments.End; ++j)
                hash = unchecked((hash ^ (uint)canonical.Argument(tables, tables.Index[extraction.Generics.Arguments[j]])) * 1099511628211UL);
            var key = (group, record.Name, record.Arguments.Count, hash);
            heads.TryGetValue(key, out int first);
            for (int candidate = first; candidate != 0; candidate = next[candidate - 1]) {
                ref readonly var template = ref CollectionsMarshal.AsSpan(templates)[candidate - 1];
                ref readonly var method = ref template.Method;
                bool identity = record.MetadataOffset != 0 && method.Identity.MetadataOffset != 0
                    ? record.MetadataOffset == method.Identity.MetadataOffset
                    : EqualMethod(signatures, bindings, record.Signature, method.Identity.Signature);
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

    internal static bool EqualMethod(Signatures signatures, TypeBindings bindings, int left, int right) {
        var a = signatures.Methods[left];
        var b = signatures.Methods[right];
        uint ac = a.CallingConvention & ~0x10U;
        if (a.NativeConvention)
            ac = (a.CallingConvention & ~3U) != 0 ? uint.MaxValue : (a.CallingConvention & 2) == 0 ? 0x20U : 0U;

        uint bc = b.CallingConvention & ~0x10U;
        if (b.NativeConvention)
            bc = (b.CallingConvention & ~3U) != 0 ? uint.MaxValue : (b.CallingConvention & 2) == 0 ? 0x20U : 0U;

        if (left == 0 || right == 0 || ac == uint.MaxValue || ac != bc || a.GenericParameterCount != b.GenericParameterCount
            || a.Parameters.Count != b.Parameters.Count || a.Varargs.Count != 0 || b.Varargs.Count != 0)
            return false;

        for (int i = -1; i < a.Parameters.Count; ++i) {
            if (!EqualType(signatures, bindings, i == -1 ? a.ReturnType : signatures.Edges[a.Parameters.Start + i],
                i == -1 ? b.ReturnType : signatures.Edges[b.Parameters.Start + i]))
                return false;
        }
        return true;
    }

    private static bool EqualType(Signatures signatures, TypeBindings bindings, int left, int right) {
        if (left == right)
            return left != 0;

        var a = signatures.Nodes[left];
        var b = signatures.Nodes[right];
        if (a.Kind is SignatureKind.Named or SignatureKind.RuntimeType
            && b.Kind is SignatureKind.Named or SignatureKind.RuntimeType) {
            int binding = bindings.Resolve(left);
            return binding != 0 && binding == bindings.Resolve(right);
        }

        // Array bounds and signature modifiers are not encoded by a MethodTable
        // Compare their structure before using runtime identity for leaf types
        if (a.Kind != b.Kind || (a.Kind != SignatureKind.Modified && a.Value != b.Value)
            || a.Optional != b.Optional || a.NativeConvention != b.NativeConvention)
            return false;
        if (a.Kind is SignatureKind.TypeVariable or SignatureKind.MethodVariable)
            return true;
        if (a.Kind is not (SignatureKind.Instantiation or SignatureKind.SzArray or SignatureKind.Array
            or SignatureKind.ByReference or SignatureKind.Pointer or SignatureKind.FunctionPointer or SignatureKind.Modified))
            return false;
        if (!EqualType(signatures, bindings, a.Element, b.Element)
            || a.Arguments.Count != b.Arguments.Count || a.Varargs.Count != b.Varargs.Count
            || a.Sizes.Count != b.Sizes.Count || a.LowerBounds.Count != b.LowerBounds.Count)
            return false;
        if (a.Kind == SignatureKind.Modified && !EqualType(signatures, bindings, a.Value, b.Value))
            return false;

        var edges = CollectionsMarshal.AsSpan(signatures.Edges);
        if (!edges.Slice(a.Sizes.Start, a.Sizes.Count).SequenceEqual(edges.Slice(b.Sizes.Start, b.Sizes.Count))
            || !edges.Slice(a.LowerBounds.Start, a.LowerBounds.Count).SequenceEqual(edges.Slice(b.LowerBounds.Start, b.LowerBounds.Count)))
            return false;
        for (int i = 0; i < a.Arguments.Count; ++i) {
            if (!EqualType(signatures, bindings, edges[a.Arguments.Start + i], edges[b.Arguments.Start + i]))
                return false;
        }
        for (int i = 0; i < a.Varargs.Count; ++i) {
            if (!EqualType(signatures, bindings, edges[a.Varargs.Start + i], edges[b.Varargs.Start + i]))
                return false;
        }
        return true;
    }
}
