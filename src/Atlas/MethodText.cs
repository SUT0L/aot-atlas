using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public readonly ref struct MethodRecord {
    public readonly ulong DeclaringType, Entrypoint, Dictionary, InvokeStub;
    public readonly int Section, Vertex, Signature;
    public readonly uint Flags, Token, MetadataOffset, NativeOffset;
    public readonly string Name;
    public readonly bool AsyncVariant;
    public readonly ReadOnlySpan<ulong> Arguments;

    public MethodRecord(Extraction extraction, int index) {
        if (index < extraction.Maps.Methods.Count) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Maps.Methods)[index];
            Section = 306;
            Vertex = entry.Vertex;
            DeclaringType = entry.DeclaringType;
            Entrypoint = entry.Entrypoint;
            InvokeStub = entry.InvokeStub;
            Name = entry.Name;
            Flags = entry.Flags;
            MetadataOffset = entry.MetadataOffset;
            NativeOffset = entry.NativeSignatureOffset;
            Signature = entry.Signature != 0 ? entry.Signature : extraction.Layout.Method(NativeOffset).Signature;
            Arguments = CollectionsMarshal.AsSpan(extraction.Maps.GenericArguments).Slice(entry.GenericArguments.Start, entry.GenericArguments.Count);
        } else {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Generics.Methods)[index - extraction.Maps.Methods.Count];
            Section = entry.Section;
            Vertex = entry.Vertex;
            DeclaringType = entry.DeclaringType;
            Entrypoint = entry.Entrypoint;
            Dictionary = entry.Dictionary;
            Name = entry.Name;
            MetadataOffset = entry.MetadataOffset;
            NativeOffset = entry.NativeOffset;
            Signature = entry.Signature;
            Token = entry.Token;
            AsyncVariant = entry.AsyncVariant;
            Arguments = CollectionsMarshal.AsSpan(extraction.Generics.Arguments).Slice(entry.Arguments.Start, entry.Arguments.Count);
        }
    }
}

public sealed class MethodText(Extraction extraction) {
    private readonly StringBuilder builder = new(512);
    private readonly Dictionary<int, string> signatureText = new();
    private string[] typeArguments = new string[16], methodArguments = new string[16];
    private char[] text = new char[512];
    private int ownerStart, ownerLength, argumentCount;
    public int NameLength;
    public ReadOnlySpan<char> Owner => text.AsSpan(ownerStart, ownerLength);
    public ReadOnlySpan<string> Arguments => methodArguments.AsSpan(0, argumentCount);

    public ReadOnlySpan<char> Render(scoped in MethodRecord entry, bool includeSignature = true) {
        var tables = extraction.Types;
        var names = extraction.Names.Values;
        int typeIndex = tables.Index[entry.DeclaringType];
        var arguments = tables.Types[typeIndex].Arguments;
        if (arguments.Count > typeArguments.Length)
            Array.Resize(ref typeArguments, arguments.Count);
        if (entry.Arguments.Length > methodArguments.Length)
            Array.Resize(ref methodArguments, entry.Arguments.Length);
        argumentCount = entry.Arguments.Length;

        for (int i = 0; i < arguments.Count; ++i)
            typeArguments[i] = names[tables.Index[tables.Pointers[arguments.Start + i]]];
        for (int i = 0; i < entry.Arguments.Length; ++i)
            methodArguments[i] = names[tables.Index[entry.Arguments[i]]];

        builder.Clear();
        if (entry.AsyncVariant)
            builder.Append("async_variant::");

        ownerStart = builder.Length;
        ownerLength = names[typeIndex].Length;
        builder.Append(names[typeIndex]).Append("::").Append(entry.Name);
        if (entry.Arguments.Length != 0) {
            builder.Append('<');
            for (int i = 0; i < entry.Arguments.Length; ++i) {
                if (i != 0)
                    builder.Append(',');
                builder.Append(methodArguments[i]);
            }
            builder.Append('>');
        }

        NameLength = builder.Length;
        if (includeSignature)
            extraction.Metadata.Signatures.AppendMethod(builder, entry.Signature,
                typeArguments.AsSpan(0, arguments.Count), methodArguments.AsSpan(0, entry.Arguments.Length));
        return CopyText();
    }

    public ReadOnlySpan<char> Render(in TraceMethod entry, bool includeSignature = true) {
        var signatures = extraction.Metadata.Signatures;
        var parameters = CollectionsMarshal.AsSpan(extraction.Traces.ParameterNames);
        ref readonly var owner = ref CollectionsMarshal.AsSpan(signatures.Nodes)[entry.DeclaringType];
        int count = owner.Kind == SignatureKind.Instantiation ? owner.Arguments.Count : entry.TypeParameterNames.Count;
        if (count > typeArguments.Length)
            Array.Resize(ref typeArguments, count);
        argumentCount = entry.ParameterNames.Count;
        if (argumentCount > methodArguments.Length)
            Array.Resize(ref methodArguments, argumentCount);
        parameters.Slice(entry.ParameterNames.Start, argumentCount).CopyTo(methodArguments);

        for (int i = 0; i < count; ++i) {
            if (owner.Kind == SignatureKind.Instantiation) {
                typeArguments[i] = TypeName(signatures.Edges[owner.Arguments.Start + i]);
            } else {
                typeArguments[i] = parameters[entry.TypeParameterNames.Start + i];
            }
        }

        builder.Clear();
        builder.Append("stacktrace::");
        ownerStart = builder.Length;
        signatures.AppendType(builder, entry.DeclaringType);
        if (owner.Kind != SignatureKind.Instantiation && count != 0) {
            builder.Append('<');
            for (int i = 0; i < count; ++i) {
                if (i != 0)
                    builder.Append(',');
                builder.Append(typeArguments[i]);
            }
            builder.Append('>');
        }

        ownerLength = builder.Length - ownerStart;
        builder.Append("::").Append(entry.Name.Length == 0 ? "??" : entry.Name);
        if (entry.ParameterNames.Count != 0) {
            builder.Append('<');
            for (int i = entry.ParameterNames.Start; i < entry.ParameterNames.End; ++i) {
                if (i != entry.ParameterNames.Start)
                    builder.Append(',');
                builder.Append(parameters[i]);
            }
            builder.Append('>');
        }

        NameLength = builder.Length;
        if (includeSignature && entry.Signature != 0)
            signatures.AppendMethod(builder, entry.Signature, typeArguments.AsSpan(0, count),
                parameters.Slice(entry.ParameterNames.Start, entry.ParameterNames.Count));
        return CopyText();
    }

    public ReadOnlySpan<char> Render(in MethodTemplate template, bool includeSignature = true) {
        var signatures = extraction.Metadata.Signatures;
        var tables = extraction.Types;
        var names = extraction.Names.Values;
        ref readonly var entry = ref template.Method;
        ref readonly var owner = ref CollectionsMarshal.AsSpan(signatures.Nodes)[entry.DeclaringType];
        var typeArgs = owner.Kind == SignatureKind.Instantiation ? owner.Arguments
            : owner.TypeAddress != 0 ? tables.Types[tables.Index[owner.TypeAddress]].Arguments : default;

        if (typeArgs.Count > typeArguments.Length)
            Array.Resize(ref typeArguments, typeArgs.Count);
        argumentCount = entry.Arguments.Count;
        if (argumentCount > methodArguments.Length)
            Array.Resize(ref methodArguments, argumentCount);

        for (int i = 0; i < typeArgs.Count; ++i) {
            int index = typeArgs.Start + i;
            typeArguments[i] = owner.Kind == SignatureKind.Instantiation ? TypeName(signatures.Edges[index])
                : names[tables.Index[tables.Pointers[index]]];
        }
        for (int i = 0; i < argumentCount; ++i)
            methodArguments[i] = TypeName(signatures.Edges[entry.Arguments.Start + i]);

        builder.Clear();
        builder.Append("template::");
        if (template.UniversalCanonical)
            builder.Append("universal::");
        if (template.AsyncVariant)
            builder.Append("async_variant::");
        if ((entry.Flags & 2) != 0)
            builder.Append("unboxing::");

        ownerStart = builder.Length;
        signatures.AppendType(builder, entry.DeclaringType);
        ownerLength = builder.Length - ownerStart;
        builder.Append("::").Append(entry.Identity.Name).Append('<');
        for (int i = 0; i < argumentCount; ++i) {
            if (i != 0)
                builder.Append(',');
            builder.Append(methodArguments[i]);
        }
        builder.Append('>');

        NameLength = builder.Length;
        if (includeSignature)
            signatures.AppendMethod(builder, entry.Identity.Signature, typeArguments.AsSpan(0, typeArgs.Count), Arguments);
        return CopyText();
    }

    private string TypeName(int signature) {
        ref var name = ref CollectionsMarshal.GetValueRefOrAddDefault(signatureText, signature, out bool known);
        if (!known)
            name = extraction.Metadata.Signatures.RenderType(signature);
        return name!;
    }

    private ReadOnlySpan<char> CopyText() {
        if (builder.Length > text.Length)
            Array.Resize(ref text, Math.Max(builder.Length, text.Length * 2));
        builder.CopyTo(0, text, 0, builder.Length);
        return text.AsSpan(0, builder.Length);
    }
}
