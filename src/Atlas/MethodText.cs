using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public readonly ref struct MethodRecord {
    private readonly Extraction source;
    internal bool IsFrom(Extraction extraction) => ReferenceEquals(source, extraction);
    public readonly ulong DeclaringType;
    public readonly ulong Entrypoint;
    public readonly ulong Dictionary;
    public readonly ulong InvokeStub;

    public readonly int Section;
    public readonly int Vertex;
    internal readonly int Signature;
    public SignatureMethod MethodSignature => source.Signatures.MethodSignatures[Signature];

    public readonly uint Flags;
    public readonly uint Token;
    public readonly uint MetadataOffset;
    public readonly uint NativeOffset;

    public readonly string Name;
    public readonly bool AsyncVariant;
    public readonly ReadOnlySpan<ulong> Arguments;

    public MethodRecord(Extraction extraction, int index) {
        source = extraction;
        if (index < extraction.Maps.Methods.Count) {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Maps.Methods)[index];
            Section        = (int)RtrSectionId.InvokeMap;
            Vertex         = entry.Vertex;

            DeclaringType  = entry.DeclaringType;
            Entrypoint     = entry.Entrypoint;
            InvokeStub     = entry.InvokeStub;

            Name           = entry.Name;

            Flags          = entry.Flags;
            MetadataOffset = entry.MetadataOffset;
            NativeOffset   = entry.NativeSignatureOffset;

            Signature = entry.Signature != 0
                ? entry.Signature
                : extraction.Layout.Method(NativeOffset).Signature;
            Arguments = CollectionsMarshal.AsSpan(extraction.Maps.GenericArguments)
                .Slice(entry.GenericArguments.Start, entry.GenericArguments.Count);
        } else {
            ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Generics.Methods)
                [index - extraction.Maps.Methods.Count];
            Section        = entry.Section;
            Vertex         = entry.Vertex;

            DeclaringType  = entry.DeclaringType;
            Entrypoint     = entry.Entrypoint;
            Dictionary     = entry.Dictionary;

            Name           = entry.Name;

            MetadataOffset = entry.MetadataOffset;
            NativeOffset   = entry.NativeOffset;
            Signature      = entry.Signature;

            Token          = entry.Token;
            AsyncVariant   = entry.AsyncVariant;

            Arguments = CollectionsMarshal.AsSpan(extraction.Generics.Arguments)
                .Slice(entry.Arguments.Start, entry.Arguments.Count);
        }
    }
}

public sealed class MethodText(Extraction extraction) {
    private readonly StringBuilder builder = new(512);
    private readonly Dictionary<int, string> signatureText = new();
    private string[] typeArguments = new string[16];
    private string[] methodArguments = new string[16];

    private SignatureArgument[] typeBindings = [];
    private SignatureArgument[] methodBindings = [];
    private int typeBindingCount;

    internal int SignatureIndex { get; private set; }
    public SignatureMethod Signature => extraction.Signatures.MethodSignatures[SignatureIndex];
    public bool SignatureComplete { get; private set; } = true;
    public SignatureContext Context => !SignatureComplete
        ? new(typeBindings.AsSpan(0, typeBindingCount), methodBindings.AsSpan(0, argumentCount))
        : throw new InvalidOperationException("The signature display was not abbreviated.");

    private char[] text = new char[512];
    private int ownerStart;
    private int ownerLength;
    private int argumentCount;

    public int NameLength { get; private set; }
    public ReadOnlySpan<char> Owner => text.AsSpan(ownerStart, ownerLength);
    public ReadOnlySpan<string> Arguments => methodArguments.AsSpan(0, argumentCount);

    public ReadOnlySpan<char> Render(scoped in MethodRecord entry, bool includeSignature = true) {
        if (!entry.IsFrom(extraction))
            throw new ArgumentException("The method belongs to a different extraction.", nameof(entry));

        var tables = extraction.Types;
        var names = extraction.Names.Values;

        int typeIndex = tables.Index[entry.DeclaringType];
        var arguments = tables.Types[typeIndex].Arguments;
        var typeAddresses = CollectionsMarshal.AsSpan(tables.Pointers).Slice(arguments.Start, arguments.Count);

        if (arguments.Count > typeArguments.Length)
            Array.Resize(ref typeArguments, arguments.Count);

        if (entry.Arguments.Length > methodArguments.Length)
            Array.Resize(ref methodArguments, entry.Arguments.Length);

        argumentCount = entry.Arguments.Length;
        SignatureIndex = includeSignature ? entry.Signature : 0;
        SignatureComplete = true;

        for (int i = 0; i < arguments.Count; ++i)
            typeArguments[i] = names[tables.Index[typeAddresses[i]]];

        for (int i = 0; i < entry.Arguments.Length; ++i)
            methodArguments[i] = names[tables.Index[entry.Arguments[i]]];

        builder.Clear();
        if (entry.AsyncVariant)
            builder.Append("async_variant::");

        ownerStart = builder.Length;
        ownerLength = names[typeIndex].Length;
        builder.Append(names[typeIndex])
            .Append("::")
            .Append(entry.Name);

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
        if (includeSignature) {
            SignatureComplete = entry.MethodSignature.Append(
                builder,
                typeArguments.AsSpan(0, arguments.Count),
                methodArguments.AsSpan(0, entry.Arguments.Length));
            if (!SignatureComplete) {
                PrepareContext(arguments.Count);

                for (int i = 0; i < arguments.Count; ++i)
                    typeBindings[i] = SignatureArgument.RuntimeType(typeAddresses[i], typeArguments[i]);

                for (int i = 0; i < argumentCount; ++i)
                    methodBindings[i] = SignatureArgument.RuntimeType(entry.Arguments[i], methodArguments[i]);
            }
        }

        return CopyText();
    }

    internal ReadOnlySpan<char> Render(in TraceMethod entry, bool includeSignature = true) {
        var signatures = extraction.Signatures;
        var parameters = CollectionsMarshal.AsSpan(extraction.Traces.ParameterNames);

        ref readonly var owner = ref signatures.Nodes[entry.DeclaringType];
        bool constructedOwner = owner.Kind == SignatureKind.Instantiation;
        var typeSignatures = constructedOwner
            ? signatures.Edges.Slice(owner.Arguments.Start, owner.Arguments.Count)
            : default;
        var typeParameters = constructedOwner
            ? default
            : parameters.Slice(entry.TypeParameterNames.Start, entry.TypeParameterNames.Count);
        int count = constructedOwner ? typeSignatures.Length : typeParameters.Length;

        if (count > typeArguments.Length)
            Array.Resize(ref typeArguments, count);

        argumentCount = entry.ParameterNames.Count;
        SignatureIndex = includeSignature ? entry.Signature : 0;
        SignatureComplete = true;
        if (argumentCount > methodArguments.Length)
            Array.Resize(ref methodArguments, argumentCount);

        parameters.Slice(entry.ParameterNames.Start, argumentCount).CopyTo(methodArguments);

        for (int i = 0; i < count; ++i) {
            if (constructedOwner) {
                typeArguments[i] = TypeName(typeSignatures[i]);
            } else {
                typeArguments[i] = typeParameters[i];
            }
        }

        builder.Clear();
        builder.Append("stacktrace::");
        ownerStart = builder.Length;
        signatures.Types[entry.DeclaringType].Append(builder);

        if (!constructedOwner && count != 0) {
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
        if (includeSignature && entry.Signature != 0) {
            SignatureComplete = signatures.MethodSignatures[entry.Signature].Append(
                builder,
                typeArguments.AsSpan(0, count),
                parameters.Slice(entry.ParameterNames.Start, entry.ParameterNames.Count));
            if (!SignatureComplete) {
                PrepareContext(count);

                for (int i = 0; i < count; ++i)
                    typeBindings[i] = constructedOwner
                        ? SignatureArgument.TypeSignature(signatures.Types[typeSignatures[i]], typeArguments[i])
                        : SignatureArgument.ParameterName(typeArguments[i]);

                for (int i = 0; i < argumentCount; ++i)
                    methodBindings[i] = SignatureArgument.ParameterName(methodArguments[i]);
            }
        }

        return CopyText();
    }

    internal ReadOnlySpan<char> Render(in MethodTemplate template, bool includeSignature = true) {
        var signatures = extraction.Signatures;
        var tables = extraction.Types;
        var names = extraction.Names.Values;

        ref readonly var entry = ref template.Method;
        ref readonly var owner = ref signatures.Nodes[entry.DeclaringType];
        bool constructedOwner = owner.Kind == SignatureKind.Instantiation;
        var typeArgs = constructedOwner
            ? owner.Arguments
            : owner.TypeAddress != 0
                ? tables.Types[tables.Index[owner.TypeAddress]].Arguments
                : default;
        var typeSignatures = constructedOwner
            ? signatures.Edges.Slice(typeArgs.Start, typeArgs.Count)
            : default;
        var typeAddresses = constructedOwner
            ? default
            : CollectionsMarshal.AsSpan(tables.Pointers).Slice(typeArgs.Start, typeArgs.Count);
        var methodSignatures = signatures.Edges.Slice(entry.Arguments.Start, entry.Arguments.Count);

        if (typeArgs.Count > typeArguments.Length)
            Array.Resize(ref typeArguments, typeArgs.Count);

        argumentCount = entry.Arguments.Count;
        SignatureIndex = includeSignature ? entry.Identity.Signature : 0;
        SignatureComplete = true;
        if (argumentCount > methodArguments.Length)
            Array.Resize(ref methodArguments, argumentCount);

        for (int i = 0; i < typeArgs.Count; ++i) {
            typeArguments[i] = constructedOwner
                ? TypeName(typeSignatures[i])
                : names[tables.Index[typeAddresses[i]]];
        }

        for (int i = 0; i < argumentCount; ++i)
            methodArguments[i] = TypeName(methodSignatures[i]);

        builder.Clear();
        builder.Append("template::");
        if (template.UniversalCanonical)
            builder.Append("universal::");

        if (template.AsyncVariant)
            builder.Append("async_variant::");

        if ((entry.Flags & 2) != 0)
            builder.Append("unboxing::");

        ownerStart = builder.Length;
        signatures.Types[entry.DeclaringType].Append(builder);
        ownerLength = builder.Length - ownerStart;

        builder.Append("::")
            .Append(entry.Identity.Name)
            .Append('<');

        for (int i = 0; i < argumentCount; ++i) {
            if (i != 0)
                builder.Append(',');

            builder.Append(methodArguments[i]);
        }

        builder.Append('>');

        NameLength = builder.Length;
        if (includeSignature) {
            SignatureComplete = signatures.MethodSignatures[entry.Identity.Signature].Append(
                builder,
                typeArguments.AsSpan(0, typeArgs.Count),
                Arguments);
            if (!SignatureComplete) {
                PrepareContext(typeArgs.Count);

                for (int i = 0; i < typeArgs.Count; ++i)
                    typeBindings[i] = constructedOwner
                        ? SignatureArgument.TypeSignature(signatures.Types[typeSignatures[i]], typeArguments[i])
                        : SignatureArgument.RuntimeType(typeAddresses[i], typeArguments[i]);

                for (int i = 0; i < argumentCount; ++i)
                    methodBindings[i] = SignatureArgument.TypeSignature(signatures.Types[methodSignatures[i]], methodArguments[i]);
            }
        }

        return CopyText();
    }

    private void PrepareContext(int typeCount) {
        typeBindingCount = typeCount;
        if (typeCount > typeBindings.Length)
            Array.Resize(ref typeBindings, typeCount);

        if (argumentCount > methodBindings.Length)
            Array.Resize(ref methodBindings, argumentCount);
    }

    private string TypeName(int signature) {
        ref var name = ref CollectionsMarshal.GetValueRefOrAddDefault(signatureText, signature, out bool known);
        if (!known)
            name = extraction.Signatures.Types[signature].Render();

        return name!;
    }

    private ReadOnlySpan<char> CopyText() {
        if (builder.Length > text.Length)
            Array.Resize(ref text, Math.Max(builder.Length, text.Length * 2));

        builder.CopyTo(0, text, 0, builder.Length);

        return text.AsSpan(0, builder.Length);
    }
}
