namespace Atlas;

public sealed class RuntimeTypePublication {
    private readonly MethodTable[] types;
    private readonly ulong[] pointers;
    private readonly byte[] variances;
    private readonly Dictionary<ulong, int> addresses;

    internal RuntimeTypePublication(List<MethodTable> types, List<ulong> pointers, List<byte> variances) {
        this.types = types.ToArray();
        this.pointers = pointers.ToArray();
        this.variances = variances.ToArray();
        addresses = new(types.Count);

        for (int i = 0; i < types.Count; ++i)
            addresses.Add(types[i].Address, i);
    }

    public ReadOnlySpan<MethodTable> TypeEntries => types;
    public ReadOnlySpan<ulong> PointerValues => pointers;
    public ReadOnlySpan<byte> VarianceValues => variances;
    public MethodTable AtAddress(ulong address) => types[addresses[address]];

    public ReadOnlySpan<ulong> ArgumentsOf(ulong address) {
        var range = AtAddress(address).Arguments;
        return pointers.AsSpan(range.Start, range.Count);
    }
}

public sealed class MethodTableBuilder {
    private MethodTables draft = new();
    private bool manual;
    private bool native;

    public void Root(ulong address, TypeEvidence evidence = TypeEvidence.TypeMap) {
        if (manual)
            throw new InvalidOperationException("Manually constructed runtime types cannot acquire native roots.");

        ArgumentOutOfRangeException.ThrowIfZero(address);
        draft.Types.EnsureCapacity(checked(draft.Types.Count + 1));
        draft.Index.EnsureCapacity(checked(draft.Index.Count + 1));
        draft.Add(address, evidence);
        native = true;
    }

    public void Read(PeImage image, ReadyToRun header, RuntimeMemory memory) {
        if (manual)
            throw new InvalidOperationException("Manually constructed runtime types cannot be decoded from an image.");

        header = header.ValidateSource(image);

        var working = draft.Fork();
        working.Read(image, header, memory);
        draft = working;
        native = true;
    }

    public void Type(
        MethodTable value,
        ReadOnlySpan<ulong> arguments = default,
        ReadOnlySpan<ulong> vtable = default,
        ReadOnlySpan<ulong> interfaces = default,
        ReadOnlySpan<byte> variance = default) {
        if (native)
            throw new InvalidOperationException("Native runtime roots cannot acquire manually constructed rows.");

        ArgumentOutOfRangeException.ThrowIfZero(value.Address);

        if (draft.Index.ContainsKey(value.Address))
            throw new ArgumentException("The runtime type address is already present.", nameof(value));

        if (!value.IsGeneric && !arguments.IsEmpty)
            throw new ArgumentException("Only a generic runtime type can have type arguments.", nameof(arguments));

        if (!variance.IsEmpty && variance.Length != arguments.Length)
            throw new ArgumentException("Variance and type argument counts differ.", nameof(variance));

        value.VtableCount = checked((ushort)vtable.Length);
        value.InterfaceCount = checked((ushort)interfaces.Length);
        value.GenericArity = checked((ushort)(value.IsGeneric ? arguments.Length : value.GenericArity));
        int pointerCount = checked(arguments.Length + vtable.Length + interfaces.Length);
        draft.Types.EnsureCapacity(checked(draft.Types.Count + 1));
        draft.Index.EnsureCapacity(checked(draft.Index.Count + 1));
        draft.Pointers.EnsureCapacity(checked(draft.Pointers.Count + pointerCount));
        draft.Variances.EnsureCapacity(checked(draft.Variances.Count + variance.Length));
        value.Vtable = Append(vtable);
        value.Interfaces = Append(interfaces);
        value.Arguments = Append(arguments);
        value.Variance = new(draft.Variances.Count, variance.Length);

        foreach (byte item in variance)
            draft.Variances.Add(item);

        draft.Index.Add(value.Address, draft.Types.Count);
        draft.Types.Add(value);
        draft.InvalidatePublication();
        draft.CompleteManualTypes();
        manual = true;
    }

    private IndexRange Append(ReadOnlySpan<ulong> values) {
        var range = new IndexRange(draft.Pointers.Count, values.Length);

        foreach (ulong value in values)
            draft.Pointers.Add(value);

        return range;
    }

    public RuntimeTypePublication Publish() {
        if (!draft.IsComplete)
            throw new InvalidOperationException("Native runtime roots must be decoded before publication.");

        if (manual && !draft.HasPublication) {
            foreach (var type in draft.Types) {
                if (type.IsGeneric) {
                    if (!draft.Index.TryGetValue(type.GenericDefinition, out int definition)
                        || draft.Types[definition].Kind != 3
                        || draft.Types[definition].GenericArity != type.Arguments.Count)
                        throw new InvalidOperationException("A constructed runtime type requires its matching generic definition.");
                }

                int count = MethodTables.IdentityDependencyCount(type);

                for (int i = 0; i < count; ++i) {
                    if (!draft.Index.ContainsKey(draft.IdentityDependency(type, i)))
                        throw new InvalidOperationException("A runtime type identity refers to an undeclared type address.");
                }

                if (type.Kind == 0 && type.RelatedType != 0 && !draft.Index.ContainsKey(type.RelatedType))
                    throw new InvalidOperationException("A runtime base type refers to an undeclared type address.");
            }

            draft.ValidateBaseTypes();
            draft.ValidateIdentityTypes();
        }

        return draft.Publish();
    }
}
