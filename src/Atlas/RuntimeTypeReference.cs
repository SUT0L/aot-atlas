namespace Atlas;

public readonly struct RuntimeTypeReference {
    private readonly RuntimeTypeIndex? publication;
    internal int Binding { get; }

    internal RuntimeTypeReference(RuntimeTypeIndex publication, int binding) {
        this.publication = binding == 0 ? null : publication;
        Binding = binding;
    }

    public bool IsResolved => publication is not null;
    public ulong Address => publication is null ? 0 : publication.Address(Binding);

    internal int For(RuntimeTypeIndex owner) {
        if (publication is null)
            return 0;

        if (!ReferenceEquals(publication, owner))
            throw new ArgumentException("The runtime type belongs to a different binding publication.");

        return Binding;
    }
}
