using System.Runtime.InteropServices;

namespace Atlas;

public enum GvmOutcome : byte {
    Method,
    Diamond,
    Reabstraction
}

public struct GvmMethod {
    public ulong Owner;
    public uint Token;
    public MethodIdentity Identity;
}

public struct GvmClassEntry {
    public int Vertex;
    public int Length;

    public uint Hash;
    public GvmMethod Calling;
    public GvmMethod Target;
}

public struct GvmInterfaceEntry {
    public int Vertex;
    public int Length;

    public uint Hash;
    public GvmMethod Calling;
    public IndexRange Implementations;
}

public struct GvmImplementation {
    public GvmMethod Target;
    public GvmOutcome Outcome;
    public IndexRange Types;
}

public readonly struct GvmProvidedType(ulong type, IndexRange signatures) {
    public readonly ulong Type = type;
    public readonly IndexRange Signatures = signatures;
}

public readonly struct GvmInterfaceSignature {
    public readonly uint Offset;
    internal readonly int Signature;

    internal GvmInterfaceSignature(uint offset, int signature) {
        Offset = offset;
        Signature = signature;
    }
}

public sealed class GvmTables {
    internal readonly List<GvmClassEntry> Classes = new(1024);
    internal readonly List<GvmInterfaceEntry> Interfaces = new(1024);
    internal readonly List<GvmImplementation> Implementations = new(2048);
    internal readonly List<GvmProvidedType> Types = new(4096);
    internal readonly List<GvmInterfaceSignature> Signatures = new(4096);

    public ReadOnlySpan<GvmClassEntry> ClassEntries => CollectionsMarshal.AsSpan(Classes);
    public ReadOnlySpan<GvmInterfaceEntry> InterfaceEntries => CollectionsMarshal.AsSpan(Interfaces);
    public ReadOnlySpan<GvmImplementation> ImplementationEntries => CollectionsMarshal.AsSpan(Implementations);
    public ReadOnlySpan<GvmProvidedType> TypeEntries => CollectionsMarshal.AsSpan(Types);
    public ReadOnlySpan<GvmInterfaceSignature> InterfaceSignatures => CollectionsMarshal.AsSpan(Signatures);

    private uint classHashMask;
    private uint interfaceHashMask;

    internal void Read(
        PeImage image,
        ReadyToRun rtr,
        Metadata metadata,
        NativeLayout layout,
        ReadOnlySpan<ulong> fixups,
        MapFormat format,
        MethodTables tables,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var section = rtr.Find(RtrSectionId.GenericVirtualMethodTable);
        var data = section.Length == 0
            ? default
            : image.FileSpan(section.Start, checked((int)section.Length));
        var table = new NativeTable(data);
        classHashMask = ((uint)table.BucketMask << 8) | 255;

        while (table.MoveNext()) {
            cancellationToken.ThrowIfCancellationRequested();

            var reader = new NativeReader(data, table.Vertex);
            GvmClassEntry entry = new() {
                Vertex = table.Vertex,
                Hash = ((uint)table.Bucket << 8) | table.LowHash
            };

            entry.Calling.Owner = Reference(ref reader, fixups, tables);
            entry.Target.Owner = Reference(ref reader, fixups, tables);
            entry.Calling.Token = reader.Unsigned();
            entry.Target.Token = reader.Unsigned();

            entry.Calling.Identity = MethodIdentity.Read(entry.Calling.Token, metadata, layout, format);
            entry.Target.Identity = MethodIdentity.Read(entry.Target.Token, metadata, layout, format);

            int arity = metadata.SignatureBuilder.Methods[entry.Calling.Identity.Signature].GenericParameterCount;
            if (arity == 0 || metadata.SignatureBuilder.Methods[entry.Target.Identity.Signature].GenericParameterCount != arity)
                throw new InvalidDataException("Class GVM methods have incompatible generic arities.");

            entry.Length = reader.Position - entry.Vertex;
            Classes.Add(entry);
        }

        section = rtr.Find(RtrSectionId.NativeLayoutInfo);
        var nativeData = section.Length == 0
            ? default
            : image.FileSpan(section.Start, checked((int)section.Length));

        section = rtr.Find(RtrSectionId.InterfaceGenericVirtualMethodTable);
        data = section.Length == 0
            ? default
            : image.FileSpan(section.Start, checked((int)section.Length));
        table = new NativeTable(data);
        interfaceHashMask = ((uint)table.BucketMask << 8) | 255;

        while (table.MoveNext()) {
            cancellationToken.ThrowIfCancellationRequested();

            var reader = new NativeReader(data, table.Vertex);
            GvmInterfaceEntry entry = new() {
                Vertex = table.Vertex,
                Hash = ((uint)table.Bucket << 8) | table.LowHash
            };

            entry.Calling.Owner = Reference(ref reader, fixups, tables);
            entry.Calling.Token = reader.Unsigned();
            entry.Calling.Identity = MethodIdentity.Read(entry.Calling.Token, metadata, layout, format);

            int arity = metadata.SignatureBuilder.Methods[entry.Calling.Identity.Signature].GenericParameterCount;
            if (arity == 0)
                throw new InvalidDataException("Interface GVM declaration has no generic parameters.");

            int count = checked((int)reader.Unsigned());
            if (count > reader.Remaining / 2)
                throw new InvalidDataException("Interface GVM implementations exceed storage.");

            entry.Implementations = new IndexRange(Implementations.Count, count);
            Implementations.EnsureCapacity(checked(Implementations.Count + count));

            for (int i = 0; i < count; ++i) {
                GvmImplementation implementation = new();
                implementation.Target.Token = reader.Unsigned();
                if (implementation.Target.Token >= 0xFFFFFFFE) {
                    implementation.Outcome = implementation.Target.Token == uint.MaxValue
                        ? GvmOutcome.Diamond
                        : GvmOutcome.Reabstraction;
                } else {
                    implementation.Target.Owner = Reference(ref reader, fixups, tables);
                    implementation.Target.Identity = MethodIdentity.Read(
                        implementation.Target.Token,
                        metadata,
                        layout,
                        format);
                    if (metadata.SignatureBuilder.Methods[implementation.Target.Identity.Signature]
                        .GenericParameterCount != arity)
                        throw new InvalidDataException("Interface GVM implementation has an incompatible generic arity.");
                }

                // Error outcomes still carry the complete list of affected types and interface signatures
                // They are dispatch rules
                int typeCount = checked((int)reader.Unsigned());
                if (typeCount > reader.Remaining / 2)
                    throw new InvalidDataException("Interface GVM provided types exceed storage.");

                implementation.Types = new IndexRange(Types.Count, typeCount);
                Types.EnsureCapacity(checked(Types.Count + typeCount));

                for (int j = 0; j < typeCount; ++j) {
                    ulong type = Reference(ref reader, fixups, tables);
                    int signatureCount = checked((int)reader.Unsigned());
                    if (signatureCount > reader.Remaining)
                        throw new InvalidDataException("Interface GVM signatures exceed storage.");

                    var signatures = new IndexRange(Signatures.Count, signatureCount);
                    Signatures.EnsureCapacity(checked(Signatures.Count + signatureCount));

                    for (int k = 0; k < signatureCount; ++k) {
                        uint offset = reader.Unsigned();
                        var signatureReader = new NativeReader(nativeData, checked((int)offset));
                        Signatures.Add(new GvmInterfaceSignature(offset, layout.TypeSignature(ref signatureReader)));
                    }

                    Types.Add(new GvmProvidedType(type, signatures));
                }

                Implementations.Add(implementation);
            }

            entry.Length = reader.Position - entry.Vertex;
            Interfaces.Add(entry);
        }
    }

    internal void Bind(MethodTables tables, SignatureBuilder signatures, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var types = CollectionsMarshal.AsSpan(tables.Types);

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Classes)) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var caller = ref types[tables.Index[entry.Calling.Owner]];
            ref readonly var target = ref types[tables.Index[entry.Target.Owner]];
            uint hash = ((caller.Hash << 13) ^ caller.Hash) ^ target.Hash;
            if (entry.Hash != (hash & classHashMask))
                throw new InvalidDataException("Class GVM hash does not match its runtime lookup bucket.");

            if (caller.ElementType == 0x15 || target.ElementType == 0x15)
                throw new InvalidDataException("Class GVM table contains an interface declaration or target.");
        }

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Interfaces)) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var caller = ref types[tables.Index[entry.Calling.Owner]];
            if (entry.Hash != (caller.Hash & interfaceHashMask))
                throw new InvalidDataException("Interface GVM hash does not match its runtime lookup bucket.");

            if (caller.ElementType != 0x15)
                throw new InvalidDataException("Interface GVM declaration is not an interface.");
        }

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Types)) {
            ref readonly var type = ref types[tables.Index[entry.Type]];
            if (type.ElementType == 0x15)
                throw new InvalidDataException("Interface GVM provided type is itself an interface.");
        }

        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(Signatures)) {
            var node = signatures.Nodes[entry.Signature];
            if (node.Kind == SignatureKind.Instantiation)
                node = signatures.Nodes[node.Element];

            if (node.TypeAddress == 0 || types[tables.Index[node.TypeAddress]].ElementType != 0x15)
                throw new InvalidDataException("Interface GVM signature has no interface MethodTable.");
        }
    }

    private static ulong Reference(ref NativeReader reader, ReadOnlySpan<ulong> fixups, MethodTables tables) {
        uint index = reader.Unsigned();
        if (index >= fixups.Length || fixups[(int)index] == 0)
            throw new InvalidDataException("GVM table refers outside CommonFixups or to null.");

        ulong address = fixups[(int)index];
        tables.Add(address, TypeEvidence.GenericVirtualMethod);

        return address;
    }
}
