using System.Runtime.InteropServices;

namespace Atlas;

public readonly struct TypeTemplate(
    int vertex,
    ulong methodTable,
    uint layoutOffset,
    TemplateLayoutFacts facts,
    TemplateTypeSignature baseType = default,
    IndexRange interfaces = default) {
    public readonly TemplateLayoutFacts Facts = facts;
    public readonly int Vertex = vertex;
    public readonly ulong MethodTable = methodTable;
    public readonly uint LayoutOffset = layoutOffset;
    public readonly TemplateTypeSignature BaseType = baseType;
    public readonly IndexRange Interfaces = interfaces;
}

public readonly struct TemplateTypeSignature {
    public readonly int Offset;
    internal readonly int Signature;

    internal TemplateTypeSignature(int offset, int signature) {
        Offset = offset;
        Signature = signature;
    }
}

public struct MethodTemplate {
    public int Vertex;
    public uint LayoutOffset;
    public NativeMethodEntry Method;
    public bool UniversalCanonical;
    public bool AsyncVariant;
    public bool ReturnDroppingAsyncThunk;
}

public struct TemplateLayoutFacts {
    public uint NonGcStaticBytes;
    public uint GcStaticBytes;
    public uint ThreadStaticBytes;

    public ulong GcDescriptor;
    public ulong ThreadDescriptor;
    public ulong ClassConstructor;

    public static TemplateLayoutFacts Read(
        ReadOnlySpan<byte> data,
        uint offset,
        ReadOnlySpan<ulong> statics) {
        if (offset >= data.Length)
            throw new InvalidDataException("Template bag offset exceeds NativeLayout storage.");

        var facts = new TemplateLayoutFacts();
        var reader = new NativeReader(data, (int)offset);
        ulong seen = 0;

        while (true) {
            uint kind = reader.Unsigned();
            if (kind == 0)
                return facts;

            int field = kind switch {
                0x44 => 0,
                0x45 => 1,
                0x46 => 2,
                0x47 => 3,
                0x48 => 4,
                0x4e => 5,
                _ => -1
            };

            if (field >= 0) {
                ulong bit = 1UL << field;
                if ((seen & bit) != 0)
                    throw new InvalidDataException("Duplicate template bag element.");

                seen |= bit;
            }

            uint value = reader.Unsigned();

            switch (kind) {
                case 0x44:
                    facts.NonGcStaticBytes = value;
                    break;

                case 0x45:
                    facts.GcStaticBytes = value;
                    break;

                case 0x47:
                    facts.ThreadStaticBytes = value;
                    break;

                case 0x46:
                case 0x48:
                case 0x4e:
                    if (value >= statics.Length || statics[(int)value] == 0)
                        throw new InvalidDataException("Template static reference outside NativeStatics.");

                    if (kind == 0x46)
                        facts.GcDescriptor = statics[(int)value];
                    else if (kind == 0x48)
                        facts.ThreadDescriptor = statics[(int)value];
                    else
                        facts.ClassConstructor = statics[(int)value];

                    break;
            }
        }
    }
}

public sealed class TemplateMaps {
    internal readonly List<TypeTemplate> Types = new(64);
    internal readonly List<MethodTemplate> Methods = new(8192);
    internal readonly List<TemplateTypeSignature> Interfaces = new();

    public ReadOnlySpan<TypeTemplate> TypeEntries => CollectionsMarshal.AsSpan(Types);
    public ReadOnlySpan<MethodTemplate> MethodEntries => CollectionsMarshal.AsSpan(Methods);
    public ReadOnlySpan<TemplateTypeSignature> InterfaceEntries => CollectionsMarshal.AsSpan(Interfaces);

    internal void Read(
        PeImage image,
        ReadyToRun rtr,
        MetadataBuilder metadata,
        NativeLayout layout,
        ReadOnlySpan<ulong> fixups,
        ReadOnlySpan<ulong> staticReferences,
        MapFormat format,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        var storage = rtr.Find(RtrSectionId.NativeLayoutInfo);
        ulong layoutLength = storage.Length;

        ReadOnlySpan<RtrSectionId> templateMaps = [
            RtrSectionId.TypeTemplateMap,
            RtrSectionId.GenericMethodsTemplateMap
        ];

        foreach (var id in templateMaps) {
            var section = rtr.Find(id);
            var data = section.Length == 0 ? default : image.FileSpan(section.Start, checked((int)section.Length));
            var table = new NativeTable(data);

            while (table.MoveNext()) {
                cancellationToken.ThrowIfCancellationRequested();

                var reader = new NativeReader(data, table.Vertex);
                uint reference = reader.Unsigned();
                uint offset = reader.Unsigned();
                if (offset == uint.MaxValue)
                    throw new InvalidDataException("Template map contains an unresolved layout fixup.");

                if (offset >= layoutLength)
                    throw new InvalidDataException("Template layout offset exceeds NativeLayout storage.");

                if (id == RtrSectionId.TypeTemplateMap) {
                    if (reference >= fixups.Length || fixups[(int)reference] == 0)
                        throw new InvalidDataException("Type template refers outside CommonFixups or to null.");

                    var facts = TemplateLayoutFacts.Read(
                        image.FileSpan(storage.Start, checked((int)storage.Length)),
                        offset,
                        staticReferences);
                    if (facts.ClassConstructor != 0 && !image.IsExecutable(facts.ClassConstructor))
                        throw new InvalidDataException("Template class constructor is outside executable storage.");

                    if ((facts.GcDescriptor != 0 && !image.IsMapped(facts.GcDescriptor, 1))
                        || (facts.ThreadDescriptor != 0 && !image.IsMapped(facts.ThreadDescriptor, 1)))
                        throw new InvalidDataException("Template static descriptor is outside image storage.");

                    Types.Add(new TypeTemplate(table.Vertex, fixups[(int)reference], offset, facts));
                } else {
                    var entry = layout.MethodEntry(reference, metadata, format);
                    if (entry.Arguments.Count == 0)
                        throw new InvalidDataException("Generic method template has no instantiation.");

                    if (entry.Entrypoint != 0 && !image.IsExecutable(entry.Entrypoint))
                        throw new InvalidDataException("Method template entrypoint is outside executable storage.");

                    bool variant = (entry.Flags & 8) != 0;
                    if (variant && !rtr.Format.UniversalCanonicalMethods && !rtr.Format.AsyncMethodVariants)
                        throw new InvalidDataException("Method template has a reserved variant flag.");

                    if (variant && rtr.Format.UniversalCanonicalMethods && entry.Entrypoint == 0)
                        throw new InvalidDataException("Universal canonical method template has no entrypoint.");

                    Methods.Add(new MethodTemplate {
                        Vertex = table.Vertex,
                        LayoutOffset = offset,
                        Method = entry,
                        UniversalCanonical = variant && rtr.Format.UniversalCanonicalMethods,
                        AsyncVariant = variant && rtr.Format.AsyncMethodVariants,
                        ReturnDroppingAsyncThunk = (entry.Flags & 16) != 0
                    });
                }
            }
        }
    }

    internal void ReadSignatures(
        PeImage image,
        ReadyToRun header,
        NativeLayout native,
        CancellationToken cancellationToken = default) {
        var section = header.Find(RtrSectionId.NativeLayoutInfo);
        var data = section.Length == 0
            ? default
            : image.FileSpan(section.Start, checked((int)section.Length));

        for (int index = 0; index < Types.Count; ++index) {
            cancellationToken.ThrowIfCancellationRequested();

            var template = Types[index];
            var bag = new NativeReader(data, checked((int)template.LayoutOffset));
            var baseType = default(TemplateTypeSignature);
            var interfaces = default(IndexRange);
            uint seen = 0;

            while (true) {
                uint kind = bag.Unsigned();
                if (kind == 0)
                    break;

                bool fieldLayout = kind == 0x4b && header.Format.UniversalCanonicalMethods;
                bool methodSignatures = (kind is 0x4c or 0x51) && header.Format.LegacyTemplateMethodSignatures;
                if (kind is not (1 or 2) && !fieldLayout && !methodSignatures) {
                    bag.Unsigned();
                    continue;
                }

                uint bit = kind switch { 1 => 1, 2 => 2, 0x4b => 4, 0x4c => 8, 0x51 => 16, _ => 0 };
                if ((seen & bit) != 0)
                    throw new InvalidDataException("Duplicate template type relation.");

                seen |= bit;
                int origin = bag.Position;
                long target = (long)origin + bag.Signed();
                if (target < 0 || target >= data.Length)
                    throw new InvalidDataException("Template type relation is outside NativeLayout storage.");

                var reader = new NativeReader(data, (int)target);
                if (kind == 1) {
                    baseType = new(reader.Position, native.TypeSignature(ref reader));
                    if (baseType.Signature == 0)
                        throw new InvalidDataException("Template base-type signature is null.");
                } else if (kind == 0x51) {
                    native.MethodSignature((uint)reader.Position);
                } else {
                    int count = checked((int)reader.Unsigned());
                    int minimumBytes = kind == 2 ? 1 : 2;
                    if (count > reader.Remaining / minimumBytes)
                        throw new InvalidDataException(kind == 2
                            ? "Template interface count exceeds NativeLayout storage."
                            : "Template signature count exceeds NativeLayout storage.");

                    int first = Interfaces.Count;
                    if (kind == 2)
                        Interfaces.EnsureCapacity(checked(first + count));

                    for (int item = 0; item < count; ++item) {
                        cancellationToken.ThrowIfCancellationRequested();

                        if (kind == 0x4c) {
                            reader.Unsigned(); // Vtable slot and sealed-slot bit.
                            int signatureOrigin = reader.Position;
                            long signatureTarget = (long)signatureOrigin + reader.Signed();
                            if (signatureTarget < 0 || signatureTarget >= data.Length)
                                throw new InvalidDataException("Template method signature is outside NativeLayout storage.");
                            native.MethodSignature((uint)signatureTarget);
                        } else {
                            int offset = reader.Position;
                            int signature = native.TypeSignature(ref reader);
                            if (kind == 2)
                                Interfaces.Add(new(offset, signature));
                            else {
                                if (signature == 0)
                                    throw new InvalidDataException("Template field signature is null.");
                                reader.Unsigned(); // Field storage; independent of its type root.
                            }
                        }
                    }

                    if (kind == 2)
                        interfaces = new(first, count);
                }
            }

            Types[index] = new(template.Vertex, template.MethodTable, template.LayoutOffset,
                template.Facts, baseType, interfaces);
        }
    }

    internal void ValidateRelations(
        MethodTables tables,
        SignatureBuilder signatures,
        CancellationToken cancellationToken = default) {
        var pending = new List<int>();
        var visited = new HashSet<int>();

        foreach (ref readonly var template in CollectionsMarshal.AsSpan(Types)) {
            cancellationToken.ThrowIfCancellationRequested();

            ref readonly var owner = ref CollectionsMarshal.AsSpan(tables.Types)[tables.Index[template.MethodTable]];
            int arity = owner.IsGeneric ? owner.Arguments.Count
                : owner.Kind == 2 ? 1 : owner.GenericArity;

            pending.Clear();
            visited.Clear();

            if (template.BaseType.Signature != 0) {
                ValidateDeclaration(template.BaseType.Signature, interfaceType: false, tables, signatures);
                pending.Add(template.BaseType.Signature);
            }

            for (int index = template.Interfaces.Start; index < template.Interfaces.End; ++index) {
                int signature = Interfaces[index].Signature;
                ValidateDeclaration(signature, interfaceType: true, tables, signatures);
                pending.Add(signature);
            }

            // Canonical templates reserve null interface entries. The bag supplies
            // their signatures, not addresses that can be matched to those entries.
            for (int cursor = 0; cursor < pending.Count; ++cursor) {
                cancellationToken.ThrowIfCancellationRequested();

                int signature = pending[cursor];
                if (!visited.Add(signature))
                    continue;

                ref readonly var node = ref signatures.Nodes[signature];
                if (node.Kind == SignatureKind.Unknown)
                    throw new InvalidDataException("Template signature contains a null type.");

                if (node.Kind == SignatureKind.MethodVariable
                    || (node.Kind == SignatureKind.TypeVariable && node.Value >= arity))
                    throw new InvalidDataException("Template signature variable is outside its type owner.");

                if (node.Element != 0)
                    pending.Add(node.Element);

                for (int edge = node.Arguments.Start; edge < node.Arguments.End; ++edge)
                    pending.Add(signatures.Edges[edge]);

                for (int edge = node.Varargs.Start; edge < node.Varargs.End; ++edge)
                    pending.Add(signatures.Edges[edge]);
            }
        }
    }

    private static void ValidateDeclaration(
        int signature,
        bool interfaceType,
        MethodTables tables,
        SignatureBuilder signatures) {
        var root = signatures.Nodes[signature];
        bool instantiated = root.Kind == SignatureKind.Instantiation;
        var definition = instantiated ? signatures.Nodes[root.Element] : root;
        bool valid;

        if (definition.TypeAddress != 0) {
            var type = tables.Types[tables.Index[definition.TypeAddress]];
            valid = type.ElementType == (interfaceType ? 0x15 : 0x14)
                && (instantiated ? type.Kind == 3 && type.GenericArity == root.Arguments.Count
                    : type.Kind == 0);
        } else {
            valid = !interfaceType && !instantiated && definition.Kind == SignatureKind.Named
                && definition.Name is "System.Object" or "System.ValueType" or "System.Enum"
                    or "System.Array" or "System.MulticastDelegate" or "System.Exception";
        }

        if (!valid)
            throw new InvalidDataException(interfaceType
                ? "Template interface signature has no interface MethodTable."
                : "Template base-type signature is not a class type.");
    }
}
