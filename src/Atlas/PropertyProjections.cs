using System.Runtime.InteropServices;

namespace Atlas;

public enum PropertyOrigin : byte {
    Direct,
    Canonical,
    Interface,
    Base
}

public enum PropertyRejection : byte {
    UnsupportedAbi,
    UnsupportedCode,
    UnknownStorage,
    OutsideLayout,
    UnknownGc,
    GcMismatch,
    ReferenceHelper,
    ConflictingAccessors,
    AmbiguousIdentity,
    CanonicalConflict,
    Count
}

public struct PropertyProjection {
    internal int Owner;
    internal int Contract;
    internal int SourceOwner;

    internal int Signature;
    public int Offset;

    public uint Property;
    public uint Size;

    public uint GetterMethod;
    public uint SetterMethod;

    public ulong Getter;
    public ulong Setter;

    public AbiValue Storage;
    public PropertyOrigin Origin;
    public bool ByReference;
}

public sealed class PropertyProjections {
    public Signatures Signatures { get; }
    private readonly TypeBindings bindings;
    public TypeBindings Bindings => bindings;

    public readonly MetadataMembers Members;
    internal readonly List<PropertyProjection> Projections = new();
    internal readonly int[] Rejected = new int[(int)PropertyRejection.Count];
    internal readonly PropertyFunction[] Functions;
    public ReadOnlySpan<PropertyProjection> ProjectionEntries => CollectionsMarshal.AsSpan(Projections);
    public ReadOnlySpan<int> RejectionCounts => Rejected;
    public ReadOnlySpan<PropertyFunction> FunctionEntries => Functions;

    public int LegacyIdentities { get; internal set; }
    public int LegacyMatches { get; internal set; }
    public int UnjoinedDispatch { get; internal set; }

    public RuntimeTypeReference OwnerAt(int position) => extraction.RuntimeTypeAt(Projections[position].Owner);
    public RuntimeTypeReference ContractAt(int position) => extraction.RuntimeTypeAt(Projections[position].Contract);
    public RuntimeTypeReference SourceOwnerAt(int position) => extraction.RuntimeTypeAt(Projections[position].SourceOwner);
    public SignatureType PropertyTypeAt(int position) => Signatures.Types[Projections[position].Signature];
    public RuntimeTypeReference StorageTypeAt(int position) {
        int binding = Projections[position].Storage.Binding;
        return binding == 0 ? default : extraction.RuntimeTypeAt(binding - 1);
    }

    private readonly Extraction extraction;
    private readonly Metadata metadata;
    private readonly CancellationToken cancellationToken;
    private readonly uint[] definitions;
    private readonly IndexRange[] gc;
    private readonly uint pointerFlag;
    private readonly Dictionary<(uint Owner, uint Method), int> accessorHeads = new();
    private readonly Dictionary<uint, IndexRange> ownerAccessors = new();
    private readonly List<Accessor> accessors = new();
    private readonly PropertyAccessCode scanner;

    private struct Accessor {
        internal uint Property;
        internal uint Method;
        internal uint Semantics;

        internal int Next;
    }

    private readonly record struct SlotProperty(int Contract, ushort Slot, int Accessor);

    public PropertyProjections(
        Extraction extraction,
        ManagedAbi abi,
        CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        if (!abi.IsFrom(extraction))
            throw new ArgumentException("The ABI belongs to a different extraction.", nameof(abi));

        this.extraction = extraction;
        this.cancellationToken = cancellationToken;
        metadata = extraction.Metadata;
        Members = metadata.Members;
        Signatures = metadata.PublishedSignatures;
        bindings = extraction.Bindings;
        Projections.EnsureCapacity(Members.Properties.Count);
        accessors.EnsureCapacity(Members.Accessors.Length);

        scanner = new PropertyAccessCode(extraction.Image);

        // Index metadata definitions and GC layouts by runtime owner.
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        int count = types.Length;

        definitions = new uint[count];
        gc = new IndexRange[count];

        pointerFlag = extraction.Header.Format.HasPointersFlag;

        int offsetBits = 32 - metadata.HandleBits;

        foreach (var entry in extraction.Maps.Types) {
            if (entry.Handle >> offsetBits == 0x3A) {
                definitions[extraction.Types.Index[entry.MethodTable]] = entry.Handle & ((1U << offsetBits) - 1);
            }
        }

        for (int i = 0; i < count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            if (types[i].IsGeneric) {
                definitions[i] = definitions[extraction.Types.Index[types[i].GenericDefinition]];
            }
        }

        foreach (var layout in extraction.Gc.Layouts) {
            gc[layout.TypeIndex] = layout.Runs;
        }

        // Index property accessors by their declaring metadata type and method.
        foreach (var type in metadata.Types) {
            cancellationToken.ThrowIfCancellationRequested();

            int start = accessors.Count;

            for (int p = type.Properties.Start; p < type.Properties.End; ++p) {
                if (!Members.Properties.TryGetValue(metadata.Handles[p], out var property)) {
                    continue;
                }

                for (int a = property.Accessors.Start; a < property.Accessors.End; ++a) {
                    var entry = Members.Accessors[a];
                    var key = (type.Offset, entry.Method);
                    int previous = accessorHeads.GetValueOrDefault(key);

                    accessors.Add(new Accessor {
                        Property = property.Offset,
                        Method = entry.Method,
                        Semantics = entry.Semantics,
                        Next = previous
                    });
                    accessorHeads[key] = accessors.Count;
                }
            }

            if (accessors.Count != start) {
                ownerAccessors.Add(type.Offset, new IndexRange(start, accessors.Count - start));
            }
        }

        // Project callable runtime accessors that satisfy the instance ABI.
        for (int i = 0; i < abi.RuntimeCount; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            var method = new MethodRecord(extraction, i);
            int owner = extraction.Types.Index[method.DeclaringType];
            int head = FindAccessor(owner, method.MetadataOffset, method.Name, method.Signature);

            for (int a = head; a != 0; a = accessors[a - 1].Next) {
                var accessor = accessors[a - 1];
                var property = Members.Properties[accessor.Property];
                ref readonly var methodAbi = ref abi.Methods[i];
                bool setter = accessor.Semantics == 1;

                bool eligible = accessor.Semantics is 1 or 2
                    && property.Parameters.Count == 0
                    && methodAbi.Status == AbiStatus.Complete
                    && methodAbi.Parameters.Count == (setter ? 2 : 1)
                    && abi.Parameters[methodAbi.Parameters.Start].Role == AbiRole.This
                    && abi.Parameters[methodAbi.Parameters.Start].Slot == 0;
                if (!eligible) {
                    ++Rejected[(int)PropertyRejection.UnsupportedAbi];
                    continue;
                }

                var actual = setter
                    ? abi.Parameters[methodAbi.Parameters.Start + 1].Value
                    : methodAbi.Return;
                if (!SameType(owner, property.Type, actual.Signature, method.Arguments)
                    || (setter && (abi.Parameters[methodAbi.Parameters.Start + 1].Slot != 1
                        || methodAbi.Return.Kind != AbiKind.Void))
                    || (!setter && methodAbi.Return.Indirect && methodAbi.ReturnSlot != 1)) {
                    ++Rejected[(int)PropertyRejection.UnsupportedAbi];
                    continue;
                }

                Add(owner, owner, accessor, method.Entrypoint, PropertyOrigin.Direct, method.Arguments);
            }
        }

        Merge();
        ExpandCanonical();

        // Join accessor declarations with virtual and interface dispatch slots.
        var slots = new List<SlotProperty>(extraction.Virtuals.Entries.Count);

        foreach (var entry in extraction.Virtuals.Entries) {
            cancellationToken.ThrowIfCancellationRequested();

            if (entry.Generic || entry.HierarchyDistance != 0) {
                continue;
            }

            int owner = extraction.Types.Index[entry.DeclaringType];
            int head = FindAccessor(
                owner,
                entry.Identity.MetadataOffset,
                entry.Identity.Name,
                entry.Identity.Signature);

            for (int a = head; a != 0; a = accessors[a - 1].Next) {
                slots.Add(new SlotProperty(owner, entry.Slot, a - 1));
            }
        }

        slots.Sort(static (a, b) => a.Contract != b.Contract
            ? a.Contract.CompareTo(b.Contract)
            : a.Slot.CompareTo(b.Slot));

        var slotRanges = new Dictionary<(int Contract, ushort Slot), IndexRange>(slots.Count);
        var classRanges = new Dictionary<int, IndexRange>();

        for (int start = 0; start < slots.Count;) {
            cancellationToken.ThrowIfCancellationRequested();

            int end = start + 1;

            while (end < slots.Count
                && slots[end].Contract == slots[start].Contract
                && slots[end].Slot == slots[start].Slot) {
                ++end;
            }

            slotRanges.Add(
                (slots[start].Contract, slots[start].Slot),
                new IndexRange(start, end - start));
            start = end;
        }

        for (int start = 0; start < slots.Count;) {
            cancellationToken.ThrowIfCancellationRequested();

            int end = start + 1;

            while (end < slots.Count && slots[end].Contract == slots[start].Contract) {
                ++end;
            }

            if (types[slots[start].Contract].ElementType == 20) {
                classRanges.Add(slots[start].Contract, new IndexRange(start, end - start));
            }

            start = end;
        }

        foreach (var target in extraction.Dispatch.Targets) {
            cancellationToken.ThrowIfCancellationRequested();

            var entry = extraction.Dispatch.Entries[target.Entry];
            if (!slotRanges.TryGetValue((target.InterfaceType, entry.InterfaceSlot), out var range)) {
                ++UnjoinedDispatch;
                continue;
            }

            if (target.RequiresInstantiatingThunk
                || target.GenericContext != 0
                || entry.Kind is DispatchKind.Static or DispatchKind.StaticDefault) {
                Rejected[(int)PropertyRejection.UnsupportedAbi] += range.Count;
                continue;
            }

            for (int i = range.Start; i < range.End; ++i) {
                var slot = slots[i];
                AddVirtual(
                    target.OwnerType,
                    slot.Contract,
                    accessors[slot.Accessor],
                    target.Target,
                    PropertyOrigin.Interface);
            }
        }

        // Apply inherited class slots to their derived owners.
        for (int owner = 0; owner < count; ++owner) {
            cancellationToken.ThrowIfCancellationRequested();

            if (types[owner].ElementType != 20) {
                continue;
            }

            int ancestor = owner;

            while (types[ancestor].RelatedType != 0) {
                ancestor = extraction.Types.Index[types[ancestor].RelatedType];
                if (!classRanges.TryGetValue(ancestor, out var range)) {
                    continue;
                }

                for (int i = range.Start; i < range.End; ++i) {
                    var slot = slots[i];
                    if (slot.Slot >= types[owner].Vtable.Count) {
                        continue;
                    }

                    ulong target = extraction.Types.Pointers[types[owner].Vtable.Start + slot.Slot];
                    if (extraction.Image.IsExecutable(target)) {
                        AddVirtual(owner, ancestor, accessors[slot.Accessor], target, PropertyOrigin.Base);
                    }
                }
            }
        }

        Merge();

        var accessorSlots = new HashSet<(int Contract, ushort Slot, uint Method)>();

        foreach (var slot in slots) {
            accessorSlots.Add((slot.Contract, slot.Slot, accessors[slot.Accessor].Method));
        }

        Functions = PropertyFunctions.Bind(extraction, abi, this, accessorSlots);
        cancellationToken.ThrowIfCancellationRequested();
    }

    private int FindAccessor(int owner, uint method, string name, int signature) {
        uint definition = definitions[owner];
        if (definition == 0 || signature == 0) {
            return 0;
        }

        if (method != 0) {
            return accessorHeads.GetValueOrDefault((definition, method));
        }

        if (!ownerAccessors.TryGetValue(definition, out var range)) {
            return 0;
        }

        ++LegacyIdentities;

        uint match = 0;

        for (int i = range.Start; i < range.End; ++i) {
            var candidate = metadata.Methods[metadata.ReadMethod(accessors[i].Method)];
            if (candidate.Signature == 0
                || candidate.Name != name
                || !SameSignature(owner, signature, candidate.Signature)) {
                continue;
            }

            if (match != 0 && match != candidate.Offset) {
                ++Rejected[(int)PropertyRejection.AmbiguousIdentity];
                return 0;
            }

            match = candidate.Offset;
        }

        if (match != 0) {
            ++LegacyMatches;
        }

        return accessorHeads.GetValueOrDefault((definition, match));
    }

    private bool SameSignature(int owner, int left, int right) {
        var signatures = Signatures;
        var a = signatures.Methods[left];
        var b = signatures.Methods[right];

        bool aThis = a.NativeConvention
            ? (a.CallingConvention & 2) == 0
            : (a.CallingConvention & 0x20) != 0;
        bool bThis = b.NativeConvention
            ? (b.CallingConvention & 2) == 0
            : (b.CallingConvention & 0x20) != 0;

        bool aManaged = a.NativeConvention
            ? (a.CallingConvention & ~3U) == 0
            : (a.CallingConvention & ~0x30U) == 0;
        bool bManaged = b.NativeConvention
            ? (b.CallingConvention & ~3U) == 0
            : (b.CallingConvention & ~0x30U) == 0;

        if (!aManaged
            || !bManaged
            || aThis != bThis
            || a.GenericParameterCount != 0
            || b.GenericParameterCount != 0
            || a.Parameters.Count != b.Parameters.Count
            || a.Varargs.Count != 0
            || b.Varargs.Count != 0) {
            return false;
        }

        for (int i = -1; i < a.Parameters.Count; ++i) {
            int first = i == -1 ? a.ReturnType : signatures.Edges[a.Parameters.Start + i];
            int second = i == -1 ? b.ReturnType : signatures.Edges[b.Parameters.Start + i];
            if (!SameType(owner, first, second, default)) {
                return false;
            }
        }

        return true;
    }

    private bool SameType(int owner, int left, int right, ReadOnlySpan<ulong> arguments) {
        if (left == right && left != 0) {
            return true;
        }

        var nodes = Signatures.Nodes;
        var a = ManagedAbi.Resolve(extraction, bindings, left, owner + 1, arguments);
        var b = ManagedAbi.Resolve(extraction, bindings, right, owner + 1, arguments);
        if (nodes[left].Kind == SignatureKind.Modified || nodes[right].Kind == SignatureKind.Modified) {
            return false;
        }

        if (a.Binding != 0
            && a.Binding == b.Binding
            && a.Kind == b.Kind
            && a.Size == b.Size) {
            return true;
        }

        if (a.Kind is AbiKind.Pointer or AbiKind.ByReference && a.Kind == b.Kind
            && nodes[left].Kind == nodes[right].Kind) {
            return SameType(owner, nodes[left].Element, nodes[right].Element, arguments);
        }

        return false;
    }

    private void AddVirtual(
        int owner,
        int contract,
        Accessor accessor,
        ulong target,
        PropertyOrigin origin) {
        var property = Members.Properties[accessor.Property];
        var method = metadata.Methods[metadata.ReadMethod(accessor.Method)];
        if (method.Signature == 0) {
            ++Rejected[(int)PropertyRejection.UnsupportedAbi];
            return;
        }

        var signature = Signatures.Methods[method.Signature];

        bool setter = accessor.Semantics == 1;
        bool valid = accessor.Semantics is 1 or 2
            && property.Parameters.Count == 0
            && !signature.NativeConvention
            && signature.CallingConvention == 0x20
            && signature.GenericParameterCount == 0
            && signature.Varargs.Count == 0
            && signature.Parameters.Count == (setter ? 1 : 0);

        int valueSignature = signature.ReturnType;
        if (setter && signature.Parameters.Count == 1) {
            valueSignature = Signatures.Edges[signature.Parameters.Start];
            valid &= ManagedAbi.Resolve(extraction, bindings, signature.ReturnType, contract + 1, default).Kind == AbiKind.Void;
        }

        var storage = ManagedAbi.Resolve(extraction, bindings, property.Type, contract + 1, default);
        valid &= storage.Kind is AbiKind.Integer or AbiKind.Reference
            && SameType(contract, property.Type, valueSignature, default);

        if (!valid || extraction.Types.Types[owner].IsValueType) {
            ++Rejected[(int)PropertyRejection.UnsupportedAbi];
            return;
        }

        Add(owner, contract, accessor, target, origin, default);
    }

    private void Add(
        int owner,
        int contract,
        Accessor accessor,
        ulong target,
        PropertyOrigin origin,
        ReadOnlySpan<ulong> arguments) {
        int signature = Members.Properties[accessor.Property].Type;
        var nodes = Signatures.Nodes;

        while (nodes[signature].Kind == SignatureKind.Modified) {
            signature = nodes[signature].Element;
        }

        bool byReference = nodes[signature].Kind == SignatureKind.ByReference;
        if (byReference) {
            signature = nodes[signature].Element;
        }

        var storage = ManagedAbi.Resolve(extraction, bindings, signature, contract + 1, arguments);
        var access = scanner.Read(target, accessor.Semantics == 1, storage, byReference);
        if (access.Status != PropertyAccessStatus.Exact) {
            ++Rejected[(int)(access.Status == PropertyAccessStatus.HelperRequired
                ? PropertyRejection.ReferenceHelper
                : PropertyRejection.UnsupportedCode)];
            return;
        }

        int offset = access.Offset + access.ReceiverAdjustment - (extraction.Types.Types[owner].IsValueType ? 8 : 0);
        var rejection = CheckStorage(owner, offset, access.Size, storage);
        if (rejection != PropertyRejection.Count) {
            ++Rejected[(int)rejection];
            return;
        }

        Projections.Add(new PropertyProjection {
            Owner = owner,
            Contract = contract,
            SourceOwner = owner,
            Property = accessor.Property,
            Signature = signature,
            Offset = offset,
            Size = (uint)access.Size,
            Storage = storage,
            Origin = origin,
            ByReference = byReference,
            Getter = accessor.Semantics == 2 ? target : 0,
            Setter = accessor.Semantics == 1 ? target : 0,
            GetterMethod = accessor.Semantics == 2 ? accessor.Method : 0,
            SetterMethod = accessor.Semantics == 1 ? accessor.Method : 0
        });
    }

    private PropertyRejection CheckStorage(int owner, int offset, int size, in AbiValue storage) {
        if (storage.Kind is AbiKind.Unknown
            or AbiKind.Void
            or AbiKind.Context
            or AbiKind.ByReference
            or AbiKind.BoxedReference
            || size <= 0
            || storage.Size != size) {
            return PropertyRejection.UnknownStorage;
        }

        var types = extraction.Types.Types;
        bool valueOwner = types[owner].IsValueType;
        if (offset < (valueOwner ? 0 : 8) || offset + (long)size > extraction.Fields.Layouts[owner].Length) {
            return PropertyRejection.OutsideLayout;
        }

        if ((types[owner].Flags & pointerFlag) != 0 && gc[owner].Count == 0) {
            return PropertyRejection.UnknownGc;
        }

        if (storage.Kind == AbiKind.Value
            && (storage.Binding == 0
                || ((types[storage.Binding - 1].Flags & pointerFlag) != 0
                    && gc[storage.Binding - 1].Count == 0))) {
            return PropertyRejection.UnknownGc;
        }

        long start = offset + (valueOwner ? 8 : 0);
        var expected = storage.Kind == AbiKind.Value ? gc[storage.Binding - 1] : default;
        var runs = extraction.Gc.Runs;

        bool reference = storage.Kind == AbiKind.Reference;
        bool actualReference = false;

        for (int direction = 0; direction < 2; ++direction) {
            var source = direction == 0 ? gc[owner] : expected;
            var target = direction == 0 ? expected : gc[owner];
            long sourceStart = direction == 0 ? start : 8;
            long targetStart = direction == 0 ? 8 : start;

            for (int r = source.Start; r < source.End; ++r) {
                var run = runs[r];
                long first = Math.Max(run.Offset, sourceStart);
                long end = Math.Min(run.Offset + 8L * run.Count, sourceStart + size);
                if (end <= first) {
                    continue;
                }

                if ((first - run.Offset) % 8 != 0 || (end - first) % 8 != 0) {
                    return PropertyRejection.GcMismatch;
                }

                for (long slot = first; slot < end; slot += 8) {
                    long other = slot - sourceStart + targetStart;
                    bool found = reference && direction == 0 && other == 8 && size == 8;
                    actualReference |= found;

                    for (int t = target.Start; t < target.End && !found; ++t) {
                        var candidate = runs[t];
                        found = other >= candidate.Offset
                            && other + 8 <= candidate.Offset + 8L * candidate.Count
                            && (other - candidate.Offset) % 8 == 0;
                    }

                    if (!found) {
                        return PropertyRejection.GcMismatch;
                    }
                }
            }
        }

        return reference && !actualReference
            ? PropertyRejection.GcMismatch
            : PropertyRejection.Count;
    }

    private void ExpandCanonical() {
        var groups = extraction.Fields.Canonical.Groups;
        var heads = new int[groups.Length + 1];
        var next = new int[groups.Length];

        for (int i = groups.Length - 1; i >= 0; --i) {
            next[i] = heads[groups[i]];
            heads[groups[i]] = i + 1;
        }

        int sourceCount = Projections.Count;
        var shapes = new Dictionary<(int Group, uint Property), (int Offset, uint Size, AbiKind Kind)>(sourceCount);
        var conflicts = new HashSet<(int Group, uint Property)>();

        for (int i = 0; i < sourceCount; ++i) {
            cancellationToken.ThrowIfCancellationRequested();

            var source = Projections[i];
            var key = (groups[source.Owner], source.Property);
            var shape = (source.Offset, source.Size, source.Storage.Kind);
            if (shapes.TryGetValue(key, out var previous) && previous != shape) {
                conflicts.Add(key);
            } else {
                shapes[key] = shape;
            }
        }

        var seen = new HashSet<(int Owner, uint Property)>(sourceCount);

        for (int i = 0; i < sourceCount; ++i) {
            seen.Add((Projections[i].Owner, Projections[i].Property));
        }

        for (int i = 0; i < sourceCount; ++i) {
            var source = Projections[i];
            if (conflicts.Contains((groups[source.Owner], source.Property))) {
                ++Rejected[(int)PropertyRejection.CanonicalConflict];
                continue;
            }

            for (int item = heads[groups[source.Owner]]; item != 0; item = next[item - 1]) {
                int owner = item - 1;
                if (seen.Contains((owner, source.Property))) {
                    continue;
                }

                var storage = ManagedAbi.Resolve(extraction, bindings, source.Signature, owner + 1, default);
                if (storage.Binding == 0
                    || source.Storage.Binding == 0
                    || storage.Kind != source.Storage.Kind
                    || storage.Size != source.Size) {
                    ++Rejected[(int)PropertyRejection.UnknownStorage];
                    continue;
                }

                var rejection = CheckStorage(owner, source.Offset, (int)source.Size, storage);
                if (rejection != PropertyRejection.Count) {
                    ++Rejected[(int)rejection];
                    continue;
                }

                var projection = source;
                projection.Owner    = owner;
                projection.Contract = owner;
                projection.Storage  = storage;
                projection.Origin   = PropertyOrigin.Canonical;

                Projections.Add(projection);
                seen.Add((owner, source.Property));
            }
        }
    }

    private void Merge() {
        Projections.Sort(static (a, b) => a.Owner != b.Owner
            ? a.Owner.CompareTo(b.Owner)
            : a.Contract != b.Contract
                ? a.Contract.CompareTo(b.Contract)
                : a.Property.CompareTo(b.Property));

        int output = 0;

        for (int start = 0; start < Projections.Count;) {
            cancellationToken.ThrowIfCancellationRequested();

            int end = start + 1;
            var first = Projections[start];
            bool conflict = false;

            while (end < Projections.Count
                && Projections[end].Owner == first.Owner
                && Projections[end].Contract == first.Contract
                && Projections[end].Property == first.Property) {
                var other = Projections[end++];
                conflict |= other.Offset != first.Offset
                    || other.Size != first.Size
                    || other.Storage.Kind != first.Storage.Kind
                    || other.Storage.Binding != first.Storage.Binding
                    || other.ByReference != first.ByReference;

                conflict |= first.Getter != 0 && other.Getter != 0
                    && (first.Getter != other.Getter || first.GetterMethod != other.GetterMethod);

                conflict |= first.Setter != 0 && other.Setter != 0
                    && (first.Setter != other.Setter || first.SetterMethod != other.SetterMethod);

                if (first.Getter == 0) {
                    first.Getter = other.Getter;
                    first.GetterMethod = other.GetterMethod;
                }

                if (first.Setter == 0) {
                    first.Setter = other.Setter;
                    first.SetterMethod = other.SetterMethod;
                }
            }

            if (conflict) {
                ++Rejected[(int)PropertyRejection.ConflictingAccessors];
            } else {
                Projections[output++] = first;
            }

            start = end;
        }

        Projections.RemoveRange(output, Projections.Count - output);
    }
}
