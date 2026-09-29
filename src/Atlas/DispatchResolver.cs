using System.Runtime.InteropServices;

namespace Atlas;

public enum DispatchResolutionStatus : byte {
    NoBinding, Resolved, UnknownType, UnknownCast, MissingArrayBase, InvalidHierarchy,
    Reabstraction, Diamond, NullImplementation, NonExecutable, RequiresInstantiation, UnknownRuntimeOrdering
}

public readonly record struct DispatchResolution(DispatchResolutionStatus Status, ulong Target = 0,
    ulong Witness = 0, int MappingOwner = 0, int TargetOwner = 0, int MatchedInterface = 0,
    int Entry = 0, bool Variant = false);

public sealed class DispatchResolver {
    private readonly Extraction extraction;
    private readonly Dictionary<ulong, int> arrayTypes = new();

    public DispatchResolver(Extraction extraction) {
        this.extraction = extraction;
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        for (int i = 0; i < types.Length; ++i) {
            ref readonly var type = ref types[i];
            if (type.ElementType != 0x16 || type.Kind != 0 || type.TypeManager == 0)
                continue;
            ref int array = ref CollectionsMarshal.GetValueRefOrAddDefault(arrayTypes, type.TypeManager, out bool present);
            array = present ? 0 : i + 1;
        }
    }

    public DispatchResolution Resolve(ulong receiver, ulong contract, ushort slot) {
        if (!extraction.Types.Index.TryGetValue(receiver, out int owner)
            || !extraction.Types.Index.TryGetValue(contract, out int target)
            || extraction.Types.Types[target].ElementType != 0x15)
            return new(DispatchResolutionStatus.UnknownType);

        var standard = Search(owner, target, slot, DispatchKind.Standard, false, false);
        if (standard.Status != DispatchResolutionStatus.NoBinding)
            return standard;

        // The default/variant traversal order changed without a format change in runtime #125205
        // Preserve an answer only when both orders agree
        var legacy = Search(owner, target, slot, DispatchKind.Default, false, false);
        var current = Search(owner, target, slot, DispatchKind.Default, false, true);
        if (current.Status == DispatchResolutionStatus.NoBinding)
            current = Search(owner, target, slot, DispatchKind.Default, true, true);
        return legacy == current ? current : new(DispatchResolutionStatus.UnknownRuntimeOrdering);
    }

    private DispatchResolution Search(int receiver, int contract, ushort slot, DispatchKind kind,
        bool variantOnly, bool separateVariants) {
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var pointers = CollectionsMarshal.AsSpan(extraction.Types.Pointers);
        var entries = CollectionsMarshal.AsSpan(extraction.Dispatch.Entries);
        var maps = CollectionsMarshal.AsSpan(extraction.Dispatch.Maps);
        Span<(ulong Source, ulong Target)> visited = stackalloc (ulong, ulong)[64];
        int owner = receiver, remaining = types.Length;

        while (owner >= 0 && --remaining >= 0) {
            ref readonly var type = ref types[owner];
            int map = extraction.Dispatch.TypeMaps[owner];
            if (map != 0) {
                var range = maps[map - 1].Entries;
                int first = range.Start + (kind == DispatchKind.Default ? maps[map - 1].StandardCount : 0);
                int end = first + (kind == DispatchKind.Default ? maps[map - 1].DefaultCount : maps[map - 1].StandardCount);
                int firstPass = variantOnly ? 1 : 0, lastPass = separateVariants ? firstPass : 1;

                for (int pass = firstPass; pass <= lastPass; ++pass) {
                    for (int index = first; index < end; ++index) {
                        ref readonly var entry = ref entries[index];
                        if (entry.InterfaceSlot != slot)
                            continue;
                        ulong candidateAddress = pointers[type.Interfaces.Start + entry.InterfaceIndex];
                        if (!extraction.Types.Index.TryGetValue(candidateAddress, out int candidate))
                            return new(DispatchResolutionStatus.UnknownType);

                        var match = candidate == contract ? Match.Yes
                            : pass == 0 ? Match.No : Compatible(owner, candidate, contract, visited);
                        if (match == Match.Unknown)
                            return new(DispatchResolutionStatus.UnknownCast);
                        if (match == Match.No)
                            continue;

                        ushort implementation = entry.ImplementationSlot;
                        var result = new DispatchResolution(DispatchResolutionStatus.Resolved,
                            MappingOwner: owner + 1, TargetOwner: receiver + 1, MatchedInterface: candidate + 1,
                            Entry: index + 1, Variant: candidate != contract);
                        ulong target, witness;
                        if (implementation < type.Vtable.Count) {
                            ref readonly var original = ref types[receiver];
                            if (implementation >= original.Vtable.Count)
                                return result with { Status = DispatchResolutionStatus.InvalidHierarchy };
                            target = pointers[original.Vtable.Start + implementation];
                            witness = original.Address + 24 + (uint)implementation * 8;
                        } else if (implementation >= 0xFFFE) {
                            return result with { Status = implementation == 0xFFFF
                                ? DispatchResolutionStatus.Reabstraction : DispatchResolutionStatus.Diamond };
                        } else {
                            witness = type.SealedVtable + (uint)(implementation - type.Vtable.Count) * 4;
                            int sealedIndex = extraction.Dispatch.ReadSealedSlot(extraction.Image, extraction.Memory, witness) - 1;
                            var sealedSlot = extraction.Dispatch.SealedSlots[sealedIndex];
                            target = sealedSlot.Target;
                            result = result with { TargetOwner = owner + 1 };
                            if (sealedSlot.Flags != 0)
                                result = result with { Status = DispatchResolutionStatus.RequiresInstantiation };
                        }
                        if (target == 0)
                            return result with { Status = DispatchResolutionStatus.NullImplementation, Witness = witness };
                        if (!extraction.Image.IsExecutable(target))
                            return result with { Status = DispatchResolutionStatus.NonExecutable, Witness = witness };
                        return result with { Target = target, Witness = witness };
                    }
                }
            }

            if (type.ElementType is 0x17 or 0x18) {
                if (!arrayTypes.TryGetValue(type.TypeManager, out int array) || array == 0)
                    return new(DispatchResolutionStatus.MissingArrayBase);
                owner = array - 1;
            } else if (type.Kind == 0 && type.RelatedType != 0) {
                if (!extraction.Types.Index.TryGetValue(type.RelatedType, out owner))
                    return new(DispatchResolutionStatus.UnknownType);
            } else {
                owner = -1;
            }
        }
        return new(remaining < 0 ? DispatchResolutionStatus.InvalidHierarchy : DispatchResolutionStatus.NoBinding);
    }

    private enum Match : byte { No, Yes, Unknown }

    private Match Compatible(int owner, int candidate, int contract, Span<(ulong Source, ulong Target)> visited) {
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        ref readonly var source = ref types[candidate];
        ref readonly var target = ref types[contract];
        ref readonly var receiver = ref types[owner];
        bool array = receiver.ElementType is 0x17 or 0x18;
        if (!array && (receiver.Flags & 0x00800000) != 0) {
            var variance = Variance(receiver);
            if (variance.IsEmpty)
                return Match.Unknown;
            array = variance.Length == 1 && variance[0] == 0x20;
        }
        if (((target.Flags & 0x00800000) == 0 && !(array && target.IsGeneric))
            || ((source.Flags & 0x00800000) == 0 && !(array && source.IsGeneric)))
            return Match.No;
        return Parameters(candidate, contract, array, visited, 0);
    }

    private ReadOnlySpan<byte> Variance(in MethodTable type) {
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var range = type.Variance;
        if (type.GenericDefinition != 0 && extraction.Types.Index.TryGetValue(type.GenericDefinition, out int definition))
            range = types[definition].Variance;
        return CollectionsMarshal.AsSpan(extraction.Types.Variances).Slice(range.Start, range.Count);
    }

    private Match Parameters(int sourceIndex, int targetIndex, bool array,
        Span<(ulong Source, ulong Target)> visited, int depth) {
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var pointers = CollectionsMarshal.AsSpan(extraction.Types.Pointers);
        ref readonly var source = ref types[sourceIndex];
        ref readonly var target = ref types[targetIndex];
        if (source.GenericDefinition == 0 || target.GenericDefinition == 0)
            return Match.Unknown;
        if (source.GenericDefinition != target.GenericDefinition)
            return Match.No;
        var variance = Variance(target);
        if (source.Arguments.Count != target.Arguments.Count || (!array && variance.Length != target.Arguments.Count))
            return Match.Unknown;

        bool unknown = false;
        for (int i = 0; i < target.Arguments.Count; ++i) {
            ulong from = pointers[source.Arguments.Start + i], to = pointers[target.Arguments.Start + i];
            byte mode = array ? (byte)0x20 : variance[i];
            var match = mode switch {
                0 => from == to ? Match.Yes : Match.No,
                1 or 0x20 => Assignable(from, to, mode == 0x20, visited, depth),
                2 => Assignable(to, from, false, visited, depth),
                _ => Match.Unknown
            };
            if (match == Match.No)
                return Match.No;
            unknown |= match == Match.Unknown;
        }
        return unknown ? Match.Unknown : Match.Yes;
    }

    private Match Assignable(ulong from, ulong to, bool sizeEquivalence,
        Span<(ulong Source, ulong Target)> visited, int depth) {
        if (from == to && from != 0)
            return Match.Yes;
        if (!extraction.Types.Index.TryGetValue(from, out int sourceIndex)
            || !extraction.Types.Index.TryGetValue(to, out int targetIndex))
            return Match.Unknown;
        if (depth == visited.Length)
            return Match.Unknown;
        for (int i = 0; i < depth; ++i) {
            if (visited[i] == (from, to) || visited[i] == (to, from))
                return Match.No;
        }
        visited[depth++] = (from, to);

        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        var pointers = CollectionsMarshal.AsSpan(extraction.Types.Pointers);
        ref readonly var source = ref types[sourceIndex];
        ref readonly var target = ref types[targetIndex];
        if (source.Kind == 3 || target.Kind == 3)
            return Match.Unknown;

        if (target.ElementType == 0x15) {
            if (source.IsValueType)
                return Match.No;
            bool unknown = false;
            foreach (ulong address in pointers.Slice(source.Interfaces.Start, source.Interfaces.Count)) {
                if (address == to)
                    return Match.Yes;
            }
            if ((target.Flags & 0x00800000) != 0) {
                foreach (ulong address in pointers.Slice(source.Interfaces.Start, source.Interfaces.Count)) {
                    if (!extraction.Types.Index.TryGetValue(address, out int candidate)) {
                        unknown = true;
                        continue;
                    }
                    if ((types[candidate].Flags & 0x00800000) == 0)
                        continue;
                    var match = Parameters(candidate, targetIndex, source.ElementType is 0x17 or 0x18, visited, depth);
                    if (match == Match.Yes)
                        return Match.Yes;
                    unknown |= match == Match.Unknown;
                }
                if ((source.Flags & 0x00800000) != 0) {
                    var match = Parameters(sourceIndex, targetIndex, false, visited, depth);
                    if (match == Match.Yes)
                        return Match.Yes;
                    unknown |= match == Match.Unknown;
                }
            }
            return unknown ? Match.Unknown : Match.No;
        }
        if (source.ElementType == 0x15)
            return target.Kind == 0 && target.RelatedType == 0 ? Match.Yes : Match.No;

        if (target.Kind == 2) {
            if (source.Kind != 2 || source.BaseSize != target.BaseSize)
                return Match.No;
            if (!extraction.Types.Index.TryGetValue(source.RelatedType, out int element))
                return Match.Unknown;
            if (types[element].ElementType is 0x19 or 0x1A || types[element].Kind == 1)
                return Match.No;
            return Assignable(source.RelatedType, target.RelatedType, true, visited, depth);
        }
        if (target.Kind == 1)
            return Match.No;
        if (source.ElementType is 0x17 or 0x18)
            return target.ElementType == 0x16 || (target.ElementType == 0x14 && target.RelatedType == 0) ? Match.Yes : Match.No;
        if (source.Kind is 1 or 2)
            return Match.No;

        if (source.IsValueType) {
            if (!sizeEquivalence || target.ElementType is < 2 or >= 0x10)
                return Match.No;
            int sourceElement = source.ElementType - ((0x2AA0 >> source.ElementType) & 1);
            int targetElement = target.ElementType - ((0x2AA0 >> target.ElementType) & 1);
            return sourceElement == targetElement ? Match.Yes : Match.No;
        }
        if ((source.Flags & target.Flags & 0x00800000) != 0)
            return Parameters(sourceIndex, targetIndex, false, visited, depth);

        ulong parent = source.RelatedType;
        int remaining = types.Length;
        while (parent != 0 && --remaining >= 0) {
            if (parent == to)
                return Match.Yes;
            if (!extraction.Types.Index.TryGetValue(parent, out int index))
                return Match.Unknown;
            parent = types[index].Kind == 0 ? types[index].RelatedType : 0;
        }
        return remaining < 0 ? Match.Unknown : Match.No;
    }
}
