namespace Atlas;

public readonly record struct PropertyFunction(ulong Address, int Projection, bool Setter);

internal static class PropertyFunctions {
    internal static PropertyFunction[] Bind(Extraction extraction, ManagedAbi abi, PropertyProjections properties,
        HashSet<(int Contract, ushort Slot, uint Method)> accessorSlots) {
        var occupied = new HashSet<ulong>();
        for (int i = 0; i < extraction.Maps.Methods.Count + extraction.Generics.Methods.Count; ++i) {
            var method = new MethodRecord(extraction, i);
            occupied.Add(method.Entrypoint);
            occupied.Add(method.InvokeStub);
            occupied.Add(abi.Methods[i].UnboxedTarget);
        }
        foreach (ulong target in extraction.Shared.JumpTargets) {
            occupied.Add(target);
        }
        foreach (var frame in extraction.Managed.Frames) {
            if (frame.UnboxingTarget != 0) {
                occupied.Add(extraction.Image.ImageBase + frame.UnboxingTarget);
            }
        }
        foreach (var template in extraction.Templates.Methods) {
            occupied.Add(template.Method.Entrypoint);
        }
        foreach (var entry in extraction.Marshalling.Structs) {
            occupied.Add(entry.ToNative);
            occupied.Add(entry.ToManaged);
            occupied.Add(entry.Cleanup);
        }
        foreach (var entry in extraction.Marshalling.Delegates) {
            occupied.Add(entry.Open);
            occupied.Add(entry.Closed);
            occupied.Add(entry.Create);
        }
        foreach (var entry in extraction.Statics.Constructors) {
            occupied.Add(entry.Entrypoint);
        }

        var candidates = new Dictionary<ulong, PropertyFunction>();
        var ambiguous = new HashSet<ulong>();
        for (int i = 0; i < properties.Projections.Count; ++i) {
            var projection = properties.Projections[i];
            if (projection.Origin is not (PropertyOrigin.Interface or PropertyOrigin.Base) || projection.Storage.Binding == 0) {
                continue;
            }
            for (int accessor = 0; accessor < 2; ++accessor) {
                ulong address = accessor == 0 ? projection.Getter : projection.Setter;
                if (address == 0 || occupied.Contains(address)) {
                    continue;
                }
                var candidate = new PropertyFunction(address, i, accessor != 0);
                if (candidates.TryGetValue(address, out var previous)) {
                    var source = properties.Projections[previous.Projection];
                    if (source.Owner != projection.Owner || source.Offset != projection.Offset || previous.Setter != candidate.Setter
                        || source.Storage.Kind != projection.Storage.Kind || source.Storage.Size != projection.Storage.Size
                        || source.Storage.Binding != projection.Storage.Binding) {
                        ambiguous.Add(address);
                    }
                } else {
                    candidates.Add(address, candidate);
                }
            }
        }

        if (candidates.Count == 0) {
            return [];
        }

        // Identical code can serve unrelated methods whose property metadata was stripped
        // Every retained dispatch use must agree before a body receives one concrete receiver
        var virtualSlots = new HashSet<(ulong Address, int Owner, ushort Slot)>();
        foreach (var target in extraction.Dispatch.Targets) {
            if (!candidates.TryGetValue(target.Target, out var candidate)) {
                continue;
            }
            var projection = properties.Projections[candidate.Projection];
            var entry = extraction.Dispatch.Entries[target.Entry];
            uint method = candidate.Setter ? projection.SetterMethod : projection.GetterMethod;
            if (target.OwnerType != projection.Owner || target.InterfaceType != projection.Contract
                || target.RequiresInstantiatingThunk || target.GenericContext != 0 || entry.Kind != DispatchKind.Standard
                || !accessorSlots.Contains((projection.Contract, entry.InterfaceSlot, method))) {
                ambiguous.Add(target.Target);
            } else {
                virtualSlots.Add((target.Target, target.OwnerType, entry.ImplementationSlot));
            }
        }
        for (int owner = 0; owner < extraction.Types.Types.Count; ++owner) {
            var range = extraction.Types.Types[owner].Vtable;
            for (int slot = 0; slot < range.Count; ++slot) {
                ulong address = extraction.Types.Pointers[range.Start + slot];
                if (!candidates.TryGetValue(address, out var candidate)) {
                    continue;
                }
                var projection = properties.Projections[candidate.Projection];
                uint method = candidate.Setter ? projection.SetterMethod : projection.GetterMethod;
                bool bound = projection.Origin == PropertyOrigin.Base && accessorSlots.Contains((projection.Contract, (ushort)slot, method));
                if (owner != projection.Owner || (!bound && !virtualSlots.Contains((address, owner, (ushort)slot)))) {
                    ambiguous.Add(address);
                }
            }
        }
        for (int i = 0; i < extraction.Virtuals.Slots.Count; ++i) {
            var slot = extraction.Virtuals.Slots[i];
            if (!candidates.TryGetValue(slot.Target, out var candidate)) {
                continue;
            }
            var projection = properties.Projections[candidate.Projection];
            var entry = extraction.Virtuals.Entries[i];
            uint method = candidate.Setter ? projection.SetterMethod : projection.GetterMethod;
            if (slot.RequiresInstantiatingThunk || extraction.Types.Index[entry.DeclaringType] != projection.Owner
                || !accessorSlots.Contains((projection.Contract, entry.Slot, method))) {
                ambiguous.Add(slot.Target);
            }
        }

        var signatures = extraction.Metadata.Signatures;
        foreach (var trace in extraction.Traces.Methods) {
            if (!candidates.TryGetValue(trace.Entrypoint, out var candidate)) {
                continue;
            }
            var projection = properties.Projections[candidate.Projection];
            var signature = signatures.Methods[trace.Signature];
            bool valid = !trace.Hidden && extraction.Fields.Bindings.Resolve(trace.DeclaringType) == projection.Owner + 1
                && !signature.NativeConvention && signature.CallingConvention == 0x20 && signature.GenericParameterCount == 0
                && signature.Varargs.Count == 0 && signature.Parameters.Count == (candidate.Setter ? 1 : 0);
            if (valid) {
                var result = ManagedAbi.Resolve(extraction, signature.ReturnType, projection.Owner + 1, default);
                var value = result;
                if (candidate.Setter) {
                    valid = result.Kind == AbiKind.Void;
                    value = ManagedAbi.Resolve(extraction, signatures.Edges[signature.Parameters.Start], projection.Owner + 1, default);
                }
                valid &= value.Binding == projection.Storage.Binding && value.Kind == projection.Storage.Kind && value.Size == projection.Size;
            }
            if (!valid) {
                ambiguous.Add(trace.Entrypoint);
            }
        }

        var functions = new List<PropertyFunction>(candidates.Count);
        foreach (var candidate in candidates.Values) {
            if (!ambiguous.Contains(candidate.Address)) {
                functions.Add(candidate);
            }
        }
        functions.Sort(static (left, right) => left.Address.CompareTo(right.Address));
        return functions.ToArray();
    }
}
