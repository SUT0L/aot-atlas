using System.Buffers.Binary;
using Atlas;

internal static class SelectiveRuntimeReferenceChecks {
    internal static void Run(ReadOnlySpan<string> paths) {
        foreach (string path in paths) {
            var image = PeImage.ReadFile(path);
            var full = Extraction.Read(image);

            foreach (var stage in new[] { ExtractionStage.RuntimeTypes, ExtractionStage.Dispatch }) {
                var selected = Extraction.Read(image, stage);
                Check(selected.Stages == (stage | ExtractionStage.RuntimeTypes));
                CheckConcurrentReferences(selected);
                CheckRuntimeReferences(selected, full);

                if (stage == ExtractionStage.Dispatch)
                    CheckDispatchReferences(selected, full);

                var signature = full.Maps.TypeSignatureAt(0);
                var own = full.RuntimeTypeAt(0);
                Check(full.Bindings.RuntimeType(own.Address).Equals(own));
                Check(full.Bindings.Resolve(signature, own).Address == full.Maps.TypeEntries[0].MethodTable);
                Reject(() => full.Bindings.Resolve(signature, selected.RuntimeTypeAt(0)));
                Reject(() => full.Bindings.Resolve(signature, methodArguments: [selected.RuntimeTypeAt(0)]));
            }

            Console.WriteLine($"Selective runtime references: {path}; runtime/GC/frozen/marshalling/EH/dispatch addresses, concurrent first readers, shared full bindings and foreign namespaces passed.");
        }
    }

    private static void CheckConcurrentReferences(Extraction extraction) {
        using var start = new ManualResetEventSlim();
        var references = new RuntimeTypeReference[4];
        var readers = new Thread[references.Length];

        for (int i = 0; i < readers.Length; ++i) {
            int position = i;
            readers[i] = new Thread(() => {
                start.Wait();
                references[position] = extraction.RuntimeTypeAt(0);
            });
            readers[i].Start();
        }

        start.Set();

        foreach (var reader in readers)
            reader.Join();

        foreach (var reference in references)
            Check(reference.IsResolved && reference.Equals(references[0]));
    }

    private static void CheckRuntimeReferences(Extraction selected, Extraction full) {
        var types = selected.Types.Publish().TypeEntries;
        var fullTypes = full.Types.Publish().TypeEntries.ToArray().ToDictionary(type => type.Address);

        for (int i = 0; i < types.Length; ++i) {
            Check(selected.RuntimeTypeAt(i).Address == types[i].Address);
            Check(fullTypes.ContainsKey(types[i].Address));
        }

        Reject(() => selected.RuntimeTypeAt(-1));
        int typeCount = types.Length;
        Reject(() => selected.RuntimeTypeAt(typeCount));

        var fullGc = new HashSet<ulong>();

        for (int i = 0; i < full.Gc.LayoutEntries.Length; ++i)
            fullGc.Add(full.GcLayoutTypeAt(i).Address);

        for (int i = 0; i < selected.Gc.LayoutEntries.Length; ++i) {
            ulong address = types[selected.Gc.LayoutEntries[i].TypeIndex].Address;
            Check(selected.GcLayoutTypeAt(i).Address == address && fullGc.Contains(address));
        }

        for (int i = 0; i < selected.Gc.UnprovenTypeCount; ++i)
            Check(selected.UnprovenGcTypeAt(i).Address == types[selected.Gc.Unproven[i]].Address);

        for (int i = 0; i < selected.Frozen.ObjectEntries.Length; ++i) {
            var frozen = selected.Frozen.ObjectEntries[i];
            ulong header = selected.Frozen.Start + (uint)frozen.Offset;
            ulong type = BinaryPrimitives.ReadUInt64LittleEndian(selected.Memory.Read(header, 8));
            Check(selected.FrozenObjectTypeAt(i).Address == type);
        }

        for (int i = 0; i < selected.Frozen.RuntimeTypeEntries.Length; ++i) {
            var association = selected.Frozen.RuntimeTypeEntries[i];
            var frozen = selected.Frozen.ObjectEntries[association.ObjectIndex];
            ulong type = BinaryPrimitives.ReadUInt64LittleEndian(
                selected.Memory.Read(selected.Frozen.Start + (uint)frozen.Data.Start, 8));
            Check(selected.FrozenRuntimeTypeAt(i).Address == type);
        }

        for (int i = 0; i < selected.Marshalling.StructEntries.Length; ++i)
            Check(selected.NativeStructTypeAt(i).Address == types[selected.Marshalling.StructEntries[i].TypeIndex].Address);

        for (int i = 0; i < selected.Marshalling.DelegateEntries.Length; ++i)
            Check(selected.NativeDelegateTypeAt(i).Address == types[selected.Marshalling.DelegateEntries[i].TypeIndex].Address);

        if (selected.UnwindAnalysis.Managed is { } managed) {
            for (int i = 0; i < managed.ClauseEntries.Length; ++i) {
                var clause = managed.ClauseEntries[i];
                Check(selected.ExceptionTypeAt(i).Address == (clause.Kind == ExceptionClauseKind.Typed
                    ? selected.Image.ImageBase + clause.Type : 0));
            }
        }
    }

    private static void CheckDispatchReferences(Extraction selected, Extraction full) {
        var types = selected.Types.Publish().TypeEntries;
        var fullTargets = new HashSet<(ulong Owner, ulong Interface, ulong Target, ulong Context)>();

        for (int i = 0; i < full.Dispatch.TargetEntries.Length; ++i) {
            var target = full.Dispatch.TargetEntries[i];
            fullTargets.Add((full.DispatchOwnerAt(i).Address, full.DispatchInterfaceAt(i).Address,
                target.Target, target.GenericContext));
        }

        for (int i = 0; i < selected.Dispatch.TargetEntries.Length; ++i) {
            var target = selected.Dispatch.TargetEntries[i];
            ulong owner = types[target.OwnerType].Address;
            ulong contract = types[target.InterfaceType].Address;
            Check(selected.DispatchOwnerAt(i).Address == owner
                && selected.DispatchInterfaceAt(i).Address == contract
                && fullTargets.Contains((owner, contract, target.Target, target.GenericContext)));
        }

        for (int i = 0; i < selected.Dispatch.UnresolvedEntries.Length; ++i)
            Check(selected.UnresolvedDispatchOwnerAt(i).Address == types[selected.Dispatch.UnresolvedEntries[i].OwnerType].Address);

        for (int i = 0; i < types.Length; ++i) {
            var map = selected.DispatchMapForType(i);
            Check((map?.Address ?? 0) == types[i].DispatchMap);
        }
    }

    private static void Reject(Action action) {
        try {
            action();
        } catch (ArgumentException) {
            return;
        }

        throw new Exception("A foreign runtime namespace or invalid position was accepted.");
    }

    private static void Check(bool condition) {
        if (!condition)
            throw new Exception("Selective runtime reference assertion failed.");
    }
}
