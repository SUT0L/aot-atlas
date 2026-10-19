using Atlas;

internal static class AnalysisProductChecks {
    internal static void Run(ReadOnlySpan<string> paths) {
        foreach (string path in paths) {
            var image = PeImage.ReadFile(path);
            var header = ReadyToRun.Read(image);
            var metadata = MetadataBuilder.FromImage(image, header);
            metadata.ReadDefinitions();
            var fixups = RuntimeTables.Fixups(image, header.Find(RtrSectionId.CommonFixupsTable));
            var maps = ReflectionMaps.Decode(image, header, metadata, fixups);
            var products = new AnalysisProducts(image, header, metadata, maps, fixups);

            Check(products.Members is not null && products.Abi is not null && products.Properties is not null
                && products.Code is not null && products.DispatchCells is not null && products.GcInfo is not null
                && products.GenericContexts is not null && products.FunctionPointers is not null && products.Strings is not null);
            Check(ReferenceEquals(products.Members, products.Properties!.Members)
                && ReferenceEquals(products.Abi!.Signatures, products.Properties.Signatures));

            if (products.FunctionPointers!.DictionaryConsumers is { } consumers)
                Check(ReferenceEquals(products.GenericContexts, consumers.ContextReferences)
                    && ReferenceEquals(products.DictionaryConsumers, consumers));

            foreach (var row in products.Properties.ProjectionEntries) {
                var property = products.Members!.PropertyDefinitions[row.Property];
                Check(products.Members.PropertyType(row.Property).Render()
                    == products.Properties.Signatures.Types[property.Type].Render());
            }

            // The local compiler fixture declares Packet.Message as a string
            // auto-property; the getter/setter select its first reference field.
            var messages = products.Properties.ProjectionEntries.ToArray()
                .Where(row => products.Members!.PropertyDefinitions[row.Property].Name == "Message").ToArray();
            if (metadata.TypeDefinitions.ToArray().Any(row => row.Name == "Packet")) {
                Check(messages.Length == 1 && messages[0].Size == 8 && messages[0].Offset == 8
                    && messages[0].Getter != 0
                    && messages[0].Storage.Kind == AbiKind.Reference);
                Check(products.Members!.PropertyType(messages[0].Property).Render() == "System.String");
                var property = products.Members.PropertyDefinitions[messages[0].Property];
                var accessors = products.Members.AccessorEntries.Slice(property.Accessors.Start, property.Accessors.Count).ToArray();
                Check(accessors.Any(row => row.Semantics == 1) && accessors.Any(row => row.Semantics == 2));
            }

            var shared = AnalysisProducts.Read(image);
            Check(ReferenceEquals(shared.Members, shared.Properties!.Members)
                && shared.Properties.ProjectionEntries.SequenceEqual(products.Properties.ProjectionEntries)
                && shared.Abi!.MethodEntries.SequenceEqual(products.Abi!.MethodEntries)
                && shared.Code!.CallEdges.SequenceEqual(products.Code!.CallEdges));

            var selected = AnalysisProducts.Read(image,
                requested: AnalysisProduct.Code);
            Check(selected.Extraction.Stages == AnalysisProducts.RequiredExtractionStages(AnalysisProduct.Code));
            Check(selected.Abi is not null && selected.Code is not null && selected.Members is null
                && selected.Properties is null && selected.DispatchCells is null && selected.GcInfo is null
                && selected.FunctionPointers is null && selected.GenericContexts is null && selected.Strings is null);

            var contexts = AnalysisProducts.Read(image,
                requested: AnalysisProduct.GenericContexts);
            Check(contexts.Extraction.Stages == AnalysisProducts.RequiredExtractionStages(AnalysisProduct.GenericContexts));
            Check(contexts.GenericContexts is not null && contexts.DictionaryConsumers is not null && contexts.GcInfo is not null
                && contexts.FunctionPointers is null && contexts.Abi is null && contexts.Code is null
                && contexts.Members is null && contexts.Properties is null && contexts.DispatchCells is null && contexts.Strings is null);
            Check(ReferenceEquals(contexts.GenericContexts, contexts.DictionaryConsumers!.ContextReferences)
                && contexts.GenericContexts!.DeclaredMethodContexts == products.GenericContexts!.DeclaredMethodContexts
                && contexts.GenericContexts.ParameterEntries.SequenceEqual(products.GenericContexts.ParameterEntries)
                && contexts.GenericContexts.ReferenceEntries.SequenceEqual(products.GenericContexts.ReferenceEntries)
                && contexts.GenericContexts.UnresolvedControlFlowAddresses.SequenceEqual(products.GenericContexts.UnresolvedControlFlowAddresses));
            Check(contexts.DictionaryConsumers.Relations.SequenceEqual(products.DictionaryConsumers!.Relations)
                && contexts.DictionaryConsumers.SlotAccesses.SequenceEqual(products.DictionaryConsumers.SlotAccesses)
                && contexts.DictionaryConsumers.ContextTransfers.SequenceEqual(products.DictionaryConsumers.ContextTransfers)
                && contexts.DictionaryConsumers.InitialContextTransfers.SequenceEqual(products.DictionaryConsumers.InitialContextTransfers)
                && contexts.DictionaryConsumers.DelegateSlots.SequenceEqual(products.DictionaryConsumers.DelegateSlots)
                && contexts.DictionaryConsumers.InitialDelegateSlots.SequenceEqual(products.DictionaryConsumers.InitialDelegateSlots)
                && contexts.DictionaryConsumers.Failures.SequenceEqual(products.DictionaryConsumers.Failures)
                && contexts.DictionaryConsumers.UnresolvedOwners.SequenceEqual(products.DictionaryConsumers.UnresolvedOwners));

            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            Reject<OperationCanceledException>(() => AnalysisProducts.Read(image, cancellationToken: canceled.Token));
            Reject<ArgumentException>(() => AnalysisProducts.Read(image,
                requested: AnalysisProduct.Code, stages: ExtractionStage.RuntimeTypes));
            Reject<ArgumentException>(() => AnalysisProducts.Read(image,
                requested: AnalysisProduct.GenericContexts, stages: ExtractionStage.RuntimeTypes));
            Reject<ArgumentException>(() => new PropertyProjections(shared.Extraction, products.Abi!));
            Reject<ArgumentException>(() => new CodeFlow(shared.Extraction, products.Abi!));

            Console.WriteLine($"Analysis products: {path}; shared members/signature publication, ABI/property/code facts, compiler auto-property, selective prerequisites, source isolation and owner rejection passed.");
        }
    }

    private static void Check(bool value) {
        if (!value)
            throw new Exception("Analysis product assertion failed.");
    }

    private static void Reject<T>(Action action) where T : Exception {
        try {
            action();
        } catch (T) {
            return;
        }

        throw new Exception($"Expected {typeof(T).Name}.");
    }
}
