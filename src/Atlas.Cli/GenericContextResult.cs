using Atlas;

internal sealed class GenericContextResult {
    internal ManagedUnwind Managed { get; }
    internal MethodGcMap Gc { get; }
    internal GenericContextReferences References { get; }
    internal DictionarySlotConsumers Consumers { get; }
    internal string GcHeadersStatus { get; }
    internal string DelegateConsumersStatus { get; }
    internal string? DelegateConsumersError { get; }
    internal string Status { get; }
    internal MethodGcEntry[] UnresolvedParameters { get; }
    internal MethodGcEntry[] UnavailableHeaders { get; }

    internal GenericContextResult(PeImage image, ManagedUnwind managed, MethodGcMap gc,
        GenericContextReferences references, DictionarySlotConsumers consumers,
        string delegateConsumersStatus, string? delegateConsumersError = null) {
        Managed = managed;
        Gc = gc;
        References = references;
        Consumers = consumers;
        DelegateConsumersStatus = delegateConsumersStatus;
        DelegateConsumersError = delegateConsumersError;

        var resolved = references.ParameterEntries.ToArray()
            .Select(parameter => parameter.Target).ToHashSet();
        var unresolved = new List<MethodGcEntry>();
        var unavailable = new List<MethodGcEntry>();

        foreach (var method in gc.MethodEntries) {
            if (method.Info is not { } info) {
                unavailable.Add(method);
            } else if ((info.Flags & 0x30) == 0x20
                && !resolved.Contains(image.ImageBase + method.Begin)) {
                unresolved.Add(method);
            }
        }

        UnresolvedParameters = unresolved.ToArray();
        UnavailableHeaders = unavailable.ToArray();
        GcHeadersStatus = managed.RegionSource == ManagedRegionSource.Unknown ? "unavailable"
            : unavailable.Count != 0 ? "partial" : "complete";
        Status = GcHeadersStatus == "complete" && delegateConsumersStatus == "complete"
            && unresolved.Count == 0 && references.UnresolvedControlFlowAddresses.IsEmpty
            && consumers.Failures.Count == 0 && consumers.UnresolvedOwners.Count == 0
            ? "complete" : "partial";
    }
}
