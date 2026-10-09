internal ref struct AllocationMeasurement {
    private const long Budget = 1_048_576;

    private readonly long before;
    private bool active;

    public AllocationMeasurement() {
        // Background GC can charge discarded allocation-context tails to this counter.
        if (!GC.TryStartNoGCRegion(Budget))
            throw new InvalidOperationException("Cannot isolate the allocation measurement.");

        active = true;
        before = GC.GetAllocatedBytesForCurrentThread();
    }

    internal long AllocatedBytes {
        get {
            if (!active)
                throw new InvalidOperationException("Allocation measurement is not active.");

            return GC.GetAllocatedBytesForCurrentThread() - before;
        }
    }

    public void Dispose() {
        if (!active)
            return;

        GC.EndNoGCRegion();
        active = false;
    }
}
