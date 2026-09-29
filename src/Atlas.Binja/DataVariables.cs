namespace Atlas.Binja;

internal sealed unsafe class DataVariables {
    private readonly nint view;
    private readonly HashSet<ulong> preserved;

    internal DataVariables(nint view) {
        this.view = view;
        nuint count = 0;
        DataVariable* variables = Core.BNGetDataVariables(view, &count);
        try {
            preserved = new HashSet<ulong>(checked((int)count));
            for (nuint i = 0; i < count; ++i) {
                if (variables[i].AutoDiscovered == 0)
                    preserved.Add(variables[i].Address);
            }
        } finally {
            Core.BNFreeDataVariables(variables, count);
        }
    }

    internal void Define(ulong address, nint type) {
        // Freeze the preexisting user edits before our references can trigger new analysis definitions at addresses we have yet to annotate
        if (preserved.Contains(address))
            return;

        var confidence = new TypeConfidence(type);
        Core.BNDefineUserDataVariable(view, address, &confidence);
    }
}
