using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal sealed unsafe class Symbols {
    private struct Entry {
        internal nint Primary;
        internal nint StrongAuto;
        internal bool User;
        internal bool Atlas;
        internal bool Defined;
    }

    private readonly nint view;
    private readonly ulong imageBase;
    private readonly Dictionary<ulong, Entry> entries;
    private readonly List<nint> owned;
    private readonly nint* snapshot;
    private readonly nuint count;

    internal Symbols(nint view, ulong imageBase, int expected) {
        this.view = view;
        this.imageBase = imageBase;

        nuint length = 0;
        snapshot = Core.BNGetSymbols(view, &length, 0);
        count = length;

        entries = new(Math.Max(checked((int)count), expected));
        owned = new(Math.Max(checked((int)count), expected));

        try {
            // Bulk updates defer symbol processing
            // Resolve precedence before entering the batch, then let each accepted definition become the pending primary
            for (nuint i = 0; i < count; ++i) {
                nint symbol = snapshot[i];
                ulong address = Core.BNGetSymbolAddress(symbol);
                ref var entry = ref CollectionsMarshal.GetValueRefOrAddDefault(entries, address, out bool exists);

                if (!exists) {
                    entry.Primary = Core.BNGetSymbolByAddress(view, address, 0);
                    if (entry.Primary != 0) {
                        owned.Add(entry.Primary);
                        entry.Atlas = AnnotationReconciliation.Current?.OwnsSymbol(address, entry.Primary) ?? false;
                        entry.User = Core.BNIsSymbolAutoDefined(entry.Primary) == 0 && !entry.Atlas;
                    }
                }

                byte kind = Core.BNGetSymbolType(symbol);
                if (entry.StrongAuto != 0 || (kind != 0 && kind != 2) || Core.BNIsSymbolAutoDefined(symbol) == 0)
                    continue;

                byte* raw = Core.BNGetSymbolRawName(symbol);
                if (kind == 2 || !SymbolNames.IsDefault(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(raw), address))
                    entry.StrongAuto = symbol;

                Core.BNFreeString(raw);
            }
        } catch {
            Free();

            throw;
        }
    }

    internal void Free() {
        foreach (nint symbol in owned)
            Core.BNFreeSymbol(symbol);

        Core.BNFreeSymbolList(snapshot, count);
    }

    internal void Define(ulong address, byte kind, byte* name, byte* displayName = null) {
        AnnotationReconciliation.Current?.VisitSymbol(address);
        var fullName = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(name);

        Span<byte> shortName = stackalloc byte[128];

        bool compact = displayName == null && kind == 0 && fullName.IndexOf("::"u8) >= 0;
        int shortLength = 0;

        if (compact) {
            shortLength = SymbolNames.Function(fullName, address - imageBase, shortName);
            shortName[shortLength] = 0;
        }

        ref var entry = ref CollectionsMarshal.GetValueRefOrAddDefault(entries, address, out _);
        // Keep the first accepted producer for this batch, including an unchanged symbol from the previous run.
        if (entry.Defined)
            return;

        if (entry.Primary != 0) {
            byte* raw = Core.BNGetSymbolRawName(entry.Primary);
            var oldRaw = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(raw);
            bool ours = entry.Atlas && oldRaw.SequenceEqual(fullName);
            bool generated = entry.Atlas || kind != 0 || SymbolNames.IsDefault(oldRaw, address);

            Core.BNFreeString(raw);

            if (ours) {
                byte* oldShort = Core.BNGetSymbolShortName(entry.Primary);
                var display = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(oldShort);
                bool same = displayName != null
                    ? display.SequenceEqual(MemoryMarshal.CreateReadOnlySpanFromNullTerminated(displayName))
                    : compact
                        ? display.SequenceEqual(shortName[..shortLength])
                        : display.SequenceEqual(fullName);
                same &= Core.BNGetSymbolType(entry.Primary) == kind;
                Core.BNFreeString(oldShort);

                if (kind == 0 && entry.StrongAuto != 0) {
                    byte* strongRaw = Core.BNGetSymbolRawName(entry.StrongAuto);
                    byte* strongFull = Core.BNGetSymbolFullName(entry.StrongAuto);
                    byte* strongShort = Core.BNGetSymbolShortName(entry.StrongAuto);

                    nint replacement = Core.BNCreateSymbol(
                        kind, strongShort, strongFull, strongRaw, address, 0, 0, 0);

                    Core.BNFreeString(strongRaw);
                    Core.BNFreeString(strongFull);
                    Core.BNFreeString(strongShort);

                    DefineSymbol(replacement, entry.Primary);
                    owned.Add(replacement);
                    entry.Primary = replacement;
                    entry.Defined = true;

                    return;
                }

                if (same) {
                    entry.Defined = true;
                    return;
                }
            } else if (entry.User || !generated || (kind == 0 && entry.StrongAuto != 0)) {
                if (!entry.Atlas)
                    AnnotationReconciliation.Current?.ExcludeSymbol(address);
                return;
            }
        }

        // Keep full metadata identity and user-layer precedence when replacing presentation
        // Undefining first can expose a different analysis alias
        nint created;

        fixed (byte* display = shortName)
            created = Core.BNCreateSymbol(
                kind, displayName != null ? displayName : compact ? display : name,
                name, name, address, 0, 0, 0);

        DefineSymbol(created, entry.Primary);
        owned.Add(created);
        entry.Primary = created;
        entry.Atlas = true;
        entry.Defined = true;
    }

    private void DefineSymbol(nint symbol, nint previous) {
        // Bulk symbol processing can leave view queries behind the queued primary.
        // The cache holds the exact native predecessor for this accepted definition.
        if (AnnotationReconciliation.Current is { } reconciliation && reconciliation.View == view)
            reconciliation.DefineSymbol(symbol, previous);
        else
            Core.BNDefineUserSymbol(view, symbol);
    }

    internal void DefineData(DataVariables variables, ulong address, nint type, byte* name) {
        Define(address, 3, name);
        variables.Define(address, type);
    }
}
