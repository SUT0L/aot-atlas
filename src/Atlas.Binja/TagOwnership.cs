namespace Atlas.Binja;

internal sealed class TagOwnership {
    private readonly AnnotationReconciliation owned;

    internal TagOwnership(nint view) {
        owned = AnnotationReconciliation.Current
            ?? throw new InvalidOperationException("Atlas tag ownership requires an active annotation operation.");
        if (owned.View != view)
            throw new InvalidOperationException("Atlas tag ownership belongs to another view.");
    }

    internal void Reserve(int count) => owned.ReserveTags(count);
    internal bool Contains(nint tag) => owned.ContainsTag(tag);
    internal bool CanCreate(nint tagType, ulong address, bool data, string slot = "") =>
        owned.CanCreateTag(tagType, address, data, slot);
    internal void Register(nint tag, ulong address, bool data, string slot = "") => owned.RegisterTag(tag, address, data, slot);
    internal void Remove(nint tag) => owned.ForgetTag(tag);
}
