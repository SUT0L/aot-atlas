using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal static unsafe class DataTags {
    internal static void Set(TagOwnership ownership, nint view, nint tagType, ulong address, ReadOnlySpan<byte> text) {
        nuint count = 0;
        nint* tags = Core.BNGetUserDataTagsOfType(view, address, tagType, &count);
        try {
            fixed (byte* data = text) {
                nint chosen = 0;
                for (nuint i = 0; i < count; ++i) {
                    if (!ownership.Contains(tags[i]))
                        continue;
                    if (chosen != 0) {
                        ownership.Remove(tags[i]);
                        Core.BNRemoveUserDataTag(view, address, tags[i]);
                        Core.BNRemoveTag(view, tags[i], 1);
                        continue;
                    }
                    chosen = tags[i];
                    byte* previous = Core.BNTagGetData(chosen);
                    bool equal = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(previous).SequenceEqual(text[..^1]);
                    Core.BNFreeString(previous);
                    if (!equal)
                        Core.BNTagSetData(chosen, data);
                }

                if (chosen == 0) {
                    nint tag = Core.BNCreateTag(tagType, data);
                    ownership.Register(tag);
                    Core.BNAddUserDataTag(view, address, tag);
                    Core.BNFreeTag(tag);
                }
            }
        } finally {
            Core.BNFreeTagList(tags, count);
        }
    }
}
