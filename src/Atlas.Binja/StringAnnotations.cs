using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class StringAnnotations {
    internal static void Apply(
        TagOwnership ownership,
        nint view,
        PeImage image,
        NativeStrings strings,
        ReadOnlySpan<CodeEdge> references,
        ulong viewBase,
        nint task) {
        if (strings.Items.Count == 0)
            return;

        int maximum = 0;
        foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items))
            maximum = Math.Max(maximum, item.Data.Count / (item.Wide ? 2 : 1));

        byte[] text = new byte[checked(6 * maximum + 96)];
        ownership.Reserve(strings.Items.Count);

        nint tagType;
        fixed (byte* name = "AOT Atlas printable bytes\0"u8)
        fixed (byte* icon = "🔎\0"u8) {
            tagType = Core.BNGetTagType(view, name);

            if (tagType == 0) {
                tagType = Core.BNCreateTagType(view);
                Core.BNTagTypeSetName(tagType, name);
                Core.BNTagTypeSetIcon(tagType, icon);
                Core.BNAddTagType(view, tagType);
            }
        }

        try {
            int processed = 0;

            foreach (ref readonly var item in CollectionsMarshal.AsSpan(strings.Items)) {
                if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                    throw new OperationCanceledException();

                string encoding = item.Wide ? "utf16le" : "ascii";
                Utf8.TryWrite(text, $"bytes::{encoding}::nul_terminated::", out int length);
                length += FrozenText.Quote(
                    image.FileData.AsSpan(item.Data.Start, item.Data.Count), text.AsSpan(length), item.Wide);
                text[length] = 0;

                ulong address = viewBase + item.Rva;
                DataTags.Set(ownership, view, tagType, address, text.AsSpan(0, length + 1));
            }

            foreach (ref readonly var reference in references) {
                Core.BNAddUserDataReference(view, viewBase + (reference.Instruction - image.ImageBase),
                    viewBase + (reference.Target - image.ImageBase));
            }
        } finally {
            Core.BNFreeTagType(tagType);
        }
    }
}
