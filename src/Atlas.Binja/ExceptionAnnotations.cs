using System.Text.Unicode;

namespace Atlas.Binja;

internal static unsafe class ExceptionAnnotations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, DataVariables variables, nint view, Extraction extraction, ref ApplyStats stats, nint task) {
        var managed = extraction.Managed;
        if (managed.Frames.Length == 0)
            return;

        ownership.Reserve(checked(managed.Frames.Length + managed.Clauses.Length));
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 }, signed = new() { Value = 1, Confidence = 255 };
        nint u8 = Core.BNCreateIntegerType(1, &unsigned, &empty);
        nint u32 = Core.BNCreateIntegerType(4, &unsigned, &empty);
        nint i32 = Core.BNCreateIntegerType(4, &signed, &empty);
        nint[] types = new nint[6];
        nint tagType = 0;
        var headers = new HashSet<uint>(extraction.Unwind.Infos.Count);
        var associated = new HashSet<uint>(managed.AssociatedFrameCount);
        var blobTypes = new Dictionary<uint, nint>(managed.Exceptions.Length);
        Span<byte> text = stackalloc byte[256];
        Span<byte> identifier = stackalloc byte[64];
        try {
            fixed (byte* name = "AOT Atlas exceptions\0"u8)
            fixed (byte* icon = "🧩\0"u8) {
                tagType = Core.BNGetTagType(view, name);
                if (tagType == 0) {
                    tagType = Core.BNCreateTagType(view);
                    Core.BNTagTypeSetName(tagType, name);
                    Core.BNTagTypeSetIcon(tagType, icon);
                    Core.BNAddTagType(view, tagType);
                }
            }

            fixed (byte* name = text)
            fixed (byte* id = identifier)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* category = "nativeaot\0"u8)
            fixed (byte* join = "::\0"u8) {
                byte** parts = stackalloc byte*[3] { atlas, category, name };
                QualifiedName qualified = new() { Names = parts, Join = join, Count = 3 };
                for (int i = 0; i < types.Length; ++i) {
                    bool header = i < 4;
                    int key = header ? i : i - 4;
                    nint type = header ? ExceptionTypes.Header(key, u8, u32, i32) : ExceptionTypes.Associated(key, u8, i32);
                    string kind = header ? "managed-unwind" : "associated-data";
                    Utf8.TryWrite(identifier, $"aot-atlas:{kind}:v1:{key}\0", out _);
                    Utf8.TryWrite(text, $"{(header ? "unwind_header" : "associated_data")}_{key}\0", out _);
                    var actual = Core.BNDefineAnalysisType(view, id, &qualified, type);
                    types[i] = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, type);
                    Core.BNFreeQualifiedName(&actual);
                    Core.BNFreeType(type);
                }

                int processed = 0;
                foreach (ref readonly var frame in managed.Frames.AsSpan()) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    var entry = extraction.Unwind.Entries[frame.Entry - 1];
                    uint root = extraction.Unwind.Entries[managed.Frames[frame.Root - 1].Entry - 1].Function.Begin;
                    uint eh = frame.ExceptionInfo == 0 ? 0 : managed.Exceptions[frame.ExceptionInfo - 1].Address;
                    if (headers.Add(frame.Trailer)) {
                        int key = ((frame.Flags & 4) != 0 ? 1 : 0) | ((frame.Flags & 16) != 0 ? 2 : 0);
                        Utf8.TryWrite(text, $"nativeaot::unwind_header::{frame.Trailer:X8}\0", out _);
                        symbols.DefineData(variables, stats.ImageBase + frame.Trailer, types[key], name, ref stats);
                        if (frame.AssociatedData != 0) {
                            Core.BNAddUserDataReference(view, stats.ImageBase + frame.Trailer + 1, stats.ImageBase + frame.AssociatedData);
                            ++stats.DataReferences;
                        }
                        if (eh != 0) {
                            Core.BNAddUserDataReference(view, stats.ImageBase + frame.Trailer + (frame.AssociatedData == 0 ? 1U : 5U), stats.ImageBase + eh);
                            ++stats.DataReferences;
                        }
                    }

                    if (frame.AssociatedData != 0 && associated.Add(frame.AssociatedData)) {
                        Utf8.TryWrite(text, $"nativeaot::associated_data::{frame.AssociatedData:X8}\0", out _);
                        symbols.DefineData(variables, stats.ImageBase + frame.AssociatedData, types[4 + frame.AssociatedFlags], name, ref stats);
                        if (frame.UnboxingTarget != 0) {
                            Core.BNAddUserDataReference(view, stats.ImageBase + frame.AssociatedData + 1, stats.ImageBase + frame.UnboxingTarget);
                            ++stats.DataReferences;
                        }
                    }

                    int length = ExceptionText.Frame(text, managed.RegionSource, frame, entry.Function, root, eh);
                    DataTags.Set(ownership, view, tagType, stats.ImageBase + entry.Address, text[..length]);
                    if (entry.Function.Begin != root) {
                        Core.BNAddUserDataReference(view, stats.ImageBase + entry.Address, stats.ImageBase + root);
                        ++stats.DataReferences;
                    }
                    if (eh != 0) {
                        var blob = managed.Exceptions[frame.ExceptionInfo - 1];
                        foreach (ref readonly var clause in managed.Clauses.AsSpan(blob.Clauses.Start, blob.Clauses.Count)) {
                            if (clause.Kind == ExceptionClauseKind.Marker)
                                continue;
                            Core.BNAddUserDataReference(view, stats.ImageBase + clause.HandlerCell, stats.ImageBase + root + clause.HandlerOffset);
                            ++stats.DataReferences;
                            if (clause.Kind == ExceptionClauseKind.Filter) {
                                Core.BNAddUserDataReference(view, stats.ImageBase + clause.FilterCell, stats.ImageBase + root + clause.FilterOffset);
                                ++stats.DataReferences;
                            }
                        }
                    }
                }

                var element = new TypeConfidence(u8);
                processed = 0;
                foreach (ref readonly var blob in managed.Exceptions.AsSpan()) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();

                    if (!blobTypes.TryGetValue(blob.Length, out nint type)) {
                        type = Core.BNCreateArrayType(&element, blob.Length);
                        blobTypes.Add(blob.Length, type);
                    }
                    Utf8.TryWrite(text, $"nativeaot::eh_info::{blob.Address:X8}\0", out _);
                    symbols.DefineData(variables, stats.ImageBase + blob.Address, type, name, ref stats);
                    foreach (ref readonly var clause in managed.Clauses.AsSpan(blob.Clauses.Start, blob.Clauses.Count)) {
                        int length = ExceptionText.Clause(text, managed.RegionSource, clause);
                        DataTags.Set(ownership, view, tagType, stats.ImageBase + clause.Address, text[..length]);
                        if (clause.Kind == ExceptionClauseKind.Typed) {
                            Core.BNAddUserDataReference(view, stats.ImageBase + clause.TypeCell, stats.ImageBase + clause.Type);
                            ++stats.DataReferences;
                        }
                    }
                }
            }
        } finally {
            if (tagType != 0)
                Core.BNFreeTagType(tagType);
            foreach (nint type in types) {
                if (type != 0)
                    Core.BNFreeType(type);
            }
            foreach (nint type in blobTypes.Values)
                Core.BNFreeType(type);
            Core.BNFreeType(i32);
            Core.BNFreeType(u32);
            Core.BNFreeType(u8);
        }
    }
}
