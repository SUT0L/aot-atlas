using System.Buffers;
using System.Buffers.Text;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal static unsafe class DispatchAnnotations {
    internal static void Apply(Symbols symbols, TagOwnership ownership, DataVariables variables, nint view, Extraction extraction, ref ApplyStats stats, nint task) {
        var dispatch = extraction.Dispatch;
        var records = new DispatchRecords(extraction);
        ownership.Reserve(records.Sites.Length);
        var types = CollectionsMarshal.AsSpan(extraction.Types.Types);
        ulong originalBase = extraction.Image.ImageBase;
        byte[] buffer = new byte[records.BufferLength];
        Span<byte> identifier = stackalloc byte[80];
        byte empty = 0;
        BoolConfidence unsigned = new() { Confidence = 255 }, signed = new() { Value = 1, Confidence = 255 };
        nint u16 = Core.BNCreateIntegerType(2, &unsigned, &empty);
        nint i32 = Core.BNCreateIntegerType(4, &signed, &empty);
        nint instance = DispatchTypes.Entry(u16, false), statics = DispatchTypes.Entry(u16, true);
        var mapTypes = new Dictionary<ulong, nint>(dispatch.Maps.Count);
        nint tagType = 0, platform = 0;
        int processed = 0;
        try {
            fixed (byte* name = buffer)
            fixed (byte* id = identifier)
            fixed (byte* atlas = "atlas\0"u8)
            fixed (byte* category = "dispatch\0"u8)
            fixed (byte* join = "::\0"u8) {
                ReadOnlySpan<byte> prefix = "aot-atlas:dispatch-map:v1:"u8;
                byte** parts = stackalloc byte*[3] { atlas, category, id + prefix.Length };
                QualifiedName qualified = new() { Names = parts, Join = join, Count = 3 };
                Span<ushort> counts = stackalloc ushort[4];
                foreach (ref readonly var map in CollectionsMarshal.AsSpan(dispatch.Maps)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    ulong key = map.StandardCount | ((ulong)map.DefaultCount << 16) | ((ulong)map.StaticCount << 32) | ((ulong)map.StaticDefaultCount << 48);
                    if (!mapTypes.TryGetValue(key, out nint type)) {
                        prefix.CopyTo(identifier);
                        counts[0] = map.StandardCount;
                        counts[1] = map.DefaultCount;
                        counts[2] = map.StaticCount;
                        counts[3] = map.StaticDefaultCount;
                        for (int i = 0; i < 4; ++i) {
                            Utf8Formatter.TryFormat(counts[i], identifier[(prefix.Length + i * 5)..], out _, new StandardFormat('X', 4));
                            identifier[prefix.Length + i * 5 + 4] = i == 3 ? (byte)0 : (byte)'_';
                        }
                        nint structure = DispatchTypes.Map(map, u16, instance, statics);
                        var actual = Core.BNDefineAnalysisType(view, id, &qualified, structure);
                        type = Core.BNCreateNamedTypeReferenceFromTypeAndId(id, &actual, structure);
                        Core.BNFreeQualifiedName(&actual);
                        Core.BNFreeType(structure);
                        mapTypes.Add(key, type);
                    }
                    uint rva = checked((uint)(map.Address - originalBase));
                    "dispatch_map::"u8.CopyTo(buffer);
                    Utf8Formatter.TryFormat(rva, buffer.AsSpan(14), out _, new StandardFormat('X', 8));
                    buffer[22] = 0;
                    symbols.DefineData(variables, stats.ImageBase + rva, type, name, ref stats);
                }

                foreach (ref readonly var slot in CollectionsMarshal.AsSpan(dispatch.SealedSlots)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    uint rva = checked((uint)(slot.Address - originalBase));
                    "sealed_slot::"u8.CopyTo(buffer);
                    Utf8Formatter.TryFormat(rva, buffer.AsSpan(13), out _, new StandardFormat('X', 8));
                    buffer[21] = 0;
                    symbols.DefineData(variables, stats.ImageBase + rva, i32, name, ref stats);
                    if (slot.Target != 0) {
                        Core.BNAddUserDataReference(view, stats.ImageBase + rva, stats.ImageBase + (slot.Target - originalBase));
                        ++stats.DataReferences;
                    }
                }

                for (int i = 0; i < dispatch.TypeMaps.Length; ++i) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    if (dispatch.TypeMaps[i] == 0)
                        continue;
                    Core.BNAddUserDataReference(view, stats.ImageBase + (types[i].Address - originalBase),
                        stats.ImageBase + (dispatch.Maps[dispatch.TypeMaps[i] - 1].Address - originalBase));
                    ++stats.DataReferences;
                }

                foreach (ref readonly var target in CollectionsMarshal.AsSpan(dispatch.Targets)) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    ref readonly var entry = ref CollectionsMarshal.AsSpan(dispatch.Entries)[target.Entry];
                    ulong witness = stats.ImageBase + records.EntryRvas[target.Entry];
                    ulong cell = target.SealedSlot == 0 ? types[target.OwnerType].Address + 24 + (uint)entry.ImplementationSlot * 8UL
                        : dispatch.SealedSlots[target.SealedSlot - 1].Address;
                    Core.BNAddUserDataReference(view, witness, stats.ImageBase + (types[target.OwnerType].Address - originalBase));
                    Core.BNAddUserDataReference(view, witness, stats.ImageBase + (types[target.InterfaceType].Address - originalBase));
                    Core.BNAddUserDataReference(view, witness + 4, stats.ImageBase + (cell - originalBase));
                    Core.BNAddUserDataReference(view, witness + 4, stats.ImageBase + (target.Target - originalBase));
                    stats.DataReferences += 4;
                    if (target.GenericContext != 0) {
                        Core.BNAddUserDataReference(view, witness + (entry.Kind is DispatchKind.Static or DispatchKind.StaticDefault ? 6UL : 4UL),
                            stats.ImageBase + (target.GenericContext - originalBase));
                        ++stats.DataReferences;
                    }
                }

                ulong virtualMap = extraction.Header.Find(307).Start;
                for (int i = 0; i < extraction.Virtuals.Entries.Count; ++i) {
                    if (task != 0 && (processed++ & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                        throw new OperationCanceledException();
                    ref readonly var entry = ref CollectionsMarshal.AsSpan(extraction.Virtuals.Entries)[i];
                    ref readonly var slot = ref CollectionsMarshal.AsSpan(extraction.Virtuals.Slots)[i];
                    uint rva = checked((uint)(virtualMap + (uint)entry.Vertex - originalBase));
                    "rtr::307::virtual::"u8.CopyTo(buffer);
                    Utf8Formatter.TryFormat(rva, buffer.AsSpan(19), out _, new StandardFormat('X', 8));
                    buffer[27] = 0;
                    ulong address = stats.ImageBase + rva;
                    symbols.Define(address, 3, name);
                    ++stats.Symbols;
                    Core.BNAddUserDataReference(view, address, stats.ImageBase + (entry.DeclaringType - originalBase));
                    ++stats.DataReferences;
                    if (slot.DeclaringType != entry.DeclaringType) {
                        Core.BNAddUserDataReference(view, address, stats.ImageBase + (slot.DeclaringType - originalBase));
                        ++stats.DataReferences;
                    }
                    if (slot.TargetCell != 0) {
                        Core.BNAddUserDataReference(view, address, stats.ImageBase + (slot.TargetCell - originalBase));
                        ++stats.DataReferences;
                    }
                    if (slot.Target != 0) {
                        Core.BNAddUserDataReference(view, address, stats.ImageBase + (slot.Target - originalBase));
                        ++stats.DataReferences;
                    }
                }
            }

            if (records.Sites.Length == 0)
                return;
            if (!records.Sites[0].Data) {
                platform = Core.BNGetDefaultPlatform(view);
                if (platform == 0)
                    throw new NotSupportedException("The Binary Ninja view has no default platform for dispatch targets.");
            }
            fixed (byte* name = "AOT Atlas dispatch\0"u8)
            fixed (byte* icon = "🔀\0"u8) {
                tagType = Core.BNGetTagType(view, name);
                if (tagType == 0) {
                    tagType = Core.BNCreateTagType(view);
                    Core.BNTagTypeSetName(tagType, name);
                    Core.BNTagTypeSetIcon(tagType, icon);
                    Core.BNAddTagType(view, tagType);
                }
            }

            var existing = new Dictionary<ulong, int>(records.MaximumGroup);
            nint[] oldText = new nint[records.MaximumGroup];
            bool[] used = new bool[records.MaximumGroup];
            var sites = records.Sites.AsSpan();
            fixed (byte* output = buffer) {
                for (int begin = 0; begin < sites.Length;) {
                    int end = begin + 1;
                    while (end < sites.Length && sites[end].Data == sites[begin].Data && sites[end].Address == sites[begin].Address)
                        ++end;
                    bool data = sites[begin].Data;
                    ulong address = stats.ImageBase + sites[begin].Address;
                    nint function = 0;
                    if (!data) {
                        function = Core.BNGetAnalysisFunction(view, platform, address);
                        if (function == 0)
                            function = Core.BNAddFunctionForAnalysis(view, platform, address, 0, 0);
                        if (function == 0)
                            throw new InvalidDataException($"Binary Ninja rejected the dispatch target at 0x{address:X}.");
                    }
                    nuint oldCount = 0;
                    nint* tags = data ? Core.BNGetUserDataTagsOfType(view, address, tagType, &oldCount)
                        : Core.BNGetUserFunctionTagsOfType(function, tagType, &oldCount);
                    int previous = checked((int)oldCount);
                    if (previous > oldText.Length) {
                        Array.Resize(ref oldText, previous);
                        Array.Resize(ref used, previous);
                    }
                    existing.Clear();
                    existing.EnsureCapacity(previous);
                    oldText.AsSpan(0, previous).Clear();
                    used.AsSpan(0, previous).Clear();
                    try {
                        for (int i = 0; i < previous; ++i) {
                            if (!ownership.Contains(tags[i])) {
                                used[i] = true;
                                continue;
                            }
                            byte* text = Core.BNTagGetData(tags[i]);
                            oldText[i] = (nint)text;
                            var value = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(text);
                            if (value.Length >= 29 && value.StartsWith("dispatch::"u8) && value[18] == ':'
                                && value.Slice(27, 2).SequenceEqual("::"u8)
                                && uint.TryParse(value.Slice(10, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint owner)
                                && uint.TryParse(value.Slice(19, 8), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint witness))
                                existing.TryAdd(((ulong)owner << 32) | witness, i);
                        }
                        for (int i = begin; i < end; ++i) {
                            if (task != 0 && (i & 1023) == 0 && Core.BNIsBackgroundTaskCancelled(task) != 0)
                                throw new OperationCanceledException();
                            int length = DispatchRecords.WriteText(extraction, sites[i], buffer);
                            if (existing.TryGetValue(sites[i].Key, out int old)) {
                                used[old] = true;
                                var value = MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)oldText[old]);
                                if (!value.SequenceEqual(buffer.AsSpan(0, length)))
                                    Core.BNTagSetData(tags[old], output);
                            } else {
                                nint tag = Core.BNCreateTag(tagType, output);
                                ownership.Register(tag);
                                if (data)
                                    Core.BNAddUserDataTag(view, address, tag);
                                else
                                    Core.BNAddUserFunctionTag(function, tag);
                                Core.BNFreeTag(tag);
                            }
                        }
                        for (int i = 0; i < previous; ++i) {
                            if (used[i])
                                continue;
                            ownership.Remove(tags[i]);
                            if (data)
                                Core.BNRemoveUserDataTag(view, address, tags[i]);
                            else
                                Core.BNRemoveUserFunctionTag(function, tags[i]);
                            Core.BNRemoveTag(view, tags[i], 1);
                        }
                    } finally {
                        for (int i = 0; i < previous; ++i)
                            Core.BNFreeString((byte*)oldText[i]);
                        Core.BNFreeTagList(tags, oldCount);
                        if (function != 0)
                            Core.BNFreeFunction(function);
                    }
                    begin = end;
                }
            }
        } finally {
            foreach (nint type in mapTypes.Values)
                Core.BNFreeType(type);
            if (platform != 0)
                Core.BNFreePlatform(platform);
            if (tagType != 0)
                Core.BNFreeTagType(tagType);
            Core.BNFreeType(statics);
            Core.BNFreeType(instance);
            Core.BNFreeType(i32);
            Core.BNFreeType(u16);
        }
    }
}
