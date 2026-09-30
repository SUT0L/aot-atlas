using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public struct UnwindEntry {
    public uint Address;
    public RuntimeFunction Function;
    public int Info, Parent, Root;
    public bool Indirect;
}

public struct UnwindInfo {
    public uint Address, Handler;
    public byte VersionFlags, PrologSize, SlotCount, Frame;
    public ushort Length;
    public int ChainedEntry;

    public int Version => VersionFlags & 7;
    public int Flags => VersionFlags >> 3;
    public int TailOffset => (4 + SlotCount * 2 + 3) & ~3;
}

public sealed class UnwindTables {
    public readonly int DirectoryCount;
    public readonly List<UnwindEntry> Entries;
    public readonly List<UnwindInfo> Infos;

    public UnwindTables(PeImage image) {
        var functions = RuntimeTables.Functions(image);
        DirectoryCount = functions.Length;
        Entries = new List<UnwindEntry>(functions.Length);
        Infos = new List<UnwindInfo>(functions.Length);
        var entries = new Dictionary<uint, int>();
        var infos = new Dictionary<uint, int>(functions.Length);
        for (int i = 0; i < functions.Length; ++i) {
            uint address = checked(image.ExceptionRva + (uint)i * 12);
            Entries.Add(new UnwindEntry { Address = address, Function = functions[i] });
        }

        for (int cursor = 0; cursor < Entries.Count; ++cursor) {
            var entry = Entries[cursor];
            uint unwind = entry.Function.Unwind;
            if ((unwind & 1) != 0) {
                entry.Indirect = true;
                entry.Parent = ReadEntry(image, unwind & ~1U, entries);
            } else {
                if (!infos.TryGetValue(unwind, out int index)) {
                    var header = image.FileSpan(image.ImageBase + unwind, 4);
                    UnwindInfo info = new() {
                        Address = unwind,
                        VersionFlags = header[0],
                        PrologSize = header[1],
                        SlotCount = header[2],
                        Frame = header[3]
                    };
                    if (info.Version is not (1 or 2))
                        throw new NotSupportedException($"Unsupported AMD64 unwind version {info.Version} at RVA 0x{unwind:X}.");
                    if ((info.Flags & ~7) != 0 || ((info.Flags & 4) != 0 && (info.Flags & 3) != 0))
                        throw new InvalidDataException("Unwind flags combine incompatible handler and chain formats.");

                    // NativeAOT can put its private trailer immediately after the slots
                    // Padding belongs to the Windows tail only
                    int length = 4 + info.SlotCount * 2;
                    if ((info.Flags & 4) != 0) {
                        length = info.TailOffset + 12;
                        info.ChainedEntry = ReadEntry(image, checked(unwind + (uint)info.TailOffset), entries);
                    } else if ((info.Flags & 3) != 0) {
                        length = info.TailOffset + 4;
                        info.Handler = BinaryPrimitives.ReadUInt32LittleEndian(image.FileSpan(image.ImageBase + unwind + (uint)info.TailOffset, 4));
                        if (!image.IsExecutable(image.ImageBase + info.Handler))
                            throw new InvalidDataException("Windows unwind handler is outside executable storage.");
                    }
                    image.FileSpan(image.ImageBase + unwind, length);
                    info.Length = checked((ushort)length);
                    index = Infos.Count + 1;
                    infos.Add(unwind, index);
                    Infos.Add(info);
                }

                entry.Info = index;
                entry.Parent = Infos[index - 1].ChainedEntry;
            }

            Entries[cursor] = entry;
        }

        var records = CollectionsMarshal.AsSpan(Entries);
        var state = new byte[records.Length];
        var path = new int[records.Length];
        for (int i = 0; i < records.Length; ++i) {
            int current = i, count = 0;
            while (state[current] != 2) {
                if (state[current] == 1)
                    throw new InvalidDataException("Cyclic Windows unwind records.");

                state[current] = 1;
                path[count++] = current;
                if (records[current].Parent == 0) {
                    records[current].Root = current + 1;
                    state[current] = 2;
                    break;
                }
                current = records[current].Parent - 1;
            }

            int root = records[current].Root;
            while (count != 0) {
                int member = path[--count];
                records[member].Root = root;
                state[member] = 2;
            }
        }
    }

    private int ReadEntry(PeImage image, uint address, Dictionary<uint, int> index) {
        uint directoryOffset = unchecked(address - image.ExceptionRva);
        if (directoryOffset < image.ExceptionSize) {
            if (directoryOffset % 12 != 0)
                throw new InvalidDataException("An indirect or chained pointer addresses the middle of a RUNTIME_FUNCTION.");
            return (int)(directoryOffset / 12) + 1;
        }

        if (index.TryGetValue(address, out int existing))
            return existing;
        if ((address & 3) != 0)
            throw new InvalidDataException("An indirect or chained RUNTIME_FUNCTION is not DWORD aligned.");

        var row = image.FileSpan(image.ImageBase + address, 12);
        uint begin = BinaryPrimitives.ReadUInt32LittleEndian(row);
        uint end = BinaryPrimitives.ReadUInt32LittleEndian(row[4..]);
        uint unwind = BinaryPrimitives.ReadUInt32LittleEndian(row[8..]);
        RuntimeFunction function = new(begin, end, unwind);
        RuntimeTables.ValidateFunction(image, address, function);

        int result = Entries.Count + 1;
        index.Add(address, result);
        Entries.Add(new UnwindEntry { Address = address, Function = function });
        return result;
    }
}
