using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Unicode;

namespace Atlas;

public struct PInvokeModule {
    public ulong Address, NameAddress, CallingAssemblyType;
    public IndexRange Name;
    public uint SearchPath;
}

public struct PInvokeMethod {
    public ulong Address, EntryPoint;
    public IndexRange Name;
    public int Module;
    public uint Flags;
    public bool ByOrdinal => EntryPoint <= ushort.MaxValue;
}

public sealed class PInvokeFixups {
    public readonly List<PInvokeModule> Modules;
    public readonly List<PInvokeMethod> Methods;

    public PInvokeFixups(PeImage image, MethodTables types, ReflectionMaps maps) {
        int count = 0;
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            if (entry.Name == "<Module>")
                ++count;
        }

        var targets = new Dictionary<ulong, int>(count);
        foreach (ref readonly var entry in CollectionsMarshal.AsSpan(maps.Types)) {
            if (entry.Name != "<Module>")
                continue;

            ref readonly var type = ref CollectionsMarshal.AsSpan(types.Types)[types.Index[entry.MethodTable]];
            if (type.Kind == 0 && type.ElementType == 20 && type.BaseSize == 24 && type.RelatedType == 0
                && type.VtableCount == 0 && type.InterfaceCount == 0)
                targets.TryAdd(type.Address, 0);
        }

        // A shape alone is not a module identity
        // The CallingAssemblyType must resolve through TypeMap to the runtimes global module type
        var candidates = FindCells(image, targets);
        var moduleCandidates = new List<PInvokeModule>(candidates.Length);
        var modules = new Dictionary<ulong, int>(candidates.Length);
        foreach (ulong address in candidates) {
            var data = image.FileSpan(address, 28);
            ulong nameAddress = BinaryPrimitives.ReadUInt64LittleEndian(data[8..]);
            uint searchPath = BinaryPrimitives.ReadUInt32LittleEndian(data[24..]);
            if ((searchPath != 0 && (searchPath & 0x80000000) == 0) || !ReadName(image, nameAddress, out var name))
                continue;

            modules.Add(address, moduleCandidates.Count);
            moduleCandidates.Add(new PInvokeModule {
                Address = address, NameAddress = nameAddress, Name = name,
                CallingAssemblyType = BinaryPrimitives.ReadUInt64LittleEndian(data[16..]), SearchPath = searchPath
            });
        }

        candidates = FindCells(image, modules);
        Modules = new List<PInvokeModule>(moduleCandidates.Count);
        int[] moduleIndexes = new int[moduleCandidates.Count];
        Methods = new List<PInvokeMethod>(candidates.Length);
        foreach (ulong address in candidates) {
            var data = image.FileSpan(address, 28);
            ulong entryPoint = BinaryPrimitives.ReadUInt64LittleEndian(data[8..]);
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[24..]);
            if (flags is not (0 or 2 or 3))
                continue;

            IndexRange name = default;
            if (entryPoint > ushort.MaxValue && !ReadName(image, entryPoint, out name))
                continue;

            int candidate = modules[BinaryPrimitives.ReadUInt64LittleEndian(data[16..])];
            if (moduleIndexes[candidate] == 0) {
                Modules.Add(moduleCandidates[candidate]);
                moduleIndexes[candidate] = Modules.Count;
            }

            Methods.Add(new PInvokeMethod {
                Address = address, EntryPoint = entryPoint, Name = name, Flags = flags,
                Module = moduleIndexes[candidate] - 1
            });
        }
    }

    private static ulong[] FindCells(PeImage image, Dictionary<ulong, int> targets) {
        if (targets.Count == 0)
            return [];

        // Counting cheap pointer matches first bounds all output storage
        // Decode names only for those matches, without allocations per cell
        ulong[] candidates = [];
        for (int pass = 0; pass < 2; ++pass) {
            int count = 0;
            foreach (ref readonly var section in image.Sections.AsSpan()) {
                if (!section.Writable)
                    continue;
                var data = image.FileData.AsSpan(section.FileOffset, section.FileSize);
                int start = (int)((8 - (section.Rva & 7)) & 7);
                for (int offset = start; offset <= data.Length - 28; offset += 8) {
                    if (BinaryPrimitives.ReadUInt64LittleEndian(data[offset..]) != 0
                        || !targets.ContainsKey(BinaryPrimitives.ReadUInt64LittleEndian(data[(offset + 16)..])))
                        continue;

                    if (pass != 0)
                        candidates[count] = image.ImageBase + section.Rva + (uint)offset;
                    ++count;
                }
            }

            if (pass == 0)
                candidates = new ulong[count];
        }

        return candidates;
    }

    private static bool ReadName(PeImage image, ulong address, out IndexRange name) {
        name = default;
        int index = image.FindSection(address);
        if (index < 0)
            return false;

        ref readonly var section = ref image.Sections[index];
        ulong offset = address - image.ImageBase - section.Rva;
        if (offset >= (ulong)section.FileSize)
            return false;

        int start = section.FileOffset + (int)offset;
        var bytes = image.FileData.AsSpan(start, section.FileSize - (int)offset);
        int length = bytes.IndexOf((byte)0);
        if (length < 0 || !Utf8.IsValid(bytes[..length]))
            return false;

        name = new IndexRange(start, length);
        return true;
    }
}
