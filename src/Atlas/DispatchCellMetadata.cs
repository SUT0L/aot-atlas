using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Atlas;

public readonly record struct DispatchCellInfo {
    public RtrSectionId Section { get; init; }
    public int Vertex { get; init; }
    public int Length { get; init; }
    public int CellIndex { get; init; }
    public int CellCount { get; init; }
    public ulong FirstCell { get; init; }
    public uint TypeFixup { get; init; }
    public ulong Type { get; init; }
    public ushort Slot { get; init; }
    public uint InstantiationFixup { get; init; }
    public ulong Instantiation { get; init; }
    public uint Token { get; init; }
    public uint AsyncFlag { get; init; }
    public MethodIdentity Method { get; init; }
    public MetadataFactStatus Status { get; init; }
    public IndexRange Arguments { get; init; }

    public bool IsGvm => Section == RtrSectionId.GvmDispatchCellInfoRegion;
}

public enum DispatchCellLayout : byte { StubAndInterface, CachedMethodTableAndCode }

public readonly record struct DispatchCellMetadataFailure(RtrSectionId Section, int Vertex, int CellIndex, string Error);

public sealed class DispatchCellMetadata {
    private readonly List<DispatchCellInfo> entries = new();
    private readonly List<ulong> arguments = new();
    private readonly List<DispatchCellMetadataFailure> failures = new();
    public ReadOnlySpan<DispatchCellInfo> Entries => CollectionsMarshal.AsSpan(entries);
    public ReadOnlySpan<ulong> ArgumentAddresses => CollectionsMarshal.AsSpan(arguments);
    public ReadOnlySpan<DispatchCellMetadataFailure> Failures => CollectionsMarshal.AsSpan(failures);
    public DispatchCellLayout Layout { get; }
    public RtrSection InterfaceRegion { get; }
    public RtrSection GvmRegion { get; }
    private readonly int interfaceCount;
    internal int InterfaceCount => interfaceCount;

    internal DispatchCellMetadata(
        PeImage image,
        ReadyToRun header,
        RuntimeMemory memory,
        ulong[] references,
        MetadataBuilder metadata,
        NativeLayout layout,
        MapFormat grammar,
        MethodTables types,
        CancellationToken cancellationToken) {
        Layout = header.Format.SeparateDispatchCellInfo
            ? DispatchCellLayout.CachedMethodTableAndCode : DispatchCellLayout.StubAndInterface;
        InterfaceRegion = header.Find(RtrSectionId.InterfaceDispatchCellRegion);
        GvmRegion = header.Find(RtrSectionId.GvmDispatchCellRegion);

        if (InterfaceRegion.Length != 0 && GvmRegion.Length != 0) {
            bool overlap = InterfaceRegion.Start <= GvmRegion.Start
                ? GvmRegion.Start - InterfaceRegion.Start < InterfaceRegion.Length
                : InterfaceRegion.Start - GvmRegion.Start < GvmRegion.Length;
            if (overlap) {
                const string error = "Interface and GVM dispatch cell regions overlap.";
                failures.Add(new(RtrSectionId.InterfaceDispatchCellInfoRegion, -1, -1, error));
                failures.Add(new(RtrSectionId.GvmDispatchCellInfoRegion, -1, -1, error));
                return;
            }
        }

        Read(RtrSectionId.InterfaceDispatchCellInfoRegion, InterfaceRegion);
        interfaceCount = entries.Count;
        Read(RtrSectionId.GvmDispatchCellInfoRegion, GvmRegion);

        void Read(RtrSectionId id, RtrSection cells) {
            cancellationToken.ThrowIfCancellationRequested();
            var section = header.Find(id);
            if (section.Length == 0 && cells.Length == 0)
                return;

            int pending = -1;
            int vertex = -1;
            int cellIndex = -1;
            try {
                if (!header.Format.SeparateDispatchCellInfo)
                    throw new InvalidDataException($"RTR section {(int)id} requires the indexed dispatch cell format.");

                if (section.Length == 0 || cells.Length == 0 || (cells.Start & 7) != 0 || cells.Length % 16 != 0)
                    throw new InvalidDataException($"RTR section {(int)id} has no matching complete dispatch cell region.");

                int cellSection = image.FindSection(cells.Start);
                if (cellSection < 0 || !image.Sections[cellSection].Writable)
                    throw new InvalidDataException($"RTR section {cells.Id} is not writable dispatch cell storage.");

                ref readonly var storage = ref image.Sections[cellSection];
                ulong offset = cells.Start - image.ImageBase - storage.Rva;
                if (cells.Length > storage.VirtualSize - offset)
                    throw new InvalidDataException($"RTR section {cells.Id} extends beyond dispatch cell storage.");

                var data = image.FileSpan(section.Start, checked((int)section.Length));
                var array = new NativeArray(data);
                int count = checked((int)(cells.Length / 16));
                if (array.Count > count)
                    throw new InvalidDataException($"RTR section {(int)id} indexes beyond its dispatch cell region.");

                bool first = true;
                while (array.MoveNext()) {
                    cancellationToken.ThrowIfCancellationRequested();
                    vertex = array.Vertex;
                    cellIndex = array.Index;
                    CompleteRun(cellIndex);
                    if (first && cellIndex != 0)
                        failures.Add(new(id, vertex, 0, "Dispatch cell region has no contract for its first cell."));
                    first = false;

                    try {
                        var reader = new NativeReader(data, vertex);
                        uint typeFixup = reader.Unsigned();
                        ulong type = Reference(typeFixup);
                        var entry = new DispatchCellInfo {
                            Section = id,
                            Vertex = vertex,
                            CellIndex = cellIndex,
                            FirstCell = cells.Start + (uint)cellIndex * 16UL,
                            TypeFixup = typeFixup,
                            Type = type
                        };

                        if (id == RtrSectionId.InterfaceDispatchCellInfoRegion) {
                            entry = entry with { Slot = checked((ushort)reader.Unsigned()) };
                        } else {
                            uint instantiationFixup = reader.Unsigned();
                            ulong instantiation = Reference(instantiationFixup);
                            uint token = reader.Unsigned();
                            uint asyncFlag = reader.Unsigned();
                            if (asyncFlag > 1)
                                throw new InvalidDataException("GVM dispatch cell has an invalid async variant flag.");

                            var method = MethodIdentity.Read(token, metadata, layout, grammar, maskedAsync: true);
                            if (method.AsyncVariant)
                                throw new InvalidDataException("GVM dispatch cell token contains flags outside its separate async field.");

                            method.AsyncVariant = asyncFlag != 0;
                            entry = entry with {
                                InstantiationFixup = instantiationFixup,
                                Instantiation = instantiation,
                                Token = token,
                                AsyncFlag = asyncFlag,
                                Method = method
                            };

                            if (method.Signature == 0) {
                                // The encoded cell and method relationship are still known.
                                // Generic composition has no count of its own to recover.
                                entry = entry with { Status = MetadataFactStatus.Unresolved };
                                failures.Add(new(id, vertex, cellIndex,
                                    "GVM dispatch argument count is unavailable because its method signature is unavailable."));
                            } else {
                                int arity = metadata.SignatureBuilder.Methods[method.Signature].GenericParameterCount;
                                if (arity == 0)
                                    throw new InvalidDataException("GVM dispatch cell method is not generic.");

                                var composition = memory.Read(instantiation, checked(arity * 4));
                                int argumentStart = arguments.Count;
                                try {
                                    arguments.EnsureCapacity(checked(argumentStart + arity));
                                    for (int argument = 0; argument < arity; ++argument) {
                                        int argumentOffset = argument * 4;
                                        int delta = BinaryPrimitives.ReadInt32LittleEndian(composition[argumentOffset..]);
                                        if (delta == 0)
                                            throw new InvalidDataException("GVM dispatch cell has a null instantiation argument.");

                                        ulong address = checked((ulong)((long)instantiation + argumentOffset + delta));
                                        arguments.Add(address);
                                    }
                                } catch {
                                    arguments.RemoveRange(argumentStart, arguments.Count - argumentStart);
                                    throw;
                                }

                                entry = entry with { Arguments = new IndexRange(argumentStart, arity) };
                            }
                        }

                        types.Add(type, TypeEvidence.DispatchCell);
                        foreach (ulong argument in ArgumentAddresses.Slice(entry.Arguments.Start, entry.Arguments.Count))
                            types.Add(argument, TypeEvidence.DispatchCell);

                        entries.Add(entry with { Length = reader.Position - vertex });
                        pending = entries.Count - 1;
                    } catch (Exception error) when (error is InvalidDataException or OverflowException) {
                        failures.Add(new(id, vertex, cellIndex, error.Message));
                    }
                }

                CompleteRun(count);
                if (first)
                    failures.Add(new(id, -1, 0, "Dispatch cell region contains no indexed contracts."));
            } catch (Exception error) when (error is InvalidDataException or OverflowException) {
                failures.Add(new(id, vertex, cellIndex, error.Message));
            }

            void CompleteRun(int end) {
                if (pending < 0)
                    return;

                var previous = entries[pending];
                int length = end - previous.CellIndex;
                // Each run has an anchor at least every 100 cells in the producer.
                if (length is < 1 or > 100) {
                    failures.Add(new(id, previous.Vertex, previous.CellIndex, "Invalid sparse dispatch cell run length."));
                } else {
                    entries[pending] = previous with { CellCount = length };
                }

                pending = -1;
            }
        }

        ulong Reference(uint index) {
            if (index >= references.Length || references[(int)index] == 0)
                throw new InvalidDataException("Dispatch cell info refers outside NativeReferences or to null.");

            return references[(int)index];
        }
    }

    internal void ValidateTypes(MethodTables types, CancellationToken cancellationToken) {
        for (int i = 0; i < interfaceCount; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            var entry = entries[i];
            if (types.Types[types.Index[entry.Type]].ElementType == 0x15) {
                continue;
            }

            entries[i] = entry with { Status = entry.Status | MetadataFactStatus.InvalidHandle };
            failures.Add(new(entry.Section, entry.Vertex, entry.CellIndex,
                "Interface dispatch contract refers to a runtime type that is not an interface."));
        }
    }

    internal int Find(ulong address) {
        int low;
        int high;
        if (address >= InterfaceRegion.Start && address - InterfaceRegion.Start < InterfaceRegion.Length) {
            low = 0;
            high = interfaceCount - 1;
        } else if (address >= GvmRegion.Start && address - GvmRegion.Start < GvmRegion.Length) {
            low = interfaceCount;
            high = entries.Count - 1;
        } else {
            return -1;
        }

        while (low <= high) {
            int middle = low + ((high - low) >> 1);
            ref readonly var entry = ref CollectionsMarshal.AsSpan(entries)[middle];
            if (address < entry.FirstCell)
                high = middle - 1;
            else if (address - entry.FirstCell >= (uint)entry.CellCount * 16UL)
                low = middle + 1;
            else
                return middle;
        }

        return -1;
    }
}
