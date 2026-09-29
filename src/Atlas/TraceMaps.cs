using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Atlas;

public struct TraceMethod {
    public int Offset, DeclaringType, Signature;
    public uint TypeToken, NameOffset, SignatureOffset, ParameterNamesOffset;
    public ulong Entrypoint;
    public string Name;
    public IndexRange ParameterNames, TypeParameterNames;
    public bool Hidden;
}

public readonly struct TracePoint(int nativeOffset, int line, int document) {
    public readonly int NativeOffset = nativeOffset, Line = line, Document = document;
}

public readonly struct TraceLines(int vertex, ulong entrypoint, IndexRange points) {
    public readonly int Vertex = vertex;
    public readonly ulong Entrypoint = entrypoint;
    public readonly IndexRange Points = points;
}

public sealed class TraceMaps {
    public readonly List<TraceMethod> Methods = new(65536);
    public readonly List<string> ParameterNames = new(256);
    public readonly List<string> Documents = new(1024);
    public readonly List<TraceLines> Lines = new(8192);
    public readonly List<TracePoint> Points = new(65536);

    public TraceMaps(PeImage image, ReadyToRun rtr, Metadata metadata, ReadOnlySpan<ulong> fixups) {
        var section = rtr.Find(327);
        if (section.Length != 0)
            ReadMethods(image.FileSpan(section.Start, checked((int)section.Length)), section.Start, image, metadata);

        section = rtr.Find(329);
        if (section.Length != 0)
            ReadDocuments(image.FileSpan(section.Start, checked((int)section.Length)));

        section = rtr.Find(328);
        if (section.Length != 0)
            ReadLines(image.FileSpan(section.Start, checked((int)section.Length)), image, fixups);
    }

    private void ReadMethods(ReadOnlySpan<byte> data, ulong address, PeImage image, Metadata metadata) {
        var reader = new NativeReader(data);
        int count = BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4));
        if (count < 0 || count > reader.Remaining / 5)
            throw new InvalidDataException("Stack-trace entry count exceeds its storage.");

        Methods.EnsureCapacity(count);
        TraceMethod current = new() { Name = "" };
        var parameterIndex = new Dictionary<uint, IndexRange>();
        int offsetBits = 32 - metadata.HandleBits;
        uint offsetMask = (1U << offsetBits) - 1;

        for (int i = 0; i < count; ++i) {
            current.Offset = reader.Position;
            byte command = reader.Take(1)[0];
            if ((command & ~31) != 0 || (command & 12) == 12)
                throw new InvalidDataException("Invalid stack-trace command flags.");

            if ((command & 1) != 0) {
                current.TypeToken = BinaryPrimitives.ReadUInt32LittleEndian(reader.Take(4));
                uint kind = current.TypeToken >> offsetBits;
                if (current.TypeToken != 0 && kind is not (0x3A or 0x3D or 0x3E))
                    throw new InvalidDataException("Stack-trace owner is not a metadata type handle.");

                uint handle = ((current.TypeToken & offsetMask) << metadata.HandleBits) | kind;
                current.DeclaringType = metadata.TypeSignature(handle);
                current.TypeParameterNames = default;
                if (kind == 0x3A && metadata.TypeIndex.TryGetValue(current.TypeToken & offsetMask, out int typeIndex)) {
                    var parameters = metadata.Types[typeIndex].GenericParameters;
                    current.TypeParameterNames = new IndexRange(ParameterNames.Count, parameters.Count);
                    for (int j = 0; j < parameters.Count; ++j) {
                        var parameter = metadata.Reader(metadata.Handles[parameters.Start + j]);
                        if (parameter.Unsigned() != j)
                            throw new InvalidDataException("Stack-trace type parameters are out of order.");

                        parameter.Unsigned();
                        parameter.Unsigned();
                        ParameterNames.Add(metadata.String(parameter.Unsigned()));
                    }
                }
            }

            if ((command & 2) != 0) {
                current.NameOffset = reader.Unsigned();
                current.Name = metadata.String(current.NameOffset);
            }

            if ((command & 12) != 0) {
                current.SignatureOffset = reader.Unsigned();
                current.Signature = current.SignatureOffset == 0 ? 0 : metadata.MethodSignature(current.SignatureOffset);
                current.ParameterNames = default;
                current.ParameterNamesOffset = 0;
            }

            if ((command & 8) != 0) {
                current.ParameterNamesOffset = reader.Unsigned();
                ref var range = ref CollectionsMarshal.GetValueRefOrAddDefault(parameterIndex, current.ParameterNamesOffset, out bool known);
                if (!known) {
                    var parameters = metadata.Reader(current.ParameterNamesOffset);
                    int length = checked((int)parameters.Unsigned());
                    if (length > parameters.Remaining)
                        throw new InvalidDataException("Stack-trace generic parameter names exceed their storage.");

                    range = new IndexRange(ParameterNames.Count, length);
                    ParameterNames.EnsureCapacity(checked(ParameterNames.Count + length));
                    uint kindMask = (1U << metadata.HandleBits) - 1;

                    for (int j = 0; j < length; ++j) {
                        uint handle = parameters.Unsigned();
                        if ((handle & kindMask) != 0x1A)
                            throw new InvalidDataException("Stack-trace generic parameter name is not a string handle.");

                        string name = metadata.String(handle >> metadata.HandleBits);
                        if (name.Length == 0)
                            throw new InvalidDataException("Stack-trace generic parameter has no name.");

                        ParameterNames.Add(name);
                    }
                }

                current.ParameterNames = range;
                if (range.Count == 0 || range.Count != metadata.Signatures.Methods[current.Signature].GenericParameterCount)
                    throw new InvalidDataException("Stack-trace generic parameter names do not match the signature arity.");
            }

            ulong cell = checked(address + (uint)reader.Position);
            int delta = BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4));
            current.Entrypoint = checked((ulong)((long)cell + delta));
            if (!image.IsExecutable(current.Entrypoint))
                throw new InvalidDataException("Stack-trace entrypoint is outside executable storage.");

            current.Hidden = (command & 16) != 0;
            if (!current.Hidden && (current.DeclaringType == 0 || current.Name.Length == 0 || current.Signature == 0))
                throw new InvalidDataException("Visible stack-trace method has incomplete metadata.");

            Methods.Add(current);
        }

        if (reader.Remaining != 0)
            throw new InvalidDataException("Stack-trace data extends beyond its declared entry count.");
    }

    private void ReadDocuments(ReadOnlySpan<byte> data) {
        if (data.Length < 4)
            throw new InvalidDataException("Truncated stack-trace document table.");

        uint first = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (first == 0 || first % 4 != 0 || first > data.Length)
            throw new InvalidDataException("Invalid stack-trace document table extent.");

        int count = (int)(first / 4);
        Documents.EnsureCapacity(count);
        var utf8 = new UTF8Encoding(false, true);

        for (int i = 0; i < count; ++i) {
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(data[(i * 4)..]);
            if (offset < first || offset >= data.Length)
                throw new InvalidDataException("Stack-trace document offset exceeds string storage.");

            var bytes = data[(int)offset..];
            int end = bytes.IndexOf((byte)0);
            if (end < 0)
                throw new InvalidDataException("Unterminated stack-trace document name.");

            Documents.Add(utf8.GetString(bytes[..end]));
        }
    }

    private void ReadLines(ReadOnlySpan<byte> data, PeImage image, ReadOnlySpan<ulong> fixups) {
        var table = new NativeTable(data);
        while (table.MoveNext()) {
            var reader = new NativeReader(data, table.Vertex);
            uint index = reader.Unsigned();
            if (index >= fixups.Length || !image.IsExecutable(fixups[(int)index]))
                throw new InvalidDataException("Stack-trace line map has no executable CommonFixups entrypoint.");

            ulong entrypoint = fixups[(int)index];
            int count = checked((int)reader.Unsigned());
            if (count == 0 || count > reader.Remaining / 2)
                throw new InvalidDataException("Stack-trace sequence points exceed their storage.");

            var range = new IndexRange(Points.Count, count);
            Points.EnsureCapacity(checked(Points.Count + count));
            int document = 0, offset = 0, line = 0;

            for (int i = 0; i < count; ++i) {
                int delta = reader.Signed();
                if (i == 0) {
                    document = delta;
                    delta = reader.Signed();
                } else if (delta == 0) {
                    document = reader.Signed();
                    delta = reader.Signed();
                }

                offset = checked(offset + delta);
                line = checked(line + reader.Signed());
                if ((uint)document >= Documents.Count || offset < 0 || line < 0)
                    throw new InvalidDataException("Invalid stack-trace sequence point.");

                Points.Add(new TracePoint(offset, line, document));
            }

            Lines.Add(new TraceLines(table.Vertex, entrypoint, range));
        }
    }
}
