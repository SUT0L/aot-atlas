using System.Runtime.InteropServices;

namespace Atlas;

public enum MapFormat : byte {
    Auto, Legacy, Metadata
}

public enum FieldLocation : byte {
    Unknown, Offset, StaticAddress, StaticBlock, Ordinal
}

public struct TypeMapEntry {
    public ulong MethodTable;
    public uint Handle;
    public int Vertex, Signature;
    public string Name;
}

public readonly struct DerivedTypeEntry(int section, int vertex, ulong methodTable) {
    public readonly int Section = section, Vertex = vertex;
    public readonly ulong MethodTable = methodTable;
}

public struct InvokeMapEntry {
    public ulong DeclaringType, Entrypoint, InvokeStub;
    public uint Flags, MetadataOffset, NativeSignatureOffset;
    public int Vertex, Signature;
    public string Name;
    public IndexRange GenericArguments;
}

public struct FieldMapEntry {
    public ulong DeclaringType, StaticBase;
    public uint Flags, MetadataOffset, Value, StaticBaseIndex;
    public int Vertex, Signature;
    public string Name;
    public FieldLocation Location;

    public int Storage => (int)(Flags & 3);
}

public sealed class ReflectionMaps {
    public MapFormat Format;

    public readonly List<TypeMapEntry> Types = new(8192);
    public readonly List<DerivedTypeEntry> DerivedTypes = new(4096);
    public readonly List<InvokeMapEntry> Methods = new(32768);
    public readonly List<FieldMapEntry> Fields = new(4096);
    public readonly List<ulong> GenericArguments = new(8192);

    public static MapFormat SelectFormat(int major, ReadOnlySpan<byte> invokes, ReadOnlySpan<byte> fields,
        ReadOnlySpan<byte> nativeLayout, Metadata metadata, MapFormat requested = MapFormat.Auto) {
        if (requested != MapFormat.Auto)
            return requested;
        if (major != 12)
            return major < 12 ? MapFormat.Legacy : MapFormat.Metadata;

        bool legacy = true, modern = true, any = false;
        for (int which = 0; which < 2; ++which) {
            var data = which == 0 ? invokes : fields;
            var table = new NativeTable(data);
            while (table.MoveNext()) {
                any = true;
                var reader = new NativeReader(data, table.Vertex);
                uint flags = reader.Unsigned();
                if ((flags & (which == 0 ? 4U : 8U)) != 0) {
                    modern = false;
                    continue;
                }

                if (which != 0)
                    reader.Unsigned();

                int namePosition = reader.Position;
                uint handle = reader.Unsigned();

                // Membership in the decoded definition index proves record kind and signature together; plausible bytes do not
                if (modern)
                    modern = which == 0 ? metadata.MethodIndex.ContainsKey(handle) : metadata.FieldIndex.ContainsKey(handle);

                if (legacy) {
                    try {
                        if (which == 0) {
                            if (handle == 0 || handle >= nativeLayout.Length)
                                legacy = false;
                            else {
                                var signature = new NativeReader(nativeLayout, (int)handle);
                                legacy = signature.String().Length != 0;
                                int origin = signature.Position;
                                long target = (long)origin + signature.Signed();
                                legacy &= target > 0 && target < nativeLayout.Length;
                            }
                        } else {
                            var name = new NativeReader(data, namePosition);
                            legacy = name.String().Length != 0 && name.Remaining != 0;
                        }
                    } catch (Exception error) when (error is InvalidDataException or OverflowException or System.Text.DecoderFallbackException) {
                        legacy = false;
                    }
                }
            }
        }

        if (!any)
            return MapFormat.Metadata;
        if (legacy != modern)
            return legacy ? MapFormat.Legacy : MapFormat.Metadata;

        throw new InvalidDataException("RTR 12 reflection map grammar is unresolved; specify --map-format legacy or --map-format metadata.");
    }

    public void Read(PeImage image, ReadyToRun rtr, Metadata metadata, ReadOnlySpan<ulong> fixups, MapFormat requested = MapFormat.Auto) {
        var invokeSection = rtr.Find(306);
        var fieldSection = rtr.Find(309);
        var layoutSection = rtr.Find(330);
        var invokes = invokeSection.Length == 0 ? default : image.FileSpan(invokeSection.Start, checked((int)invokeSection.Length));
        var fields = fieldSection.Length == 0 ? default : image.FileSpan(fieldSection.Start, checked((int)fieldSection.Length));
        var nativeLayout = layoutSection.Length == 0 ? default : image.FileSpan(layoutSection.Start, checked((int)layoutSection.Length));

        Format = SelectFormat(rtr.Major, invokes, fields, nativeLayout, metadata, requested);
        bool legacy = Format == MapFormat.Legacy;

        foreach (int id in new[] { 301, 302, 303, 304, 311 }) {
            var section = rtr.Find(id);
            if (section.Length == 0)
                continue;

            var data = image.FileSpan(section.Start, checked((int)section.Length));
            var table = new NativeTable(data);
            while (table.MoveNext()) {
                var reader = new NativeReader(data, table.Vertex);
                uint index = reader.Unsigned();
                if (index >= fixups.Length)
                    throw new InvalidDataException($"Type map {id} refers outside CommonFixups.");

                if (id != 301) {
                    DerivedTypes.Add(new DerivedTypeEntry(id, table.Vertex, fixups[(int)index]));
                    continue;
                }

                uint handle = reader.Unsigned();
                int offsetBits = 32 - metadata.HandleBits;
                uint kind = handle >> offsetBits;
                if (kind is not (0x3A or 0x3D))
                    throw new InvalidDataException($"TypeMap contains an invalid metadata handle kind 0x{kind:X}.");

                uint offset = handle & ((1U << offsetBits) - 1);
                if (offset == 0)
                    throw new InvalidDataException("TypeMap contains a nil metadata handle.");

                int signature = metadata.TypeSignature((offset << metadata.HandleBits) | kind);
                string name = metadata.Signatures.Nodes[signature].Name;
                Types.Add(new TypeMapEntry {
                    MethodTable = fixups[(int)index],
                    Handle = handle,
                    Vertex = table.Vertex,
                    Signature = signature,
                    Name = kind == 0x3D ? "typeref::" + name : name
                });
            }
        }

        var invokeTable = new NativeTable(invokes);
        uint invokeMask = legacy ? 0x70FFU : rtr.Major <= 12 ? 0x70FBU : 0x70BBU;
        while (invokeTable.MoveNext()) {
            var reader = new NativeReader(invokes, invokeTable.Vertex);
            InvokeMapEntry entry = new() {
                Vertex = invokeTable.Vertex,
                Flags = reader.Unsigned()
            };
            if ((entry.Flags & ~invokeMask) != 0)
                throw new InvalidDataException($"Unknown InvokeMap flags 0x{entry.Flags:X}.");

            uint handle = reader.Unsigned();
            uint type = reader.Unsigned();
            if (type >= fixups.Length)
                throw new InvalidDataException("InvokeMap declaring type refers outside CommonFixups.");
            entry.DeclaringType = fixups[(int)type];

            if ((entry.Flags & 0x20) != 0) {
                uint index = reader.Unsigned();
                if (index >= fixups.Length)
                    throw new InvalidDataException("InvokeMap entrypoint refers outside CommonFixups.");
                entry.Entrypoint = fixups[(int)index];
                if (!image.IsExecutable(entry.Entrypoint))
                    throw new InvalidDataException("InvokeMap entrypoint is outside executable sections.");
            }

            if ((entry.Flags & 0x80) == 0) {
                uint index = reader.Unsigned();
                if (index >= fixups.Length)
                    throw new InvalidDataException("InvokeMap invoke stub refers outside CommonFixups.");
                entry.InvokeStub = fixups[(int)index];
                if (!image.IsExecutable(entry.InvokeStub))
                    throw new InvalidDataException("InvokeMap invoke stub is outside executable sections.");
            }

            if (!legacy || (entry.Flags & 4) != 0)
                entry.MetadataOffset = handle;
            else
                entry.NativeSignatureOffset = handle;

            if ((entry.Flags & 2) != 0) {
                if (legacy && (entry.Flags & 0x10) != 0)
                    entry.NativeSignatureOffset = reader.Unsigned();

                if (!(rtr.Major <= 12 && (entry.Flags & 0x40) != 0)) {
                    int count = checked((int)reader.Unsigned());
                    if (count > reader.Remaining)
                        throw new InvalidDataException("InvokeMap generic arguments exceed storage.");

                    entry.GenericArguments = new IndexRange(GenericArguments.Count, count);
                    GenericArguments.EnsureCapacity(checked(GenericArguments.Count + count));
                    for (int i = 0; i < count; ++i) {
                        uint index = reader.Unsigned();
                        if (index >= fixups.Length)
                            throw new InvalidDataException("InvokeMap generic argument refers outside CommonFixups.");
                        GenericArguments.Add(fixups[(int)index]);
                    }
                }
            }

            if (entry.MetadataOffset != 0) {
                int index = metadata.ReadMethod(entry.MetadataOffset);
                ref var method = ref CollectionsMarshal.AsSpan(metadata.Methods)[index];
                if (method.Signature == 0)
                    method.Signature = metadata.MethodSignature(method.SignatureOffset);
                entry.Name = method.Name;
                entry.Signature = method.Signature;
            } else {
                if (entry.NativeSignatureOffset == 0 || entry.NativeSignatureOffset >= nativeLayout.Length)
                    throw new InvalidDataException("InvokeMap has no readable metadata or NativeLayout method identity.");

                var name = new NativeReader(nativeLayout, (int)entry.NativeSignatureOffset);
                entry.Name = name.String();
                int origin = name.Position;
                long target = (long)origin + name.Signed();
                if (target <= 0 || target >= nativeLayout.Length)
                    throw new InvalidDataException("InvokeMap NativeLayout signature points outside storage.");
            }

            Methods.Add(entry);
        }

        var fieldTable = new NativeTable(fields);
        uint fieldMask = legacy ? 0xEFU : rtr.Major <= 12 ? 0xE7U : 0xE3U;
        while (fieldTable.MoveNext()) {
            var reader = new NativeReader(fields, fieldTable.Vertex);
            FieldMapEntry entry = new() {
                Vertex = fieldTable.Vertex,
                Flags = reader.Unsigned()
            };
            if ((entry.Flags & ~fieldMask) != 0)
                throw new InvalidDataException($"Unknown FieldAccessMap flags 0x{entry.Flags:X}.");

            uint type = reader.Unsigned();
            if (type >= fixups.Length)
                throw new InvalidDataException("FieldAccessMap declaring type refers outside CommonFixups.");
            entry.DeclaringType = fixups[(int)type];

            if (!legacy || (entry.Flags & 8) != 0) {
                entry.MetadataOffset = reader.Unsigned();
                int index = metadata.ReadField(entry.MetadataOffset);
                ref var field = ref CollectionsMarshal.AsSpan(metadata.Fields)[index];
                if (field.Signature == 0) {
                    var signature = metadata.Reader(field.SignatureOffset);
                    field.Signature = metadata.TypeSignature(signature.Unsigned());
                }
                entry.Name = field.Name;
                entry.Signature = field.Signature;
            } else
                entry.Name = reader.String();

            if (rtr.Major <= 12 && (entry.Flags & 4) != 0) {
                entry.Location = FieldLocation.Ordinal;
                entry.Value = reader.Unsigned();
            } else if (entry.Storage == 0 || (entry.Flags & 0x20) != 0) {
                entry.Location = FieldLocation.Offset;
                entry.Value = reader.Unsigned();
            } else {
                entry.StaticBaseIndex = reader.Unsigned();
                if (entry.StaticBaseIndex >= fixups.Length)
                    throw new InvalidDataException("FieldAccessMap static storage refers outside CommonFixups.");
                entry.StaticBase = fixups[(int)entry.StaticBaseIndex];
                entry.Location = entry.Storage == 1 ? FieldLocation.StaticAddress : FieldLocation.StaticBlock;
                if (entry.Storage != 1)
                    entry.Value = reader.Unsigned();
            }

            Fields.Add(entry);
        }
    }
}
