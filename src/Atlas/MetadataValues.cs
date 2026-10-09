using System.Buffers.Binary;

namespace Atlas;

public readonly record struct MetadataValue(uint Handle, string Kind, object? Value, string? Type = null);
public readonly record struct MetadataNamedArgument(uint Flags, string Name, string Type, MetadataValue Value);
public readonly struct MetadataAttributePayload {
    public readonly uint Offset;
    public readonly uint Constructor;
    public readonly string Type;
    internal readonly MetadataValue[] FixedArguments;
    internal readonly MetadataNamedArgument[] NamedArguments;
    public ReadOnlySpan<MetadataValue> FixedArgumentValues => FixedArguments;
    public ReadOnlySpan<MetadataNamedArgument> NamedArgumentValues => NamedArguments;

    internal MetadataAttributePayload(
        uint offset,
        uint constructor,
        string type,
        MetadataValue[] fixedArguments,
        MetadataNamedArgument[] namedArguments) {
        Offset = offset;
        Constructor = constructor;
        Type = type;
        FixedArguments = fixedArguments;
        NamedArguments = namedArguments;
    }
}

public sealed partial class Metadata {
    private const int ValueLimit = 1_000_000;

    public MetadataValue Constant(uint handle, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        using var operation = new SignatureOperation(this);
        int budget = ValueLimit - 1;

        try {
            var value = ReadConstant(handle, 0, ref budget, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return value;
        } catch (OverflowException e) {
            operation.Rollback();
            throw new InvalidDataException("Metadata constant is outside its encoded type range.", e);
        } catch {
            operation.Rollback();
            throw;
        }
    }

    // The caller reserves each result slot before decoding it. Nested arrays
    // reserve their full capacity before allocation, including shared references.
    private MetadataValue ReadConstant(uint handle, int depth, ref int budget, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        if (handle == 0)
            return new(handle, "absent", null);

        if (depth >= 64)
            throw new InvalidDataException("Metadata constant nesting exceeds 64 records.");

        uint kind = handle & ((1U << HandleBits) - 1);
        if (LegacyConstants && kind == 7)
            kind = 6;

        // Null reference records contain no bytes; their offset can be at the end of storage.
        if (kind == 0x14) {
            if ((handle >> HandleBits) > Data.Length)
                throw new InvalidDataException("Null constant record is outside metadata storage.");

            return new(handle, "null", null);
        }

        var reader = Reader(handle >> HandleBits);
        object? value;
        string name;

        switch (kind) {
            case 4:
                name = "bool";
                value = Boolean(ref reader);
                break;

            case 6:
                name = "byte";
                value = reader.Take(1)[0];
                break;

            case 8:
                name = "char";
                value = checked((ushort)reader.Unsigned());
                break;

            case 0xa:
                name = "double";
                value = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(reader.Take(8)));
                break;

            case 0xc: {
                uint underlying = reader.Unsigned();
                uint type = reader.Unsigned();
                ReserveValues(ref budget, 1);

                return new(
                    handle,
                    "enum",
                    ReadConstant(underlying, depth + 1, ref budget, cancellationToken),
                    SignatureBuilder.RenderType(TypeSignature(type)));
            }

            case 0xf:
                name = "int16";
                value = checked((short)reader.Signed());
                break;

            case 0x11:
                name = "int32";
                value = reader.Signed();
                break;

            case 0x13:
                name = "int64";
                value = reader.SignedLong();
                break;

            case 0x16:
                name = "sbyte";
                value = unchecked((sbyte)reader.Take(1)[0]);
                break;

            case 0x18:
                name = "single";
                value = BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4)));
                break;

            case 0x1a:
                name = "string";
                value = String(handle >> HandleBits);
                break;

            case 0x1c:
                name = "uint16";
                value = checked((ushort)reader.Unsigned());
                break;

            case 0x1e:
                name = "uint32";
                value = reader.Unsigned();
                break;

            case 0x20:
                name = "uint64";
                value = reader.UnsignedLong();
                break;

            case 0x3a:
            case 0x3c:
            case 0x3d:
            case 0x3e:
                return new(handle, "type", SignatureBuilder.RenderType(TypeSignature(handle)));

            case 0xb: {
                uint type = reader.Unsigned();
                ReserveValues(ref budget, 1);

                return new(
                    handle,
                    "enum_array",
                    ReadConstant(reader.Unsigned(), depth + 1, ref budget, cancellationToken),
                    SignatureBuilder.RenderType(TypeSignature(type)));
            }

            case 3:
            case 5:
            case 7:
            case 9:
            case 0xe:
            case 0x10:
            case 0x12:
            case 0x15:
            case 0x17:
            case 0x1b:
            case 0x1d:
            case 0x1f: {
                int count = Count(ref reader);
                ReserveValues(ref budget, count);

                var values = new object[count];

                for (int i = 0; i < count; ++i) {
                    if ((i & 1023) == 0)
                        cancellationToken.ThrowIfCancellationRequested();

                    values[i] = kind switch {
                        3 => Boolean(ref reader),
                        5 => reader.Take(1)[0],
                        7 => checked((ushort)reader.Unsigned()),
                        9 => BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(reader.Take(8))),
                        0xe => checked((short)reader.Signed()),
                        0x10 => reader.Signed(),
                        0x12 => reader.SignedLong(),
                        0x15 => unchecked((sbyte)reader.Take(1)[0]),
                        0x17 => BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(reader.Take(4))),
                        0x1b => checked((ushort)reader.Unsigned()),
                        0x1d => reader.Unsigned(),
                        0x1f => reader.UnsignedLong(),
                        _ => throw new InvalidDataException("Invalid primitive array kind.")
                    };
                }

                string element = kind switch {
                    3 => "bool",
                    5 => "byte",
                    7 => "char",
                    9 => "double",
                    0xe => "int16",
                    0x10 => "int32",
                    0x12 => "int64",
                    0x15 => "sbyte",
                    0x17 => "single",
                    0x1b => "uint16",
                    0x1d => "uint32",
                    _ => "uint64"
                };

                return new(handle, "array", Array.AsReadOnly(values), element + "[]");
            }

            case 0xd:
            case 0x19: {
                var values = ReadValues(ref reader, depth + 1, ref budget, cancellationToken);

                return new(handle, "array", Array.AsReadOnly(values), kind == 0x19 ? "string[]" : "object[]");
            }

            default:
                throw new InvalidDataException($"Unsupported NativeFormat constant kind 0x{kind:X}.");
        }

        return new(handle, name, value);
    }

    private MetadataValue[] ReadValues(ref NativeReader reader, int depth, ref int budget,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        int count = Count(ref reader);
        ReserveValues(ref budget, count);

        var values = new MetadataValue[count];

        for (int i = 0; i < count; ++i)
            values[i] = ReadConstant(reader.Unsigned(), depth, ref budget, cancellationToken);

        return values;
    }

    private static void ReserveValues(ref int budget, int count) {
        if (count > budget)
            throw new InvalidDataException("Metadata payload exceeds one million materialized values.");

        budget -= count;
    }

    private static bool Boolean(ref NativeReader reader) {
        byte value = reader.Take(1)[0];
        if (value > 1)
            throw new InvalidDataException("Invalid Boolean constant.");

        return value != 0;
    }

    private static int Count(ref NativeReader reader) {
        uint count = reader.Unsigned();
        if (count > reader.Remaining || count > ValueLimit)
            throw new InvalidDataException("Constant collection exceeds metadata storage.");

        return (int)count;
    }

    public MetadataAttributePayload AttributePayload(uint offset, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        using var operation = new SignatureOperation(this);
        int budget = ValueLimit;

        try {
            var attribute = ReadAttributePayload(offset, ref budget, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return attribute;
        } catch (OverflowException e) {
            operation.Rollback();
            throw new InvalidDataException("Attribute value is outside its encoded type range.", e);
        } catch {
            operation.Rollback();
            throw;
        }
    }

    private MetadataAttributePayload ReadAttributePayload(uint offset, ref int budget,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        var reader = Reader(offset);
        uint constructor = reader.Unsigned();

        var ctor = Reader(constructor >> HandleBits);
        uint type = (constructor & ((1U << HandleBits) - 1)) switch {
            0x36 => MethodOwner(ref ctor),
            0x27 => ctor.Unsigned(),
            _ => throw new InvalidDataException("Invalid custom attribute constructor.")
        };

        var fixedArguments = ReadValues(ref reader, 0, ref budget, cancellationToken);

        int namedCount = Count(ref reader);
        ReserveValues(ref budget, namedCount);

        var namedArguments = new MetadataNamedArgument[namedCount];

        for (int i = 0; i < namedArguments.Length; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            var named = Reader(reader.Unsigned());
            uint flags = named.Unsigned();
            if (flags > 1)
                throw new InvalidDataException("Invalid named attribute argument flags.");

            string name = String(named.Unsigned());
            string argumentType = SignatureBuilder.RenderType(TypeSignature(named.Unsigned()));
            namedArguments[i] = new(flags, name, argumentType,
                ReadConstant(named.Unsigned(), 0, ref budget, cancellationToken));
        }

        return new(
            offset,
            constructor,
            SignatureBuilder.RenderType(TypeSignature(type)),
            fixedArguments,
            namedArguments);
    }

    public System.Collections.ObjectModel.ReadOnlyCollection<MetadataAttributePayload> ScopeAttributePayloads(
        uint offset, bool module = false, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();
        using var operation = new SignatureOperation(this);

        try {
            var attributes = ReadScopeAttributePayloads(offset, module, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return Array.AsReadOnly(attributes);
        } catch (OverflowException error) {
            operation.Rollback();
            throw new InvalidDataException("Scope attribute value is outside its encoded type range.", error);
        } catch {
            operation.Rollback();
            throw;
        }
    }

    private MetadataAttributePayload[] ReadScopeAttributePayloads(uint offset, bool module,
        CancellationToken cancellationToken) {
        var reader = Reader(offset);

        for (int i = 0; i < 7; ++i)
            reader.Unsigned();

        reader.Take(checked((int)reader.Unsigned()));

        for (int i = 0; i < 4; ++i)
            reader.Unsigned();

        int count = Count(ref reader);
        if (module) {
            for (int i = 0; i < count; ++i) {
                if ((i & 1023) == 0)
                    cancellationToken.ThrowIfCancellationRequested();
                reader.Unsigned();
            }

            reader.Unsigned();
            reader.Take(checked((int)reader.Unsigned()));
            count = Count(ref reader);
        }

        if (count == 0)
            return [];

        // Input and payloads are immutable. Repeated handles share one decode
        // within this transaction; the budget bounds all materialized rows and values.
        int budget = ValueLimit;
        ReserveValues(ref budget, count);
        var attributes = new MetadataAttributePayload[count];
        var decoded = new Dictionary<uint, MetadataAttributePayload>();

        for (int i = 0; i < count; ++i) {
            cancellationToken.ThrowIfCancellationRequested();
            uint attributeOffset = reader.Unsigned();
            if (!decoded.TryGetValue(attributeOffset, out var attribute)) {
                attribute = ReadAttributePayload(attributeOffset, ref budget, cancellationToken);
                decoded.Add(attributeOffset, attribute);
            }

            attributes[i] = attribute;
        }

        return attributes;
    }

    private uint MethodOwner(ref NativeReader reader) {
        reader.Unsigned();

        return checked(reader.Unsigned() * (1U << HandleBits)) | 0x3A;
    }
}
