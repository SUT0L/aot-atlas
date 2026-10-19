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

internal readonly struct MetadataConstantData(MetadataValue value, int valueCount, int height) {
    private readonly string kind = value.Kind;
    private readonly object? payload = value.Value;
    private readonly string? type = value.Type;
    internal readonly int ValueCount = valueCount;
    internal readonly int Height = height;

    internal MetadataValue WithHandle(uint handle) => new(handle, kind, payload, type);
}

internal sealed partial class MetadataBuilder {
    private const int ValueLimit = 1_000_000;

    internal MetadataValue Constant(uint handle, CancellationToken cancellationToken = default) {
        EnsureMutable();
        cancellationToken.ThrowIfCancellationRequested();
        if (handle == 0)
            return new(0, "absent", null);
        int budget = ValueLimit;
        try {
            return ReadConstant(handle, 0, ref budget, out _, cancellationToken);
        } catch (OverflowException error) {
            throw new InvalidDataException("Metadata constant is outside its encoded type range.", error);
        }
    }

    private MetadataValue ReadConstant(uint handle, int depth, ref int budget, out int height,
        CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        if (Constants.TryGetValue(handle, out var cached)) {
            if (depth + cached.Height > 64)
                throw new InvalidDataException("Metadata constant nesting exceeds 64 records.");
            // Reusing storage must not make expanded payload limits depend on decode order.
            ReserveValues(ref budget, cached.ValueCount);
            height = cached.Height;
            return cached.WithHandle(handle);
        }
        int before = budget;
        ReserveValues(ref budget, 1);
        if (handle == 0) {
            height = 0;
            return new(0, "absent", null);
        }
        if (depth >= 64)
            throw new InvalidDataException("Metadata constant nesting exceeds 64 records.");
        var value = ReadConstantValue(handle, depth, ref budget, out height, cancellationToken);
        Constants.Add(handle, new(value, before - budget, height));
        return value;
    }

    private MetadataValue ReadConstantValue(uint handle, int depth, ref int budget, out int height,
        CancellationToken cancellationToken) {
        height = 1;
        var id = Decode(handle);
        AddRoot(id);
        if (id.Kind == MetadataRecordKind.ConstantReferenceValue) {
            if (id.Offset > Data.Length)
                throw new InvalidDataException("Null constant record is outside metadata storage.");
            return new(handle, "null", null);
        }
        if (IsTypeSignature(id.Kind))
            return new(handle, "type", SignatureBuilder.RenderType(TypeSignature(handle)));
        var field = RecordField(id, MetadataFieldName.Value);
        object value;
        string kind;
        switch (id.Kind) {
            case MetadataRecordKind.ConstantBooleanValue:
                kind = "bool";
                value = Required(field.Boolean, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantByteValue:
                kind = "byte";
                value = checked((byte)Required(field.UInt32, id, MetadataFieldName.Value));
                break;
            case MetadataRecordKind.ConstantCharValue:
                kind = "char";
                value = checked((ushort)Required(field.UInt32, id, MetadataFieldName.Value));
                break;
            case MetadataRecordKind.ConstantDoubleValue:
                kind = "double";
                value = Required(field.Double, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantEnumValue: {
                var nested = ReadConstant(Handle(id, MetadataFieldName.Value), depth + 1, ref budget,
                    out int nestedHeight, cancellationToken);
                height = nestedHeight + 1;
                return new(handle, "enum", nested,
                    SignatureBuilder.RenderType(TypeSignature(Handle(id, MetadataFieldName.Type))));
            }
            case MetadataRecordKind.ConstantInt16Value:
                kind = "int16";
                value = checked((short)Required(field.Int32, id, MetadataFieldName.Value));
                break;
            case MetadataRecordKind.ConstantInt32Value:
                kind = "int32";
                value = Required(field.Int32, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantInt64Value:
                kind = "int64";
                value = Required(field.Int64, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantSByteValue:
                kind = "sbyte";
                value = unchecked((sbyte)Required(field.UInt32, id, MetadataFieldName.Value));
                break;
            case MetadataRecordKind.ConstantSingleValue:
                kind = "single";
                value = Required(field.Single, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantStringValue:
                kind = "string";
                value = String(id.Offset);
                break;
            case MetadataRecordKind.ConstantUInt16Value:
                kind = "uint16";
                value = checked((ushort)Required(field.UInt32, id, MetadataFieldName.Value));
                break;
            case MetadataRecordKind.ConstantUInt32Value:
                kind = "uint32";
                value = Required(field.UInt32, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantUInt64Value:
                kind = "uint64";
                value = Required(field.UInt64, id, MetadataFieldName.Value);
                break;
            case MetadataRecordKind.ConstantEnumArray: {
                var nested = ReadConstant(Handle(id, MetadataFieldName.Value), depth + 1, ref budget,
                    out int nestedHeight, cancellationToken);
                height = nestedHeight + 1;
                return new(handle, "enum_array", nested,
                    SignatureBuilder.RenderType(TypeSignature(Handle(id, MetadataFieldName.ElementType))));
            }
            case MetadataRecordKind.ConstantHandleArray:
            case MetadataRecordKind.ConstantStringArray: {
                var items = field.Items;
                RequireComplete(items.Status);
                ReserveValues(ref budget, items.Count);
                var values = new MetadataValue[items.Count];
                for (int i = 0; i < values.Length; i++) {
                    budget++;
                    values[i] = ReadConstant(Raw(Required(items[i].Reference, id, MetadataFieldName.Value)),
                        depth + 1, ref budget, out int nestedHeight, cancellationToken);
                    height = Math.Max(height, nestedHeight + 1);
                }
                return new(handle, "array", Array.AsReadOnly(values),
                    id.Kind == MetadataRecordKind.ConstantStringArray ? "string[]" : "object[]");
            }
            default:
                return PrimitiveArray(handle, id, ref budget, cancellationToken);
        }
        return new(handle, kind, value);
    }

    private MetadataValue PrimitiveArray(uint handle, MetadataRecordId id, ref int budget,
        CancellationToken cancellationToken) => id.Kind switch {
        MetadataRecordKind.ConstantBooleanArray => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "bool", static item => ConstantScalar(item.Boolean)),
        MetadataRecordKind.ConstantByteArray => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "byte", static item => checked((byte)ConstantScalar(item.UInt32))),
        MetadataRecordKind.ConstantCharArray => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "char", static item => checked((ushort)ConstantScalar(item.UInt32))),
        MetadataRecordKind.ConstantDoubleArray => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "double", static item => ConstantScalar(item.Double)),
        MetadataRecordKind.ConstantInt16Array => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "int16", static item => checked((short)ConstantScalar(item.Int32))),
        MetadataRecordKind.ConstantInt32Array => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "int32", static item => ConstantScalar(item.Int32)),
        MetadataRecordKind.ConstantInt64Array => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "int64", static item => ConstantScalar(item.Int64)),
        MetadataRecordKind.ConstantSByteArray => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "sbyte", static item => unchecked((sbyte)ConstantScalar(item.UInt32))),
        MetadataRecordKind.ConstantSingleArray => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "single", static item => ConstantScalar(item.Single)),
        MetadataRecordKind.ConstantUInt16Array => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "uint16", static item => checked((ushort)ConstantScalar(item.UInt32))),
        MetadataRecordKind.ConstantUInt32Array => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "uint32", static item => ConstantScalar(item.UInt32)),
        MetadataRecordKind.ConstantUInt64Array => PrimitiveArray(handle, id, ref budget, cancellationToken,
            "uint64", static item => ConstantScalar(item.UInt64)),
        _ => throw new InvalidDataException($"Unsupported NativeFormat constant kind {id.Kind}.")
    };

    private MetadataValue PrimitiveArray<T>(uint handle, MetadataRecordId id, ref int budget,
        CancellationToken cancellationToken, string elementType, Func<MetadataDecodedField, T> decode) {
        var items = RecordField(id, MetadataFieldName.Value).Items;
        RequireComplete(items.Status);
        ReserveValues(ref budget, items.Count);
        T[] values = new T[items.Count];
        for (int i = 0; i < values.Length; i++) {
            if ((i & 1023) == 0)
                cancellationToken.ThrowIfCancellationRequested();
            values[i] = decode(items[i]);
        }
        return new(handle, "array", Array.AsReadOnly(values), elementType + "[]");
    }

    private static T ConstantScalar<T>(MetadataFact<T> fact) {
        if (!fact.IsAvailable)
            throw new InvalidDataException($"Constant element at 0x{fact.Source.Offset:X} is unavailable ({fact.Status}).");
        return fact.Value;
    }

    private static void RequireComplete(MetadataFactStatus status) {
        if (status != MetadataFactStatus.Valid)
            throw new InvalidDataException($"Constant collection is partial ({status}).");
    }

    private static void ReserveValues(ref int budget, int count) {
        if (count > budget)
            throw new InvalidDataException("Metadata payload exceeds one million materialized values.");
        budget -= count;
    }

    internal MetadataAttributePayload AttributePayload(uint offset, CancellationToken cancellationToken = default) {
        EnsureMutable();
        cancellationToken.ThrowIfCancellationRequested();
        if (AttributePayloads.TryGetValue(offset, out var cached))
            return cached;
        var id = Id(MetadataRecordKind.CustomAttribute, offset);
        uint constructor = Handle(id, MetadataFieldName.Constructor);
        uint type = AttributeOwner(constructor);
        int budget = ValueLimit;
        var fixedItems = RecordField(id, MetadataFieldName.FixedArguments).Items;
        RequireComplete(fixedItems.Status);
        ReserveValues(ref budget, fixedItems.Count);
        var fixedArguments = new MetadataValue[fixedItems.Count];
        for (int i = 0; i < fixedArguments.Length; i++) {
            budget++;
            fixedArguments[i] = ReadConstant(Raw(Required(fixedItems[i].Reference, id, MetadataFieldName.FixedArguments)),
                0, ref budget, out _, cancellationToken);
        }
        var namedItems = RecordField(id, MetadataFieldName.NamedArguments).Items;
        RequireComplete(namedItems.Status);
        ReserveValues(ref budget, namedItems.Count);
        var namedArguments = new MetadataNamedArgument[namedItems.Count];
        for (int i = 0; i < namedArguments.Length; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            var named = Required(namedItems[i].Reference, id, MetadataFieldName.NamedArguments);
            uint flags = UInt(named, MetadataFieldName.Flags);
            if (flags > 1)
                throw new InvalidDataException("Invalid named attribute argument flags.");
            namedArguments[i] = new(flags, Name(named),
                SignatureBuilder.RenderType(TypeSignature(Handle(named, MetadataFieldName.Type))),
                ReadConstant(Handle(named, MetadataFieldName.Value), 0, ref budget, out _, cancellationToken));
        }
        var result = new MetadataAttributePayload(offset, constructor,
            SignatureBuilder.RenderType(TypeSignature(type)), fixedArguments, namedArguments);
        AttributePayloads.Add(offset, result);
        return result;
    }

    internal System.Collections.ObjectModel.ReadOnlyCollection<MetadataAttributePayload> ScopeAttributePayloads(
        uint offset, bool module = false, CancellationToken cancellationToken = default) {
        EnsureMutable();
        cancellationToken.ThrowIfCancellationRequested();
        var key = (offset, module);
        if (ScopePayloads.TryGetValue(key, out var cached))
            return cached;
        var id = Id(MetadataRecordKind.ScopeDefinition, offset);
        var items = RecordField(id, module ? MetadataFieldName.ModuleCustomAttributes : MetadataFieldName.CustomAttributes).Items;
        RequireComplete(items.Status);
        if (items.Count > ValueLimit)
            throw new InvalidDataException("Scope payload exceeds one million materialized values.");
        var values = new MetadataAttributePayload[items.Count];
        for (int i = 0; i < values.Length; i++) {
            cancellationToken.ThrowIfCancellationRequested();
            values[i] = AttributePayload(Required(items[i].Reference, id, MetadataFieldName.CustomAttributes).Offset, cancellationToken);
        }
        var result = Array.AsReadOnly(values);
        ScopePayloads.Add(key, result);
        return result;
    }
}
