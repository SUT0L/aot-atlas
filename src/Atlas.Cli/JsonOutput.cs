using System.Buffers;
using System.Diagnostics;
using System.Text.Json;

internal static class JsonOutput {
    // Bound worst-case escaping and UTF-16 transcoding to the 64 KiB output buffer.
    private const int TextSegmentLength = 2 * 1024;
    private const int Utf8SegmentLength = 8 * 1024;
    private const int Base64SegmentLength = 32 * 1024;

    internal static Utf8JsonWriter CreateWriter(Stream stream, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();

        return new Utf8JsonWriter(new StreamBuffer(stream, cancellationToken), new JsonWriterOptions { Indented = true });
    }

    internal static void WriteString(Utf8JsonWriter json, string propertyName, string? value) {
        if (value is null)
            json.WriteNull(propertyName);
        else
            WriteString(json, propertyName, value.AsSpan());
    }

    internal static void WriteString(Utf8JsonWriter json, string propertyName, ReadOnlySpan<char> value) {
        if (value.Length <= TextSegmentLength) {
            json.WriteString(propertyName, value);
            return;
        }

        json.WritePropertyName(propertyName);
        WriteStringValue(json, value);
    }

    internal static void WriteStringValue(Utf8JsonWriter json, string? value) {
        if (value is null)
            json.WriteNullValue();
        else
            WriteStringValue(json, value.AsSpan());
    }

    internal static void WriteStringValue(Utf8JsonWriter json, ReadOnlySpan<char> value) {
        if (value.Length <= TextSegmentLength) {
            json.WriteStringValue(value);
            return;
        }

        // The writer carries a split surrogate between segments and applies its configured encoder.
        while (value.Length > TextSegmentLength) {
            json.WriteStringValueSegment(value[..TextSegmentLength], isFinalSegment: false);
            value = value[TextSegmentLength..];
        }

        json.WriteStringValueSegment(value, isFinalSegment: true);
    }

    internal static void WriteString(Utf8JsonWriter json, string propertyName, ReadOnlySpan<byte> utf8Value) {
        if (utf8Value.Length <= Utf8SegmentLength) {
            json.WriteString(propertyName, utf8Value);
            return;
        }

        json.WritePropertyName(propertyName);

        while (utf8Value.Length > Utf8SegmentLength) {
            json.WriteStringValueSegment(utf8Value[..Utf8SegmentLength], isFinalSegment: false);
            utf8Value = utf8Value[Utf8SegmentLength..];
        }

        json.WriteStringValueSegment(utf8Value, isFinalSegment: true);
    }

    internal static void WriteBase64String(Utf8JsonWriter json, string propertyName, ReadOnlySpan<byte> value) {
        if (value.Length <= Base64SegmentLength) {
            json.WriteBase64String(propertyName, value);
            return;
        }

        json.WritePropertyName(propertyName);

        while (value.Length > Base64SegmentLength) {
            json.WriteBase64StringSegment(value[..Base64SegmentLength], isFinalSegment: false);
            value = value[Base64SegmentLength..];
        }

        json.WriteBase64StringSegment(value, isFinalSegment: true);
    }

    internal static void WriteHexString(Utf8JsonWriter json, string propertyName,
        ReadOnlySpan<byte> value, bool lowercase = false) {
        json.WritePropertyName(propertyName);
        Span<byte> hex = stackalloc byte[Utf8SegmentLength];

        do {
            int length = Math.Min(value.Length, hex.Length / 2);
            var segment = value[..length];
            var destination = hex[..(length * 2)];
            int written;
            bool converted = lowercase
                ? Convert.TryToHexStringLower(segment, destination, out written)
                : Convert.TryToHexString(segment, destination, out written);

            // Two ASCII hex digits per input byte guarantee sufficient conversion storage.
            Debug.Assert(converted && written == destination.Length);
            value = value[length..];
            json.WriteStringValueSegment(destination, isFinalSegment: value.IsEmpty);
        } while (!value.IsEmpty);
    }

    // Utf8JsonWriter(Stream) retains the document until Flush; this buffer writes each committed chunk.
    private sealed class StreamBuffer(Stream stream, CancellationToken cancellationToken) : IBufferWriter<byte> {
        private byte[] buffer = new byte[64 * 1024];

        public void Advance(int count) {
            cancellationToken.ThrowIfCancellationRequested();
            stream.Write(buffer.AsSpan(0, count));
        }

        public Memory<byte> GetMemory(int sizeHint = 0) {
            cancellationToken.ThrowIfCancellationRequested();

            if (sizeHint > buffer.Length)
                buffer = new byte[sizeHint];

            return buffer;
        }

        public Span<byte> GetSpan(int sizeHint = 0) {
            return GetMemory(sizeHint).Span;
        }
    }
}
