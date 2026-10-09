using System.Text;
using System.Text.Json;

internal static class JsonOutputChecks {
    internal static void Run() {
        using (var stream = new MemoryStream()) {
            using (var json = JsonOutput.CreateWriter(stream, default)) {
                json.WriteStartObject();
                json.WriteString("name", "a\"b\nλ");
                json.Flush();
                json.WriteStartArray("values");
                json.WriteNumberValue(-1);
                json.WriteBooleanValue(true);
                json.WriteNullValue();
                json.WriteEndArray();
                json.WriteEndObject();
            }

            const string expected = "{\n  \"name\": \"a\\u0022b\\n\\u03BB\",\n  \"values\": [\n    -1,\n    true,\n    null\n  ]\n}";
            Require(Encoding.UTF8.GetString(stream.ToArray()) == expected, "Escaping, indentation, or Flush changed.");
            Require(stream.CanWrite, "JSON disposal closed its caller-owned stream.");
        }

        using (var expected = new MemoryStream())
        using (var actual = new ObservedStream()) {
            using (var json = new Utf8JsonWriter(expected, new JsonWriterOptions { Indented = true }))
                WriteRecord(json);

            using (var json = JsonOutput.CreateWriter(actual, default)) {
                WriteRecord(json);
                Require(actual.Writes > 1, "The single record did not stream before completion.");
            }

            Require(expected.ToArray().AsSpan().SequenceEqual(actual.ToArray()), "Chunked output bytes changed.");
            using var document = JsonDocument.Parse(actual.ToArray());
            var record = document.RootElement;
            Require(record.GetProperty("values").GetArrayLength() == 50_000, "Chunking lost array values.");
            Require(record.GetProperty("values")[49_999].GetInt32() == 49_999, "Chunking changed the final value.");
            Require(record.GetProperty("token").GetString() == new string('x', 70 * 1024), "An oversized token changed.");
        }

        using (var cancellation = new CancellationTokenSource())
        using (var stream = new ObservedStream(cancellation: cancellation)) {
            bool canceled = false;

            try {
                using var json = JsonOutput.CreateWriter(stream, cancellation.Token);
                WriteRecord(json);
            } catch (OperationCanceledException error) {
                canceled = error.CancellationToken == cancellation.Token;
            }

            Require(canceled, "The operation token did not interrupt serialization.");
            Require(stream.Writes == 1, "Serialization wrote after cancellation.");
        }

        using (var stream = new ObservedStream(fail: true)) {
            bool failed = false;

            try {
                using var json = JsonOutput.CreateWriter(stream, default);
                WriteRecord(json);
            } catch (IOException error) {
                failed = error.Message == "write fault";
            }

            Require(failed, "Serialization did not propagate the write fault.");
        }

        CheckTokenSegments();
        CheckHexTokens();
        CheckCancellationBeforeGrowth();

        using (var cancellation = new CancellationTokenSource())
        using (var stream = new ObservedStream(cancellation: cancellation)) {
            bool canceled = false;

            try {
                using var json = JsonOutput.CreateWriter(stream, cancellation.Token);
                json.WriteStartObject();
                JsonOutput.WriteString(json, "token", new string('x', 1024 * 1024));
                json.WriteEndObject();
            } catch (OperationCanceledException error) {
                canceled = error.CancellationToken == cancellation.Token;
            }

            Require(canceled && stream.Writes == 1, "A single large token did not stop after cancellation.");
            Require(stream.Length <= 64 * 1024, "A single large token exceeded the streaming buffer.");
        }

        Console.WriteLine("JSON output: bytes, chunked records/tokens, encoding and hex boundaries, ownership, cancellation and write fault passed.");
    }

    private static void CheckTokenSegments() {
        string arrayText = new string('x', 2047) + "😀tail";
        byte[] expectedArray = SerializeToken(json => {
            json.WriteStartArray("value");
            json.WriteStringValue((string?)null);
            json.WriteStringValue("");
            json.WriteStringValue(arrayText);
            json.WriteEndArray();
        });
        byte[] actualArray = SerializeToken(json => {
            json.WriteStartArray("value");
            JsonOutput.WriteStringValue(json, (string?)null);
            JsonOutput.WriteStringValue(json, "");
            JsonOutput.WriteStringValue(json, arrayText);
            json.WriteEndArray();
        });
        Require(expectedArray.AsSpan().SequenceEqual(actualArray), "Array string values changed.");

        foreach (string? text in new string?[] {
            null, "", "a\"b\nλ", new string('x', 2047) + "😀tail",
            new string('x', 2047) + "\uD800z", new string('x', 4095) + "\uD800",
            new string('λ', 20_000), new string('\0', 20_000)
        }) {
            byte[] expected = SerializeToken(json => json.WriteString("value", text));
            byte[] actual = SerializeToken(json => JsonOutput.WriteString(json, "value", text));
            Require(expected.AsSpan().SequenceEqual(actual), "Segmented UTF-16 encoding changed.");

            using var document = JsonDocument.Parse(actual);
            string? normalized = text is null ? null : Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(text));
            Require(document.RootElement.GetProperty("value").GetString() == normalized, "A UTF-16 value changed.");
        }

        foreach (byte[] text in new byte[][] {
            [], Encoding.UTF8.GetBytes(new string('x', 8191) + "😀tail"),
            Encoding.UTF8.GetBytes(new string('x', 8190) + "😀tail"),
            Enumerable.Repeat((byte)'x', 8191).Concat(new byte[] { 0xE2, 0x82 }).ToArray()
        }) {
            byte[] expected = SerializeToken(json => json.WriteString("value", text.AsSpan()));
            byte[] actual = SerializeToken(json => JsonOutput.WriteString(json, "value", text.AsSpan()));
            Require(expected.AsSpan().SequenceEqual(actual), "Segmented UTF-8 encoding changed.");

            using var document = JsonDocument.Parse(actual);
            Require(document.RootElement.GetProperty("value").GetString() == Encoding.UTF8.GetString(text),
                "A UTF-8 value changed.");
        }

        foreach (int length in new[] { 0, 1, 2, 32767, 32768, 32769, 65535, 65536, 65537 }) {
            var data = new byte[length];

            for (int i = 0; i < data.Length; ++i)
                data[i] = (byte)(i % 251);

            byte[] expected = SerializeToken(json => json.WriteBase64String("value", data));
            byte[] actual = SerializeToken(json => JsonOutput.WriteBase64String(json, "value", data));
            Require(expected.AsSpan().SequenceEqual(actual), "Segmented Base64 encoding changed.");

            using var document = JsonDocument.Parse(actual);
            Require(document.RootElement.GetProperty("value").GetBytesFromBase64().AsSpan().SequenceEqual(data),
                "A Base64 payload changed.");
        }
    }

    private static void CheckHexTokens() {
        foreach (int length in new[] { 0, 1, 4095, 4096, 4097, 65537 }) {
            var data = new byte[length];

            for (int i = 0; i < data.Length; ++i)
                data[i] = (byte)(i % 251);

            byte[] expected = SerializeToken(json => json.WriteString("value", Convert.ToHexString(data)));
            byte[] actual = SerializeToken(json => JsonOutput.WriteHexString(json, "value", data));
            Require(expected.AsSpan().SequenceEqual(actual), "Uppercase hex encoding changed.");
            using var upper = JsonDocument.Parse(actual);
            Require(Convert.FromHexString(upper.RootElement.GetProperty("value").GetString()!).AsSpan().SequenceEqual(data),
                "An uppercase hex payload changed.");

            expected = SerializeToken(json => json.WriteString("value", Convert.ToHexStringLower(data)));
            actual = SerializeToken(json => JsonOutput.WriteHexString(json, "value", data, lowercase: true));
            Require(expected.AsSpan().SequenceEqual(actual), "Lowercase hex encoding changed.");
            using var lower = JsonDocument.Parse(actual);
            Require(Convert.FromHexString(lower.RootElement.GetProperty("value").GetString()!).AsSpan().SequenceEqual(data),
                "A lowercase hex payload changed.");
        }

    }

    private static byte[] SerializeToken(Action<Utf8JsonWriter> write) {
        using var stream = new MemoryStream();

        using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true })) {
            json.WriteStartObject();
            write(json);
            json.WriteNumber("after", 1);
            json.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static void CheckCancellationBeforeGrowth() {
        using var cancellation = new CancellationTokenSource();
        using var stream = new MemoryStream();
        var json = JsonOutput.CreateWriter(stream, cancellation.Token);
        cancellation.Cancel();

        try {
            bool canceled = false;

            try {
                json.WriteStringValue(new string('x', 1024 * 1024));
            } catch (OperationCanceledException error) {
                canceled = error.CancellationToken == cancellation.Token;
            }

            Require(canceled && stream.Length == 0, "Cancellation was delayed until after oversized encoding.");
        } finally {
            try {
                json.Dispose();
            } catch (OperationCanceledException error) when (error.CancellationToken == cancellation.Token) {
            }
        }
    }

    private static void WriteRecord(Utf8JsonWriter json) {
        json.WriteStartObject();
        json.WriteStartArray("values");

        for (int i = 0; i < 50_000; ++i)
            json.WriteNumberValue(i);

        json.WriteEndArray();
        json.WriteString("token", new string('x', 70 * 1024));
        json.WriteEndObject();
    }

    private static void Require(bool condition, string error) {
        if (!condition)
            throw new Exception(error);
    }

    private sealed class ObservedStream(bool fail = false, CancellationTokenSource? cancellation = null) : MemoryStream {
        internal int Writes;

        public override void Write(ReadOnlySpan<byte> data) {
            ++Writes;
            if (fail)
                throw new IOException("write fault");

            base.Write(data);
            cancellation?.Cancel();
        }
    }
}
