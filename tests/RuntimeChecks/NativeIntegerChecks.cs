using System.Diagnostics;

#if RUNTIME_CHECKS
using Internal.NativeFormat;
using MicrosoftNativeReader = Internal.NativeFormat.NativeReader;
#endif

internal static class NativeIntegerChecks {
#if RUNTIME_CHECKS
    private readonly record struct EncodedValue(int Offset, int Length, uint Bits, bool Signed);

    internal static unsafe void Run() {
#if DEBUG
        throw new InvalidOperationException("Use a Release build: Microsoft's malformed-input path asserts before throwing.");
#else
        long start = Stopwatch.GetTimestamp();
        var encoder = new NativePrimitiveEncoder();
        encoder.Init();
        var values = new List<EncodedValue>();

        void Unsigned(uint value) {
            int offset = encoder.Size;
            encoder.WriteUnsigned(value);
            values.Add(new(offset, encoder.Size - offset, value, Signed: false));
        }

        void Signed(int value) {
            int offset = encoder.Size;
            encoder.WriteSigned(value);
            values.Add(new(offset, encoder.Size - offset, unchecked((uint)value), Signed: true));
        }

        for (uint value = 0; value < 16_384; ++value)
            Unsigned(value);
        for (int value = -8_192; value < 8_192; ++value)
            Signed(value);

        foreach (uint boundary in new uint[] { 128, 16_384, 2_097_152, 268_435_456 }) {
            for (int delta = -2; delta <= 2; ++delta)
                Unsigned((uint)((long)boundary + delta));
        }
        foreach (int boundary in new[] { 64, 8_192, 1_048_576, 134_217_728 }) {
            for (int delta = -2; delta <= 2; ++delta) {
                Signed(boundary + delta);
                Signed(-boundary + delta);
            }
        }
        Unsigned(uint.MaxValue);
        Signed(int.MinValue);
        Signed(int.MaxValue);

        var random = new Random(0x4E_46_31);
        for (int sample = 0; sample < 8_192; ++sample) {
            uint bits = (uint)random.NextInt64(0, 1L << 32);
            Unsigned(bits);
            Signed(unchecked((int)bits));
        }

        byte[] canonical = encoder.GetBytes();
        var unsignedWidths = new int[6];
        var signedWidths = new int[6];
        fixed (byte* bytes = canonical) {
            var reference = new MicrosoftNativeReader(bytes, (uint)canonical.Length);
            var fixture = new byte[5];
            foreach (var value in values) {
                int fixtureEnd = value.Signed
                    ? NativeFixture.Signed(fixture, 0, unchecked((int)value.Bits))
                    : NativeFixture.Unsigned(fixture, 0, value.Bits);
                if (fixtureEnd != value.Length
                    || !fixture.AsSpan(0, fixtureEnd).SequenceEqual(canonical.AsSpan(value.Offset, value.Length)))
                    throw new InvalidDataException("Fixture encoder disagrees with Microsoft's canonical bytes.");
                uint end;
                uint expected;
                var actual = new Atlas.NativeReader(canonical, value.Offset);
                uint result;
                if (value.Signed) {
                    end = reference.DecodeSigned((uint)value.Offset, out int signed);
                    expected = unchecked((uint)signed);
                    result = unchecked((uint)actual.Signed());
                    ++signedWidths[value.Length];
                } else {
                    end = reference.DecodeUnsigned((uint)value.Offset, out expected);
                    result = actual.Unsigned();
                    ++unsignedWidths[value.Length];
                }
                if (expected != value.Bits || result != expected
                    || end != value.Offset + value.Length || actual.Position != end) {
                    throw new InvalidDataException($"Native integer mismatch in Microsoft-encoded "
                        + $"{(value.Signed ? "signed" : "unsigned")} record at 0x{value.Offset:X}: "
                        + $"input=0x{value.Bits:X8}, Microsoft=0x{expected:X8}/{end}, Atlas=0x{result:X8}/{actual.Position}.");
                }
            }
        }

        int accepted = 0;
        int rejected = 0;
        int excluded = 0;
        byte[] record = new byte[5];
        fixed (byte* bytes = record) {
            var reference = new MicrosoftNativeReader(bytes, (uint)record.Length);
            for (int pair = 0; pair <= ushort.MaxValue; ++pair) {
                record[0] = (byte)pair;
                record[1] = (byte)(pair >> 8);
                record[2] = 0x80;
                record[3] = 0x7F;
                record[4] = 0xFF;
                Compare(reference, record, ref accepted, ref rejected);
            }

            for (int length = 0; length < record.Length; ++length) {
                reference = new MicrosoftNativeReader(bytes, (uint)length);
                for (int prefix = 0; prefix <= byte.MaxValue; ++prefix) {
                    record[0] = (byte)prefix;
                    // The upstream five-byte escape reads its payload without a bounds check.
                    // Its truncated forms cannot serve as a rejection oracle.
                    if (length != 0 && (prefix & 31) == 15) {
                        ++excluded;
                        continue;
                    }
                    Compare(reference, record.AsSpan(0, length), ref accepted, ref rejected);
                }
            }
        }

        for (int width = 1; width <= 5; ++width) {
            if (unsignedWidths[width] == 0 || signedWidths[width] == 0)
                throw new InvalidDataException($"Microsoft integer encoder did not exercise width {width}.");
        }

        int longRecords = CheckLongs();

        Console.WriteLine($"Native integers: {values.Count} Microsoft-encoded canonical records "
            + $"(unsigned widths 1..5: {string.Join('/', unsignedWidths.AsSpan(1).ToArray())}; "
            + $"signed: {string.Join('/', signedWidths.AsSpan(1).ToArray())}), "
            + $"{longRecords} canonical 64-bit records; "
            + $"{accepted} accepted and {rejected} rejected raw decodes matched values and next offsets; "
            + $"{excluded} upstream-unsafe truncated escapes excluded; "
            + $"batch {Stopwatch.GetElapsedTime(start).TotalMilliseconds:F3} ms.");
#endif
    }

    private static unsafe int CheckLongs() {
        var encoder = new NativePrimitiveEncoder();
        encoder.Init();
        var values = new List<(int Offset, int End, ulong Bits, bool Signed)>();
        foreach (ulong bits in new ulong[] {
            0, 63, 64, 127, 128, int.MaxValue, (ulong)int.MaxValue + 1,
            uint.MaxValue, (ulong)uint.MaxValue + 1, long.MaxValue, 1UL << 63,
            0xFFFF_FFFF_7FFF_FFFF, 0xFFFF_FFFF_8000_0000, ulong.MaxValue
        }) {
            int offset = encoder.Size;
            encoder.WriteUnsignedLong(bits);
            values.Add((offset, encoder.Size, bits, false));
            offset = encoder.Size;
            encoder.WriteSignedLong(unchecked((long)bits));
            values.Add((offset, encoder.Size, bits, true));
        }
        byte[] encoded = encoder.GetBytes();
        fixed (byte* bytes = encoded) {
            var reference = new MicrosoftNativeReader(bytes, (uint)encoded.Length);
            foreach (var value in values) {
                var actual = new Atlas.NativeReader(encoded, value.Offset);
                uint end;
                ulong expected;
                ulong result;
                if (value.Signed) {
                    end = reference.DecodeSignedLong((uint)value.Offset, out long signed);
                    expected = unchecked((ulong)signed);
                    result = unchecked((ulong)actual.SignedLong());
                } else {
                    end = reference.DecodeUnsignedLong((uint)value.Offset, out expected);
                    result = actual.UnsignedLong();
                }
                if (expected != value.Bits || result != expected || end != value.End || actual.Position != end)
                    throw new InvalidDataException($"Native 64-bit integer mismatch at 0x{value.Offset:X}.");
            }
        }
        return values.Count;
    }

    private static void Compare(MicrosoftNativeReader reference, ReadOnlySpan<byte> bytes,
        ref int accepted, ref int rejected) {
        for (int mode = 0; mode < 2; ++mode) {
            bool signed = mode != 0;
            bool referenceRejected = false;
            uint expected = 0;
            uint end = 0;
            try {
                if (signed) {
                    end = reference.DecodeSigned(0, out int value);
                    expected = unchecked((uint)value);
                } else {
                    end = reference.DecodeUnsigned(0, out expected);
                }
            } catch (BadImageFormatException) {
                referenceRejected = true;
            }

            var actual = new Atlas.NativeReader(bytes);
            bool actualRejected = false;
            uint result = 0;
            try {
                result = signed ? unchecked((uint)actual.Signed()) : actual.Unsigned();
            } catch (InvalidDataException) {
                actualRejected = true;
            }

            if (referenceRejected != actualRejected
                || (!referenceRejected && (expected != result || end != actual.Position))) {
                throw new InvalidDataException($"Native integer mismatch for {(signed ? "signed" : "unsigned")} "
                    + $"{Convert.ToHexString(bytes)}: Microsoft rejected={referenceRejected}, "
                    + $"value=0x{expected:X8}, end={end}; Atlas rejected={actualRejected}, "
                    + $"value=0x{result:X8}, end={actual.Position}.");
            }

            if (referenceRejected)
                ++rejected;
            else
                ++accepted;
        }
    }
#else
    internal static void Run() {
        throw new InvalidOperationException("Build RuntimeChecks with ReaderSchema and a dotnet/runtime checkout.");
    }
#endif
}
