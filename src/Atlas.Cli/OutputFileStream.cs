internal sealed class OutputFileStream(string path) : Stream {
    private readonly FileStream file = File.Create(path);

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => file.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) {
        ValidateBufferArguments(buffer, offset, count);
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer) {
        try {
            file.Write(buffer);
        } catch (ArgumentOutOfRangeException error) when (IsFileSizeError(error)) {
            throw FileSizeError(error);
        }
    }

    public override void Flush() {
        try {
            file.Flush();
        } catch (ArgumentOutOfRangeException error) when (IsFileSizeError(error)) {
            throw FileSizeError(error);
        }
    }

    protected override void Dispose(bool disposing) {
        try {
            if (disposing)
                file.Dispose();
        } catch (ArgumentOutOfRangeException error) when (IsFileSizeError(error)) {
            throw FileSizeError(error);
        } finally {
            base.Dispose(disposing);
        }
    }

    // Unix FileStream maps EFBIG to this argument error. The owned file accepts valid spans only.
    private static bool IsFileSizeError(ArgumentOutOfRangeException error) {
        return !OperatingSystem.IsWindows() && error.ParamName == "value";
    }

    private IOException FileSizeError(ArgumentOutOfRangeException error) {
        return new IOException($"Output file size limit exceeded: '{file.Name}'.", error);
    }
}
