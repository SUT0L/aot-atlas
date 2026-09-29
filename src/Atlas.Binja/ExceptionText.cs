using System.Text.Unicode;

namespace Atlas.Binja;

internal static class ExceptionText {
    internal static int Frame(Span<byte> text, ManagedRegionSource source, in ManagedFrame frame, in RuntimeFunction function, uint root, uint eh) {
        string proof = source == ManagedRegionSource.Pogo ? "pogo" : "section";
        string kind = (frame.Flags & 3) switch { 0 => "root", 1 => "handler", _ => "filter" };
        if (!Utf8.TryWrite(text, $"{proof}::nativeaot::frame::{function.Begin:X8}-{function.End:X8} kind={kind} root={root:X8} flags={frame.Flags:X2} trailer={frame.Trailer:X8} eh={eh:X8} associated={frame.AssociatedData:X8} unboxing={frame.UnboxingTarget:X8}\0", out int length))
            throw new InvalidDataException("NativeAOT frame tag exceeds its output buffer.");
        return length;
    }

    internal static int Clause(Span<byte> text, ManagedRegionSource source, in ExceptionClause clause) {
        string proof = source == ManagedRegionSource.Pogo ? "pogo" : "section";
        string kind = clause.Kind switch {
            ExceptionClauseKind.Typed => "typed",
            ExceptionClauseKind.Fault => "fault",
            ExceptionClauseKind.Filter => "filter",
            _ => "marker"
        };
        if (!Utf8.TryWrite(text, $"{proof}::nativeaot::eh_clause::{clause.Address:X8} kind={kind} try={clause.TryStart:X8}-{clause.TryEnd:X8} handler_offset={clause.HandlerOffset:X8} filter_offset={clause.FilterOffset:X8} catch_mt={clause.Type:X8}\0", out int length))
            throw new InvalidDataException("NativeAOT exception tag exceeds its output buffer.");
        return length;
    }
}
