using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal readonly record struct AnnotationPublicationMeasurement(double WaitSeconds, long WaitAllocatedBytes);

internal sealed class AnnotationView : IDisposable {
    internal nint Handle { get; private set; }

    internal AnnotationView(nint view) {
        Handle = Core.BNNewViewReference(view);
    }

    internal void Update(nint view) {
        if (view == Handle)
            return;

        nint retained = Core.BNNewViewReference(view);
        Core.BNFreeBinaryView(Handle);
        Handle = retained;
    }

    internal void Refresh() {
        nint current = AnnotationPublication.RetainCurrentView(Handle);
        Core.BNFreeBinaryView(Handle);
        Handle = current;
    }

    public void Dispose() => Core.BNFreeBinaryView(Handle);
}

internal sealed unsafe class AnnotationPublication {
    [InlineArray(54)]
    private struct OtherCallbacks {
        private nint first;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Notification {
        internal nint Context;
        internal delegate* unmanaged[Cdecl]<nint, nint, ulong> Barrier;
        internal OtherCallbacks Other;
    }

    private readonly Action<nint> publish;
    private readonly CancellationToken cancellationToken;
    private readonly nint view;
    private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private ExceptionDispatchInfo? error;
    private int started;
    private int callbackThread;
    private double callbackSeconds;
    private long callbackAllocated;

    private AnnotationPublication(nint view, Action<nint> publish, CancellationToken cancellationToken) {
        this.view = view;
        this.publish = publish;
        this.cancellationToken = cancellationToken;
    }

    internal static AnnotationPublicationMeasurement Run(nint view, Action<nint> publish, CancellationToken cancellationToken = default) {
        cancellationToken.ThrowIfCancellationRequested();

        long start = Stopwatch.GetTimestamp();
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        nint retainedView = Core.BNNewViewReference(view);
        var pending = new AnnotationPublication(retainedView, publish, cancellationToken);
        var context = GCHandle.Alloc(pending);

        try {
            Core.BNExecuteOnMainThreadAndWait(GCHandle.ToIntPtr(context), &Dispatch);
            pending.error?.Throw();
        } finally {
            context.Free();
            Core.BNFreeBinaryView(retainedView);
        }

        long waitingAllocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        if (pending.callbackThread == Environment.CurrentManagedThreadId)
            waitingAllocated -= pending.callbackAllocated;

        return new(Math.Max(0, Stopwatch.GetElapsedTime(start).TotalSeconds - pending.callbackSeconds), waitingAllocated);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void Dispatch(nint context) {
        var pending = (AnnotationPublication)GCHandle.FromIntPtr(context).Target!;
        nint current = 0;
        try {
            pending.cancellationToken.ThrowIfCancellationRequested();
            current = RetainCurrentView(pending.view);
            var notification = new Notification { Context = context, Barrier = &Notify };

            // Keep UI view replacement outside publication. The barrier callback
            // holds the core lock and must never synchronously dispatch to the UI.
            Core.BNRegisterDataNotification(current, &notification);
            bool cancelled = false;
            try {
                try {
                    pending.completion.Task.Wait(pending.cancellationToken);
                } catch (OperationCanceledException) {
                    cancelled = true;
                }
            } finally {
                // Unregistration waits for an active callback before releasing
                // its stack notification and managed context.
                Core.BNUnregisterDataNotification(current, &notification);
            }

            pending.error?.Throw();
            if (cancelled && !pending.completion.Task.IsCompleted)
                pending.cancellationToken.ThrowIfCancellationRequested();

            // A native caller can close the file while the UI waits for the barrier.
            nint live = RetainCurrentView(current);
            Core.BNFreeBinaryView(live);
        } catch (Exception error) {
            pending.error = ExceptionDispatchInfo.Capture(error);
        } finally {
            if (current != 0)
                Core.BNFreeBinaryView(current);
        }
    }

    internal static nint RetainCurrentView(nint view) {
        byte* kind = Core.BNGetViewType(view);
        nint file = Core.BNGetFileForView(view);

        try {
            nint current = Core.BNGetFileViewOfType(file, kind);
            if (current == 0)
                throw new OperationCanceledException("The Binary Ninja file no longer has the requested view.");

            return current;
        } finally {
            Core.BNFreeFileMetadata(file);
            Core.BNFreeString(kind);
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static ulong Notify(nint pointer, nint view) {
        var pending = (AnnotationPublication)GCHandle.FromIntPtr(pointer).Target!;

        if (Interlocked.Exchange(ref pending.started, 1) != 0)
            return 0;

        long start = Stopwatch.GetTimestamp();
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        pending.callbackThread = Environment.CurrentManagedThreadId;
        try {
            pending.cancellationToken.ThrowIfCancellationRequested();
            pending.publish(view);
        } catch (Exception error) {
            pending.error = ExceptionDispatchInfo.Capture(error);
        } finally {
            pending.callbackSeconds = Stopwatch.GetElapsedTime(start).TotalSeconds;
            pending.callbackAllocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
            pending.completion.TrySetResult();
        }

        return 0;
    }
}

internal static unsafe partial class Core {
    [LibraryImport(Library)]
    internal static partial void BNExecuteOnMainThreadAndWait(nint context, delegate* unmanaged[Cdecl]<nint, void> callback);

    [LibraryImport(Library)]
    internal static partial void BNRegisterDataNotification(nint view, void* notification);

    [LibraryImport(Library)]
    internal static partial void BNUnregisterDataNotification(nint view, void* notification);
}
