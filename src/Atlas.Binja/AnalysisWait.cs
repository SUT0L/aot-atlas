using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Atlas.Binja;

internal sealed unsafe class AnalysisWait : IDisposable {
    private static readonly Lock PendingLock = new();
    private static readonly Dictionary<nint, AnalysisWait> Pending = [];
    private static nint nextContext;

    private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private nint view;
    private readonly nint context;
    private nint registration;

    private AnalysisWait(nint view) {
        this.view = Core.BNNewViewReference(view);

        try {
            lock (PendingLock) {
                context = checked(++nextContext);
                Pending.Add(context, this);
            }

            registration = Core.BNAddAnalysisCompletionEvent(view, context, &Notify);
            if (registration == 0)
                throw new IOException("Binary Ninja could not register analysis completion.");
        } catch {
            Dispose();
            throw;
        }
    }

    internal static void Run(nint view, CancellationToken cancellationToken) {
        using var current = new AnnotationView(view);
        Run(current, cancellationToken);
    }

    internal static void Run(AnnotationView currentView, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();

        while (true) {
            currentView.Refresh();
            nint view = currentView.Handle;
            if (Core.BNGetAnalysisState(view) == 1)
                throw new InvalidOperationException("Release the Binary Ninja analysis hold before running the Atlas command.");

            Core.BNUpdateAnalysis(view);
            using var pending = new AnalysisWait(view);

            while (!pending.completion.Task.Wait(100, cancellationToken)) {
                currentView.Refresh();
                if (Core.BNGetAnalysisState(currentView.Handle) == 1)
                    throw new InvalidOperationException("Release the Binary Ninja analysis hold before running the Atlas command.");

                if (currentView.Handle != view)
                    break;
            }

            cancellationToken.ThrowIfCancellationRequested();
            currentView.Refresh();
            if (currentView.Handle == view)
                return;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void Notify(nint context) {
        AnalysisWait? pending;
        lock (PendingLock)
            Pending.Remove(context, out pending);

        pending?.completion.TrySetResult();
    }

    public void Dispose() {
        // Free releases our event reference without cancelling the host callback.
        // Never-reused cookies make delayed callbacks safe after abandonment;
        // native cancellation would stop later analysis.
        lock (PendingLock)
            Pending.Remove(context);

        if (registration != 0) {
            Core.BNFreeAnalysisCompletionEvent(registration);
            registration = 0;
        }

        if (view != 0) {
            Core.BNFreeBinaryView(view);
            view = 0;
        }
    }
}
