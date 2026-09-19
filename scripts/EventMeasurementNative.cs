// Native local future-event delivery observer. No log, policy or service writes.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Wela.EventMeasurementV1 {
    public sealed class Delivery {
        public string Xml;
        public string BookmarkXml;
        public double ElapsedSeconds;
    }
    public sealed class Capture {
        public string Status;
        public int NativeError;
        public string Diagnostic;
        public string StartedUtc;
        public string CompletedUtc;
        public double RegistrationSeconds;
        public double ElapsedSeconds;
        public int OutsideWindowCallbacks;
        public int BeforeWindowCallbacks;
        public long XmlUtf8Bytes;
        public Delivery[] Events;
    }
    public sealed class Observer : IDisposable {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint Callback(uint action, IntPtr context, IntPtr evt);
        [DllImport("wevtapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr EvtSubscribe(IntPtr session, IntPtr signal, string channel, string query, IntPtr bookmark, IntPtr context, Callback callback, uint flags);
        [DllImport("wevtapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr EvtCreateBookmark(string xml);
        [DllImport("wevtapi.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EvtUpdateBookmark(IntPtr bookmark, IntPtr evt);
        [DllImport("wevtapi.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EvtRender(IntPtr context, IntPtr evt, uint flags, int size, IntPtr buffer, out int used, out int count);
        [DllImport("wevtapi.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EvtClose(IntPtr handle);
        private readonly object gate = new object();
        private readonly ManualResetEvent finished = new ManualResetEvent(false);
        private readonly Stopwatch timer = new Stopwatch();
        private readonly List<Delivery> events = new List<Delivery>();
        private readonly Callback callback;
        private readonly int seconds, maximum;
        private IntPtr subscription, bookmark;
        private bool armed, disposed, completed;
        private string status = "WindowComplete", diagnostic = "", started;
        private int nativeError, outsideWindow, beforeWindow;
        private long xmlBytes;
        private double registration, elapsed;
        public string StartedUtc { get { return started; } }
        public double RegistrationSeconds { get { return registration; } }
        public Observer(string channel, int seconds, int maximum) {
            if (seconds < 1 || seconds > 60 || maximum < 1 || maximum > 1024) throw new ArgumentOutOfRangeException();
            this.seconds=seconds; this.maximum=maximum; callback=OnEvent;
            bookmark=EvtCreateBookmark(null);
            if (bookmark==IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "EvtCreateBookmark failed");
            Stopwatch opening=Stopwatch.StartNew();
            subscription=EvtSubscribe(IntPtr.Zero, IntPtr.Zero, channel, "*", IntPtr.Zero, IntPtr.Zero, callback, 0x10001);
            int error=Marshal.GetLastWin32Error();
            registration=opening.Elapsed.TotalSeconds;
            if(subscription==IntPtr.Zero) { EvtClose(bookmark); bookmark=IntPtr.Zero; finished.Dispose(); throw new System.ComponentModel.Win32Exception(error,"EvtSubscribe failed"); }
            lock(gate) { started=DateTime.UtcNow.ToString("o"); timer.Start(); armed=true; }
        }
        private static string Render(IntPtr handle, uint flags, int maximumBytes) {
            int used, count;
            bool ok=EvtRender(IntPtr.Zero,handle,flags,0,IntPtr.Zero,out used,out count);
            int error=Marshal.GetLastWin32Error();
            if(ok || error!=122 || used<2 || used>maximumBytes) throw new InvalidOperationException("EvtRender size/error outside bounds: "+error+"/"+used);
            IntPtr buffer=Marshal.AllocHGlobal(used);
            try {
                if(!EvtRender(IntPtr.Zero,handle,flags,used,buffer,out used,out count)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),"EvtRender failed");
                return Marshal.PtrToStringUni(buffer);
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        private uint OnEvent(uint action, IntPtr context, IntPtr evt) {
            // The service owns callback event handles. Never close them here.
            lock(gate) {
                if(disposed || completed) return 0;
                if(action==0) { nativeError=unchecked((int)evt.ToInt64()); status="NativeError"; diagnostic="Native subscription error (including stale/missing records when reported): "+nativeError; finished.Set(); return 0; }
                if(action!=1) { status="NativeError"; diagnostic="Unknown subscription callback action"; finished.Set(); return 0; }
                if(!armed) { beforeWindow++; return 0; }
                double observed=timer.Elapsed.TotalSeconds;
                if(observed>=seconds) { outsideWindow++; finished.Set(); return 0; }
                if(status!="WindowComplete") return 0;
                if(events.Count>=maximum) { status="EventCapExceeded"; diagnostic="At least one additional delivery exceeded the selected event cap."; elapsed=observed; finished.Set(); return 0; }
                try {
                    string xml=Render(evt,1,2097152);
                    int bytes=System.Text.Encoding.UTF8.GetByteCount(xml);
                    if(bytes>1048576 || xmlBytes+bytes>16777216) { status="XmlCapExceeded"; diagnostic="Rendered XML exceeds the per-event 1 MiB or batch 16 MiB cap."; elapsed=observed; finished.Set(); return 0; }
                    if(!EvtUpdateBookmark(bookmark,evt)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),"EvtUpdateBookmark failed");
                    events.Add(new Delivery { Xml=xml, BookmarkXml=Render(bookmark,2,65536), ElapsedSeconds=observed });
                    xmlBytes+=bytes;
                } catch(Exception ex) { status="NativeError"; diagnostic=ex.Message; elapsed=observed; finished.Set(); }
            }
            return 0;
        }
        public Capture Complete() {
            if(disposed || completed) throw new InvalidOperationException("Observer is already closed");
            double remaining=seconds-timer.Elapsed.TotalSeconds;
            if(remaining>0) finished.WaitOne((int)Math.Ceiling(remaining*1000));
            lock(gate) { completed=true; if(status=="WindowComplete") elapsed=seconds; else if(elapsed==0) elapsed=Math.Min(timer.Elapsed.TotalSeconds,seconds); }
            // EvtClose outside the callback lock avoids a shutdown/callback deadlock.
            if(subscription!=IntPtr.Zero) { EvtClose(subscription); subscription=IntPtr.Zero; }
            return new Capture { Status=status, NativeError=nativeError, Diagnostic=diagnostic, StartedUtc=started, CompletedUtc=DateTime.UtcNow.ToString("o"), RegistrationSeconds=registration, ElapsedSeconds=elapsed, OutsideWindowCallbacks=outsideWindow, BeforeWindowCallbacks=beforeWindow, XmlUtf8Bytes=xmlBytes, Events=events.ToArray() };
        }
        public void Dispose() {
            lock(gate) { if(disposed) return; disposed=true; }
            if(subscription!=IntPtr.Zero) { EvtClose(subscription); subscription=IntPtr.Zero; }
            if(bookmark!=IntPtr.Zero) { EvtClose(bookmark); bookmark=IntPtr.Zero; }
            finished.Dispose();
            GC.KeepAlive(callback);
        }
    }
}
