//  Copyright (c) 2009 Neil Williams

//  Permission is hereby granted, free of charge, to any person
//  obtaining a copy of this software and associated documentation
//  files (the "Software"), to deal in the Software without
//  restriction, including without limitation the rights to use,
//  copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following
//  conditions:

//  The above copyright notice and this permission notice shall be
//  included in all copies or substantial portions of the Software.

//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
//  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
//  OTHER DEALINGS IN THE SOFTWARE.

namespace Spladug.PacketCapture
{
    using System;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;

    internal static class ReturnValue
    {
        internal const int Success = 0;
        internal const int Error = -1;
        internal const int EOF = -2;
    }

    internal static class NativeMethods
    {
        private const string PcapDll = "wpcap.dll";

        internal const int ErrorBufferSize = 256;
        internal const long MicrosecondsToTicks = 10L;
        internal static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1);

        [DllImport(PcapDll, CharSet=CharSet.Ansi, ThrowOnUnmappableChar=true, BestFitMapping=false)]
        internal static extern int pcap_findalldevs(ref IntPtr deviceListHead, StringBuilder errbuf);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern void pcap_freealldevs(IntPtr deviceListHead);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern PcapHandle pcap_open_live(string device, int snapshotLength, int isPromiscuous, int timeout, StringBuilder errbuf);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern int pcap_next_ex(PcapHandle p, ref pcap_pkthdr header, ref IntPtr dataPtr);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern void pcap_breakloop(PcapHandle p);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern string pcap_geterr(PcapHandle p);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern int pcap_datalink(PcapHandle p);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern PcapHandle pcap_open_offline(string fileName, StringBuilder errbuf);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern PcapDumperHandle pcap_dump_open(PcapHandle p, string fileName);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern void pcap_dump(PcapDumperHandle p, pcap_pkthdr header, byte[] data);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern int pcap_dump_flush(PcapDumperHandle p);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern int pcap_sendpacket(PcapHandle p, byte[] data, int length);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern int pcap_compile(PcapHandle p, bpf_program compiled, string code, int optimize, uint netmask);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern int pcap_setfilter(PcapHandle p, bpf_program filter);

        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern void pcap_freecode(bpf_program filter);

        // these two calls have a extra attributes to ensure they don't mess things up
        // inside the safehandles
        [SuppressUnmanagedCodeSecurity]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern void pcap_close(IntPtr p);

        [SuppressUnmanagedCodeSecurity]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport(PcapDll, CharSet = CharSet.Ansi, ThrowOnUnmappableChar = true, BestFitMapping = false)]
        internal static extern void pcap_dump_close(IntPtr dumper);
    }
}
