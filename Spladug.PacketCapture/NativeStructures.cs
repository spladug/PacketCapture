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
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class pcap_if
    {
        public IntPtr Next;
        public string Name;
        public string Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct timeval
    {
        public IntPtr Seconds;
        public IntPtr Microseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal sealed class pcap_pkthdr
    {
        public timeval Timestamp;
        public int DataLength;
        public int ActualLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class bpf_program
    {
        public int ProgramLength;
        public IntPtr Instructions;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct pcap_addr
    {
        public IntPtr Next;
        public IntPtr Address;
        public IntPtr Netmask;
        public IntPtr BroadcastAddress;
        public IntPtr DestinationAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct sockaddr_in
    {
        public short Family;
        public ushort Port;
        public uint Address; // technically a substruct, but with only one member... 
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct sockaddr_in6
    {
        public short Family;
        public ushort Port;
        public uint FlowInfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Address;
        public uint ScopeId;
    }
}
