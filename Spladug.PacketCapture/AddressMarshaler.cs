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
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;

    internal static class AddressMarshaler
    {
        private static IPAddress PtrToAddress(IntPtr addressPtr)
        {
            if (addressPtr == IntPtr.Zero)
                return null;

            var addressFamily = (AddressFamily)Marshal.ReadInt16(addressPtr);

            switch (addressFamily)
            {
                case AddressFamily.InterNetwork:
                    var ipAddress = (sockaddr_in)Marshal.PtrToStructure(addressPtr, typeof(sockaddr_in));
                    return new IPAddress(ipAddress.Address);
                case AddressFamily.InterNetworkV6:
                    var ip6Address = (sockaddr_in6)Marshal.PtrToStructure(addressPtr, typeof(sockaddr_in6));
                    return new IPAddress(ip6Address.Address, ip6Address.ScopeId);
                default:
                    return null;
            }
        }

        public static IEnumerable<IPAddress> MarshalAddresses(IntPtr addressListHead)
        {
            var addresses = new List<IPAddress>();

            var currentAddressPtr = addressListHead;
            while (currentAddressPtr != IntPtr.Zero)
            {
                var pcapAddress = (pcap_addr)Marshal.PtrToStructure(currentAddressPtr, typeof(pcap_addr));
                
                var address = PtrToAddress(pcapAddress.Address);

                if (address != null)
                    addresses.Add(address);

                currentAddressPtr = pcapAddress.Next;
            }

            return addresses;
        }
    }
}
