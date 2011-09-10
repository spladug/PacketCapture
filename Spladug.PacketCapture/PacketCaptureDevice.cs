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
    using System.Runtime.InteropServices;
    using System.Text;

    /// <summary>
    /// Provides information about and operations on a network interface 
    /// that support packet capture.
    /// </summary>
    /// <remarks>
    /// You do not create instances of this class; the 
    /// <c cref="GetAllPacketCaptureDevices">GetAllPacketCaptureDevices</c> method
    /// returns an enumerator that contains one object for each supported device
    /// in the system.
    /// </remarks>
    public sealed class PacketCaptureDevice
    {
        private readonly string name;
        private readonly string description;
        private readonly IEnumerable<IPAddress> addresses;

        private PacketCaptureDevice(string name, string description, IEnumerable<IPAddress> addresses)
        {
            this.name = name;
            this.description = description;
            this.addresses = addresses;
        }

        /// <summary>
        /// Opens the device for packet capturing.
        /// </summary>
        /// <returns>
        /// A <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c> opened 
        /// on this device and capturing the entirety of each packet.
        /// </returns>
        public PacketReader OpenRead()
        {
            // default to the largest possible size 
            // so packets are never clipped
            return OpenRead(UInt16.MaxValue);
        }

        private PcapHandle OpenPcapDevice(ushort snapshotLength)
        {
            var errorBuffer = new StringBuilder(NativeMethods.ErrorBufferSize);

            var handle = NativeMethods.pcap_open_live(
                name, // device name
                snapshotLength,
                1, // promiscuous
                PacketReader.CaptureTimeout,
                errorBuffer
            );

            if (handle.IsInvalid)
                throw new PacketCaptureException(errorBuffer.ToString());

            return handle;
        }

        /// <summary>
        /// Opens the device for packet capturing with a specified maximum 
        /// number of bytes to capture from each packet.
        /// </summary>
        /// <param name="snapshotLength">
        /// The maximum number of bytes to capture for each packet.
        /// </param>
        /// <remarks>
        /// By setting the <paramref name="snapshotLength" />, parts of packets can
        /// be efficiently captured.  For example, it is possible to capture just the headers.
        /// The snapshot length must be greater than zero, and less than or equal 
        /// to 65535.
        /// </remarks>
        /// <exception cref="Spladug.PacketCapture.PacketCaptureException">
        /// An error occured when attempting to open the packet capture device.
        /// </exception>
        /// <exception cref="System.ArgumentOutOfRangeException">
        /// snapshotLength is less than 0 or greater than 65535.
        /// </exception>
        /// <returns>
        /// A <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c> opened 
        /// on this device and capturing only as many bytes of each packet
        /// as specified by the <paramref name="snapshotLength"/>
        /// </returns>
        public PacketReader OpenRead(int snapshotLength)
        {
            if (snapshotLength < 0 || snapshotLength > UInt16.MaxValue)
                throw new ArgumentOutOfRangeException("snapshotLength", "Must be a value between 0 and 65535");

            var handle = OpenPcapDevice((ushort)snapshotLength);

            return new PacketReader(handle);
        }

        /// <summary>
        /// Opens the device for writing of raw packets.
        /// </summary>
        /// <remarks>
        /// By writing raw packets, it is possible to completely bypass the OS provided
        /// protocol stacks and inject packets onto the network with complete control. 
        /// For example, it is possible to write a packet out that looks like it came
        /// from another application, injecting it, in essence, into the TCP stream of 
        /// another process.
        /// </remarks>
        /// <exception cref="Spladug.PacketCapture.PacketCaptureException">
        /// An error occured when attempting to open the packet capture device.
        /// </exception>
        /// <returns>
        /// A <c cref="Spladug.PacketCapture.PacketWriter">PacketWriter</c> opened
        /// on this device for writing of raw packets.
        /// </returns>
        public PacketWriter OpenWrite()
        {
            var handle = OpenPcapDevice(UInt16.MaxValue);
            return new LivePacketWriter(handle);
        }

        /// <summary>
        /// Gets the name of the device.
        /// </summary>
        /// <remarks>
        /// While the Name is always available, it is not necessarily human-readable.
        /// If available, the <c cref="Description">Description</c> provides a more 
        /// user-friendly name.
        /// </remarks>
        public string Name
        {
            get { return name; }
        }

        /// <summary>
        /// Gets the description of the device.
        /// </summary>
        public string Description
        {
            get { return description; }
        }

        /// <summary>
        /// Gets the addresses associated with the device.
        /// </summary>
        public IEnumerable<IPAddress> Addresses
        {
            get { return addresses; }
        }

        /// <summary>
        /// Returns objects that describe the network devices on the local computer
        /// that support packet capture.
        /// </summary>
        /// <returns>An array containing all supported network devices.</returns>
        public static PacketCaptureDevice[] GetAllPacketCaptureDevices()
        {
            var headPtr = IntPtr.Zero;
            var errorBuffer = new StringBuilder(NativeMethods.ErrorBufferSize);

            int result = NativeMethods.pcap_findalldevs(ref headPtr, errorBuffer);

            if (result == ReturnValue.Error)
                throw new PacketCaptureException(errorBuffer.ToString());

            var currentDevicePtr = headPtr;
            var currentDevice = new pcap_if();

            var devices = new List<PacketCaptureDevice>();
            while (currentDevicePtr != IntPtr.Zero)
            {
                Marshal.PtrToStructure(currentDevicePtr, currentDevice);
                var addresses = AddressMarshaler.MarshalAddresses(currentDevice.Addresses);
                var device = new PacketCaptureDevice(currentDevice.Name, currentDevice.Description, addresses);

                devices.Add(device);

                currentDevicePtr = currentDevice.Next;
            }

            NativeMethods.pcap_freealldevs(headPtr);

            return devices.ToArray();
        }
    }
}
