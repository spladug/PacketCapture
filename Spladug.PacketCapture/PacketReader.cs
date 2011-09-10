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
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Threading;

    /// <summary>
    /// Represents a reader that provides read-only access to packets.
    /// </summary>
    public sealed class PacketReader : IDisposable
    {
        private readonly PcapHandle handle;
        private readonly LinkLayerType linkLayerType;
        private Thread thread;

        internal const int CaptureTimeout = 100;

        internal PacketReader(PcapHandle handle)
        {
            this.handle = handle;
            linkLayerType = (LinkLayerType)NativeMethods.pcap_datalink(handle);
        }

        internal PcapHandle Handle
        {
            get { return handle; }
        }

        private void ThrowIfDisposed()
        {
            ArgumentGuards.ThrowIfDisposed(handle, "PacketReader");
        }

        private void ThrowIfBusy()
        {
            if (IsBusy)
                throw new InvalidOperationException("An asynchronous operation is in progress.");
        }

        /// <summary>
        /// Gets the link layer type of the device.
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        /// <remarks>
        /// The link layer type provides enough information to parse
        /// the first header in any packet captured on this device.
        /// </remarks>
        public LinkLayerType LinkLayerType
        {
            get 
            {
                ThrowIfDisposed();
                return linkLayerType; 
            }
        }

        /// <summary>
        /// Applies a filter to the packet capture.
        /// </summary>
        /// <remarks>
        /// The filter string is a high level filtering expression, see
        /// <a href="http://www.winpcap.org/docs/docs_40_2/html/group__language.html">
        /// the WinPcap documentation</a> for a description of the syntax.
        /// 
        /// Filtering the captured traffic to the minimum required can
        /// increase the performance of the capture application as less
        /// copies need to be performed.  
        /// 
        /// Note: has no effect if reading from a file.
        /// 
        /// Note: tests for IPv4 broadcast addresses do not work at the 
        /// moment.
        /// </remarks>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        /// <paramref name="filter"/> is null.
        /// </exception>
        /// <param name="filter">Filter expression, see syntax in remarks.</param>
        public void ApplyFilter(string filter)
        {
            ThrowIfDisposed();
            ArgumentGuards.ThrowIfNull(filter, "filter");

            var program = new bpf_program();

            int compilationResult = NativeMethods.pcap_compile(
                handle, 
                program, 
                filter, 
                1, // optimize the compiled filter-program
                0 // netmask -- need to get this from the interface 
            );

            if (compilationResult == ReturnValue.Error)
                handle.ThrowLastError();

            int setFilterResult = NativeMethods.pcap_setfilter(handle, program);

            NativeMethods.pcap_freecode(program);

            if (setFilterResult == ReturnValue.Error)
                handle.ThrowLastError();
        }

        /// <summary>
        /// Clears the packet capture filter.
        /// </summary>
        /// <remarks>
        /// Has no effect if the <c>PacketReader</c> is reading from a file.
        /// </remarks>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        public void ClearFilter()
        {
            ApplyFilter("");
        }

        /// <summary>
        /// Reads a single packet from the packet capture source.
        /// </summary>
        /// <remarks>
        /// If a filter is set, only packets matching the criteria set
        /// by the filter will be read by this method.
        /// </remarks>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// is busy with an asynchronous operation.
        /// </exception>
        /// <returns>
        /// A <c cref="Spladug.PacketCapture.Packet">Packet</c> that
        /// represents the captured packet.
        /// </returns>
        public Packet ReadPacket()
        {
            ThrowIfBusy();
            return ReadPacketWithoutBusyCheck();
        }

        private Packet ReadPacketWithoutBusyCheck()
        {
            ThrowIfDisposed();

            while (true)
            {
                var header = new pcap_pkthdr();
                var dataPtr = IntPtr.Zero;

                int result = NativeMethods.pcap_next_ex(handle, ref header, ref dataPtr);

                // throw on error
                if (result == ReturnValue.Error)
                    handle.ThrowLastError();

                // check for EOF
                if (result == ReturnValue.EOF)
                    return null;

                // try again on timeout
                if (result == 0)
                    continue;

                var buffer = new byte[header.DataLength];
                Marshal.Copy(dataPtr, buffer, 0, header.DataLength);

                return new Packet { 
                    Data = buffer, 
                    NativeTimestamp = header.Timestamp,
                    LinkLayerType = linkLayerType,
                };
            }
        }

        /// <summary>
        /// Reads packets synchronously until stopped or end of file reached.
        /// </summary>
        /// <remarks>
        /// <c cref="ReadPackets">ReadPackets</c> returns an 
        /// <c>IEnumerable&lt;Packet&gt;</c> that blocks on MoveNext until a packet
        /// is read.  See the code example to see how to use this effectively.  Packets
        /// will continue to be read until <c cref="Stop">Stop</c>
        /// is called or the end of the file is reached when reading from file.
        /// </remarks>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// is busy with an asynchronous operation.
        /// </exception>
        /// <example>
        /// The following example reads packets from the network and prints the length
        /// of each received packet to the console.
        /// <code>
        /// using System;
        /// using System.Linq;
        /// using Spladug.PacketCapture;
        /// 
        /// static class Example
        /// {
        ///     static void Main()
        ///     {
        ///         var device = PacketCaptureDevice.GetAllPacketCaptureDevices().First();
        ///         
        ///         using (var reader = device.OpenRead())
        ///         {
        ///             foreach (var packet in reader.ReadPackets())
        ///             {
        ///                 Console.WriteLine(packet.Data.Length);
        ///             }
        ///         }
        ///     }
        /// }
        /// </code>
        /// </example>
        /// <returns>
        /// An enumerable object that blocks on MoveNext until a packet is read.
        /// </returns>
        public IEnumerable<Packet> ReadPackets()
        {
            ThrowIfBusy();
            return ReadPacketsWithoutBusyCheck();
        }

        private IEnumerable<Packet> ReadPacketsWithoutBusyCheck()
        {
            while (true)
            {
                var packet = ReadPacketWithoutBusyCheck();

                if (packet == null)
                    break;

                yield return packet;
            }
        }

        /// <summary>
        /// Breaks the ReadPackets loop and stops reading packets.
        /// </summary>
        /// <remarks>
        /// Stop does not invalidate the state of the PacketReader, packets
        /// can still be read from the reader after being stopped.
        /// </remarks>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        public void Stop()
        {
            ThrowIfDisposed();
            NativeMethods.pcap_breakloop(handle);
        }

        /// <summary>
        /// Stops asynchronous packet capture.
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// is not reading packets asynchronously.
        /// </exception>
        public void CancelAsync()
        {
            if (thread == null)
                throw new InvalidOperationException("No asynchronous operation in progress.");

            Stop();
            thread.Join(CaptureTimeout);
        }

        /// <summary>
        /// Gets whether an asynchronous read is in progress.
        /// </summary>
        public bool IsBusy
        {
            get { return thread != null; }
        }

        /// <summary>
        /// Occurs when a packet is read asynchronously.
        /// </summary>
        /// <seealso cref="ReadPacketsAsync"/>
        public event EventHandler<PacketReadEventArgs> PacketRead;

        /// <summary>
        /// Occurs when asynchronous packet capture has stopped.
        /// </summary>
        /// <seealso cref="ReadPacketsAsync"/>
        public event AsyncCompletedEventHandler ReadPacketsCompleted;

        /// <summary>
        /// Reads packets asynchronously until stopped or end of file reached.
        /// </summary>
        /// <remarks>
        /// Applications that need to not block can use the asynchronous read to
        /// maintain responsive.  When packets are read they will be sent to the 
        /// application via the <c cref="PacketRead">PacketRead</c> event.  If a
        /// GUI framework (such as Windows Forms or WPF) is in use, the events will
        /// be posted to the GUI thread automatically.
        /// </remarks>
        /// <example>
        /// The following example captures packets asynchronously and displays 
        /// their lengths until the user hits enter.
        /// 
        /// <code>
        /// using System;
        /// using System.Linq;
        /// using Spladug.PacketCapture;
        ///
        /// static class Example
        /// {
        ///     static void Main()
        ///     {
        ///         var device = PacketCaptureDevice.GetAllPacketCaptureDevices().First();
        ///
        ///         using (var reader = device.OpenRead())
        ///         {
        ///             reader.PacketRead += OnPacketRead;
        ///
        ///             Console.WriteLine("Press enter to stop capturing...");
        ///             reader.ReadPacketsAsync();
        ///
        ///             Console.ReadLine();
        ///         }
        ///     }
        ///
        ///     static void OnPacketRead(object sender, PacketReadEventArgs e)
        ///     {
        ///         Console.WriteLine(e.Packet.Data.Length);
        ///     }
        /// }
        /// </code>
        /// </example>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// has been closed.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// The <c cref="Spladug.PacketCapture.PacketReader">PacketReader</c>
        /// is already reading packets asynchronously.
        /// </exception>
        public void ReadPacketsAsync()
        {
            ThrowIfDisposed();
            ThrowIfBusy();

            var operation = AsyncOperationManager.CreateOperation(null);
            thread = new Thread(ReadPacketsAsyncThreadWorker);

            thread.Name = "Packet Capture Worker";
            thread.IsBackground = true;

            thread.Start(operation);
        }

        private void ReadPacketsAsyncThreadWorker(object arg)
        {
            var operation = (AsyncOperation)arg;
            Exception error = null;

            try
            {
                foreach (var packet in ReadPacketsWithoutBusyCheck())
                {
                    operation.Post(
                        OnPacketRead,
                        packet
                    );
                }
            }
            // catch all exceptions so they can be marshaled to the
            // main thread for safe handling
            catch (Exception exception)
            {
                error = exception;
            }

            operation.PostOperationCompleted(
                OnReadPacketsCompleted,
                error
            );
        }

        private void OnPacketRead(object arg)
        {
            var handler = PacketRead;

            if (handler != null)
            {
                var packet = (Packet)arg;
                handler(this, new PacketReadEventArgs(packet));
            }
        }

        private void OnReadPacketsCompleted(object arg)
        {
            var handler = ReadPacketsCompleted;

            if (handler != null)
            {
                var exception = (Exception)arg;
                handler(this, new AsyncCompletedEventArgs(exception, false, null));
            }

            thread = null;
        }

        /// <summary>
        /// Releases the resources used by the <c>PacketReader</c>.
        /// </summary>
        public void Dispose()
        {
            if (IsBusy)
                Stop();

            handle.Dispose();
        }
    }
}
