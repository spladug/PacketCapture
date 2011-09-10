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

    /// <summary>
    /// Represents a single packet on the network.
    /// </summary>
    public sealed class Packet
    {
        internal Packet() { }

        /// <summary>
        /// Gets the contents of the packet, including the headers.
        /// </summary>
        /// <remarks>
        /// If captured from the network with a snapshot length
        /// less than the actual length of the packet, the data will
        /// be truncated.
        /// </remarks>
        public byte[] Data { get; internal set; }

        /// <summary>
        /// Gets the time at which the packet was received.
        /// </summary>
        public DateTime Timestamp
        {
            get
            {
                return NativeMethods.UnixEpoch
                    .AddSeconds(NativeTimestamp.Seconds.ToInt64())
                    .AddTicks(NativeTimestamp.Microseconds.ToInt64() * NativeMethods.MicrosecondsToTicks);
            }

            internal set
            {
                var span = value - NativeMethods.UnixEpoch;
                var timeval = new timeval();

                timeval.Seconds = new IntPtr((int)span.TotalSeconds);
                span -= TimeSpan.FromSeconds(span.TotalSeconds);
                timeval.Microseconds = new IntPtr(span.Ticks / NativeMethods.MicrosecondsToTicks);

                NativeTimestamp = timeval;
            }
        }

        /// <summary>
        /// Gets the link layer type of the device the packet was captured on.
        /// </summary>
        /// <remarks>
        /// The link layer type provides enough information to parse
        /// the first header in the packet.
        /// </remarks>
        public LinkLayerType LinkLayerType { get; internal set; }

        internal timeval NativeTimestamp { get; set; }
    }
}
