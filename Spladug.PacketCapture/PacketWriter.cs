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

    /// <summary>
    /// Represents a writer that provides a way to write packets.
    /// </summary>
    public abstract class PacketWriter : IDisposable
    {
        internal PacketWriter()
        {

        }

        /// <summary>
        /// Writes raw bytes.
        /// </summary>
        /// <param name="data">A buffer containing the bytes to write.</param>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="PacketWriter">PacketWriter</c> has been closed.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        /// <c>data</c> is null.
        /// </exception>
        public abstract void Write(byte[] data);

        /// <summary>
        /// Writes a packet.
        /// </summary>
        /// <param name="packet">The packet to write.</param>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="PacketWriter">PacketWriter</c> has been closed.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        /// <c>packet</c> is null.
        /// </exception>
        public abstract void WritePacket(Packet packet);

        /// <summary>
        /// Clears out any buffers and writes buffered data out.
        /// </summary>
        /// <exception cref="System.ObjectDisposedException">
        /// The <c cref="PacketWriter">PacketWriter</c> has been closed.
        /// </exception>
        public abstract void Flush();

        /// <summary>
        /// Releases the resources used by the <c>PacketWriter</c>.
        /// </summary>
        public abstract void Dispose();
    }

    internal abstract class PacketWriter<T> : PacketWriter
        where T : SafeHandle
    {
        protected readonly T handle;

        protected PacketWriter(T handle)
        {
            this.handle = handle;
        }

        private void ThrowIfDisposed()
        {
            ArgumentGuards.ThrowIfDisposed(handle, "PacketWriter");
        }

        public sealed override void Write(byte[] data)
        {
            ThrowIfDisposed();
            ArgumentGuards.ThrowIfNull(data, "data");
            WriteCore(data);
        }

        protected abstract void WriteCore(byte[] data);

        public sealed override void WritePacket(Packet packet)
        {
            ThrowIfDisposed();
            ArgumentGuards.ThrowIfNull(packet, "packet");
            WritePacketCore(packet);
        }

        protected abstract void WritePacketCore(Packet packet);

        public sealed override void Flush()
        {
            ThrowIfDisposed();
            FlushCore();
        }

        protected abstract void FlushCore();

        public override void Dispose()
        {
            handle.Close();
        }
    }
}
