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
    using System.Text;

    /// <summary>
    /// Provides static methods for opening packet save files for reading or writing.
    /// </summary>
    public static class PacketSaveFile
    {
        /// <summary>
        /// Opens an existing packet save file for reading.
        /// </summary>
        /// <remarks>
        /// The file should be in the standard libpcap file format as produced by
        /// other pcap applications such as Wireshark or as written by this library.
        /// </remarks>
        /// <param name="fileName">
        /// The path to the save file to be opened.
        /// </param>
        /// <returns>
        /// A <c cref="PacketReader">PacketReader</c> that reads packets from the specified file.
        /// </returns>
        /// <exception cref="System.ArgumentNullException">
        /// fileName is null or the empty string.
        /// </exception>
        /// <exception cref="PacketCaptureException">
        /// An error occured opening the file.
        /// </exception>
        public static PacketReader OpenRead(string fileName)
        {
            ArgumentGuards.ThrowIfNullOrEmpty(fileName, "fileName");

            var errorBuffer = new StringBuilder(NativeMethods.ErrorBufferSize);
            var handle = NativeMethods.pcap_open_offline(fileName, errorBuffer);

            if (handle.IsInvalid)
                throw new PacketCaptureException(errorBuffer.ToString());

            return new PacketReader(handle);
        }

        /// <summary>
        /// Opens a packet save file to write to.
        /// </summary>
        /// <param name="source">
        /// The <c cref="PacketReader">PacketReader</c> that the packets to be written out were read from.
        /// </param>
        /// <param name="fileName">The path to the save file to be opened.</param>
        /// <returns>
        /// A <c cref="PacketWriter">PacketWriter</c> that writes packets to the specified file.
        /// </returns>
        /// <exception cref="System.ArgumentNullException">
        /// source is null.
        /// </exception>
        /// <exception cref="System.ArgumentNullException">
        /// fileName is null or the empty string.
        /// </exception>
        /// <exception cref="PacketCaptureException">
        /// An error occured opening the file.
        /// </exception>
        public static PacketWriter OpenWrite(PacketReader source, string fileName)
        {
            ArgumentGuards.ThrowIfNull(source, "source");
            ArgumentGuards.ThrowIfNullOrEmpty(fileName, "fileName");

            var handle = NativeMethods.pcap_dump_open(source.Handle, fileName);

            if (handle.IsInvalid)
                source.Handle.ThrowLastError();

            return new DumpFilePacketWriter(handle);
        }
    }
}
