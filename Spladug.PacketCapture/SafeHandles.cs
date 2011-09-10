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
    using Microsoft.Win32.SafeHandles;

    internal sealed class PcapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private PcapHandle()
            : base(true)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.pcap_close(handle);
            return true;
        }

        public void ThrowLastError()
        {
            string errorMessage = NativeMethods.pcap_geterr(this);
            throw new PacketCaptureException(errorMessage);
        }
    }

    internal sealed class PcapDumperHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private PcapDumperHandle()
            : base(true)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.pcap_dump_close(handle);
            return true;
        }
    }
}
