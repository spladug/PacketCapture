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
    /// <summary>
    /// Specifies the type of link layer a network interface is connected to.
    /// </summary>
    /// <remarks>
    /// The LinkLayerType is useful to determine how to start parsing a
    /// captured packet.  For example, if the LinkLayerType is Ethernet, 
    /// the first 14 bytes of the message consist of the ethernet frame 
    /// header.
    /// </remarks>
    public enum LinkLayerType
    {
        /// <summary>
        /// BSD Loopback
        /// </summary>
        BsdLoopback = 0,

        /// <summary>
        /// IEEE 802.3 Ethernet (10 Mb, 100 Mb, 1000 Mb, etc.)
        /// </summary>
        Ethernet = 1, 

        /// <summary>
        /// RFC 895 Experimental Ethernet (3 Mb)
        /// </summary>
        Ethernet3Megabit = 2,

        /// <summary>
        /// AX.25 Amateur Radio
        /// </summary>
        AmateurRadioAX25 = 3,

        /// <summary>
        /// Proteon ProNET Token Ring
        /// </summary>
        ProNet = 4,

        /// <summary>
        /// IEEE 802.5 Token Ring
        /// </summary>
        TokenRing = 6,

        /// <summary>
        /// ARCNet
        /// </summary>
        ArcNet = 7,
    }
}
