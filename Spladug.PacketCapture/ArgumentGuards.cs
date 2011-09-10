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

    internal static class ArgumentGuards
    {
        public static void ThrowIfNull<T>(T @object, string name)
            where T : class
        {
            if (@object == null)
                throw new ArgumentNullException(name);
        }

        public static void ThrowIfNullOrEmpty(string @string, string name)
        {
            if (String.IsNullOrEmpty(@string))
                throw new ArgumentNullException(name);
        }

        public static void ThrowIfDisposed<T>(T handle, string name) 
            where T : SafeHandle
        {
            if (handle.IsClosed)
                throw new ObjectDisposedException(name);
        }
    }
}
