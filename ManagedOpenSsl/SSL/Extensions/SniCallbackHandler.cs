using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL.Extensions
{
    /// <summary>
    /// Sni callback.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int SniCallbackHandler(IntPtr ssl, IntPtr ad, IntPtr arg);
}
