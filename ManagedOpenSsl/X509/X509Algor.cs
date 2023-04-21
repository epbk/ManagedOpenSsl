using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL.X509
{
    [StructLayout(LayoutKind.Sequential)]
    public struct X509_ALGOR
    {
        public IntPtr algorithm;
        public IntPtr parameter;
    } /* X509_ALGOR */ 
}
