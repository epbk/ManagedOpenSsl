// Copyright (c) 2009 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using OpenSSL.Core;
using OpenSSL.Crypto;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.X509
{
	/// <summary>
	/// Wraps the X509_OBJECT: a glorified union
	/// </summary>
	public class X509Object : BaseReference, IStackable
	{
		#region X509_OBJECT
		//const int X509_LU_RETRY = -1;
		const int X509_LU_NONE = 0;
		const int X509_LU_X509 = 1;
		const int X509_LU_CRL = 2;
		//const int X509_LU_PKEY = 3;

		[StructLayout(LayoutKind.Sequential)]
		struct X509_OBJECT
		{
			/* one of the above types */
			public int type;
			public IntPtr ptr;
		}

		#endregion

		#region Initialization

		internal X509Object(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{
		}

		#endregion

		#region Properties

		/// <summary>
		/// Returns a Certificate if the type is X509_LU_X509
		/// </summary>
		public X509Certificate Certificate
		{
			get
			{
                unsafe
                {
                    X509_OBJECT* x509 = (X509_OBJECT*)this._Ptr;

                    if (x509->type == X509_LU_X509)
                        return new X509Certificate(x509->ptr, false);

                    return null;
                }
			}
		}

		/// <summary>
		/// Returns the PrivateKey if the type is X509_LU_PKEY
		/// </summary>
        //public CryptoKey PrivateKey
        //{
        //    get
        //    {
        //        if (raw.type == X509_LU_PKEY)
        //            return new CryptoKey(raw.ptr, false);

        //        return null;
        //    }
        //}

		#endregion

		//!! TODO - Add support for CRL

		#region Overrides

		/// <summary>
		/// Calls X509_OBJECT_up_ref_count()
		/// </summary>
		internal override void AddRef()
		{
            //switch (a->type)
            //{
            //    case X509_LU_NONE:
            //        break;
            //    case X509_LU_X509:
            //        return X509_up_ref(a->data.x509);
            //    case X509_LU_CRL:
            //        return X509_CRL_up_ref(a->data.crl);
            //}
            //return 1; 

#if _LOG
            unsafe
            {
                X509_OBJECT* x509 = (X509_OBJECT*)this._Ptr;
                Log.Log.Debug("[X509Object][AddRef][{0}][{1:X16}] {2}:{3}:{4:X16}", this.InstanceID, (long)this._Ptr, this.GetType().Name, x509->type, (long)x509->ptr);
            }
#endif

            if (Native.X509_OBJECT_up_ref_count(this._Ptr) == 0)
                this._Owner = false;
		}

		/// <summary>
		/// Calls X509_OBJECT_free_contents()
		/// </summary>
        /// 
        //[System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
        //[System.Security.SecurityCritical]
        protected override void OnDispose()
		{


            //try
            //{
                //Native.X509_OBJECT_free_contents(ptr);
                //Native.X509_OBJECT_free(ptr);
            //}
            //catch
            //{
            //    throw new Exception("[Native.X509_OBJECT_free] Exception: ptr:" + ptr + " raw[type]:" + raw.type + " raw[ptr]:" + raw.ptr);
            //}


            unsafe
            {
                X509_OBJECT* x509 = (X509_OBJECT*)this._Ptr;

                if (x509->ptr != IntPtr.Zero)
                {
#if _LOG
                    Log.Log.Debug("[X509Object][OnDispose][{0}][{1:X16}] {2}:{3}:{4:X16}", this.InstanceID, (long)this._Ptr, this.GetType().Name, x509->type, (long)x509->ptr);
#endif

                    switch (x509->type)
                    {
                        case X509_LU_NONE:
                            break;
                        case X509_LU_X509:
                            Native.X509_free(x509->ptr);
                            break;
                        case X509_LU_CRL:
                            Native.X509_CRL_free(x509->ptr);
                            break;

                        default:
                            throw new Exception("[X509Object][OnDispose] Invalid type:" + x509->type);
                    }
                }
                
            }
                
                

            //if (raw.ptr != IntPtr.Zero)
            //{
            //    switch (raw.type)
            //    {
            //        case X509_LU_NONE:
            //            break;
            //        case X509_LU_X509:
            //            Native.X509_free(raw.ptr);
            //            break;
            //        case X509_LU_CRL:
            //            Native.X509_CRL_free(raw.ptr);
            //            break;
            //    }
            //}
		}

        //internal override void OnNewHandle(IntPtr ptr)
        //{
        //    raw = (X509_OBJECT)Marshal.PtrToStructure(this.ptr, typeof(X509_OBJECT));
        //}

		#endregion

		#region Fields
		//private X509_OBJECT raw;
		#endregion

	}
}
