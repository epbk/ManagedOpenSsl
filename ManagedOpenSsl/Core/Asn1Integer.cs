﻿// Copyright (c) 2009 Frank Laub
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

using System;

namespace OpenSSL.Core
{
	class Asn1Integer : Base
	{
		internal Asn1Integer(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{ }

		public Asn1Integer()
			: base(Native.ASN1_INTEGER_new(), true)
		{ }

		public Asn1Integer(int value)
			: this()
		{
			Value = value;
		}

		protected override void OnDispose()
		{
			Native.ASN1_INTEGER_free(_Ptr);
		}

		public int Value
		{
			get { return (int)Native.ASN1_INTEGER_get(_Ptr); }
			set { Native.ExpectSuccess(Native.ASN1_INTEGER_set(_Ptr, value)); }
		}

		public static int ToInt32(IntPtr ptr)
		{
			return (int)Native.ASN1_INTEGER_get(ptr);
		}
	}
}
