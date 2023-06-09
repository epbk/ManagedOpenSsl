// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
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
using System;

namespace OpenSSL.Crypto.EC
{
	/// <summary>
	/// 
	/// </summary>
	public class Group : Base
	{
		#region Initialization
		internal Group(IntPtr ptr, bool owner)
			: base(ptr, owner)
		{
		}

		/// <summary>
		/// Calls EC_GROUP_new()
		/// </summary>
		/// <param name="method"></param>
		public Group(Method method)
			: base(Native.ExpectNonNull(Native.EC_GROUP_new(method.Handle)), true)
		{
		}

		/// <summary>
		/// Calls EC_GROUP_new_by_curve_name()
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public static Group FromCurveName(Asn1Object obj)
		{
			return new Group(Native.ExpectNonNull(Native.EC_GROUP_new_by_curve_name(obj.NID)), true);
		}
		#endregion

		#region Properties
		/// <summary>
		/// Calls EC_GROUP_get_degree()
		/// </summary>
		public int Degree
		{
			get { return Native.EC_GROUP_get_degree(_Ptr); }
		}

		/// <summary>
		/// Calls EC_GROUP_method_of()
		/// </summary>
		public Method Method
		{
			get { return new Method(Native.EC_GROUP_method_of(_Ptr), false); }
		}
		#endregion

		#region Methods
		#endregion

		#region Overrides
		/// <summary>
		/// Calls EC_GROUP_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.EC_GROUP_free(this._Ptr);
		}
		#endregion
	}
}

