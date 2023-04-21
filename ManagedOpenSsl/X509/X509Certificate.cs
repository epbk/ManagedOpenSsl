// Copyright (c) 2006-2010 Frank Laub
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
	/// Wraps the X509 object
	/// </summary>
	public class X509Certificate : BaseReferenceImpl, IComparable<X509Certificate>, IStackable
	{
		#region Initialization

		internal X509Certificate(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{
		}

		internal X509Certificate(IntPtr ptr, bool owner)
			: base(ptr, owner)
		{
		}

		internal X509Certificate(IntPtr ptr, IntPtr pkey)
			: base(ptr, true)
		{
			if (pkey != IntPtr.Zero)
                this._PrivateKey = new CryptoKey(pkey, true);
		}

		private X509Certificate(X509Certificate other)
			: base(other.Handle, true)
		{
            this.AddRef();

			if (other._PrivateKey != null)
                this._PrivateKey = other._PrivateKey.CopyRef();
		}

		/// <summary>
		/// Calls X509_new()
		/// </summary>
		public X509Certificate()
			: base(Native.ExpectNonNull(Native.X509_new()), true)
		{
		}

		/// <summary>
		/// Calls PEM_read_bio_X509()
		/// </summary>
		/// <param name="bio"></param>
		public X509Certificate(BIO bio)
			: base(
				Native.ExpectNonNull(Native.PEM_read_bio_X509(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)),
				true)
		{
		}

		/// <summary>
		/// Factory method that returns a X509 using d2i_X509_bio()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromDER(BIO bio)
		{
			IntPtr pX509 = IntPtr.Zero;
			IntPtr pCert = Native.ExpectNonNull(Native.d2i_X509_bio(bio.Handle, ref pX509));
			return new X509Certificate(pCert, true);
		}

		/// <summary>
		/// Factory method to create a X509Certificate from a PKCS7 encoded in PEM
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromPKCS7_PEM(BIO bio)
		{
            PKCS7 pkcs7 = PKCS7.FromPEM(bio);
            X509Chain chain = pkcs7.Certificates;

			if (chain != null && chain.Count > 0)
				return new X509Certificate(chain[0].Handle, false);
			else
				throw new OpenSslException();
		}

		/// <summary>
		/// Factory method to create a X509Certificate from a PKCS7 encoded in DER
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromPKCS7_DER(BIO bio)
		{
            PKCS7 pkcs7 = PKCS7.FromDER(bio);
            X509Chain chain = pkcs7.Certificates;

			if (chain != null && chain.Count > 0)
				return new X509Certificate(chain[0].Handle, false);

			return null;
		}

		/// <summary>
		/// Factory method to create a X509Certificate from a PKCS12
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="strPassword"></param>
		/// <returns></returns>
		public static X509Certificate FromPKCS12(BIO bio, string strPassword)
		{
            using (PKCS12 p12 = new PKCS12(bio, strPassword))
			{
				return p12.Certificate;
			}
		}

		/// <summary>
		/// Creates a new X509 certificate
		/// </summary>
		/// <param name="serial"></param>
		/// <param name="subject"></param>
		/// <param name="issuer"></param>
		/// <param name="pubkey"></param>
		/// <param name="start"></param>
		/// <param name="end"></param>
		public X509Certificate(
			byte[] serial,
			X509Name subject,
			X509Name issuer,
			CryptoKey pubkey,
			DateTime start,
			DateTime end)
			: this()
		{
            this.Version = 2;
            this.SerialNumber = serial;
            this.Subject = subject;
            this.Issuer = issuer;
            this.PublicKey = pubkey;
            this.NotBefore = start;
            this.NotAfter = end;
		}

		#endregion

		#region Raw Structures

		#region X509_VAL

        [StructLayout(LayoutKind.Sequential)]
        struct ASN1_STRING
        {
            public int length;
            public int type;
            public IntPtr data;
            /*
             * The value of the following field depends on the type being held.  It
             * is mostly being used for BIT_STRING so if the input data has a
             * non-zero 'unused bits' value, it will be handled correctly
             */
            public int flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ASN1_ENCODING
        {
            public IntPtr enc;         /* DER encoding */
            public int len;                   /* Length of encoding */
            public int modified;               /* set to 1 if 'enc' is invalid */
        }

		[StructLayout(LayoutKind.Sequential)]
		private struct X509_VAL
		{
			public IntPtr notBefore;
			public IntPtr notAfter;
		}

        [StructLayout(LayoutKind.Sequential)]
        struct X509_SIG_INFO
        {
            /* NID of message digest */
            public int mdnid;
            /* NID of public key algorithm */
            public int pknid;
            /* Security bits */
            public int secbits;
            /* Various flags */
            uint flags;
        }

		#endregion

		#region X509_CINF

		[StructLayout(LayoutKind.Sequential)]
		private struct X509_CINF
		{
			public IntPtr version;
            public ASN1_STRING serialNumber;
			public X509_ALGOR signature;
			public IntPtr issuer;
            public X509_VAL validity;
			public IntPtr subject;
			public IntPtr key;
			public IntPtr issuerUID;
			public IntPtr subjectUID;
			public IntPtr extensions;
			public Asn1Encoding enc;
		}

		#endregion

		#region X509

		[StructLayout(LayoutKind.Sequential)]
		private struct X509
		{
            public X509_CINF cert_info;
            public X509_ALGOR sig_alg;
            public ASN1_STRING signature;
            public X509_SIG_INFO siginf;
			public int references;
			//public IntPtr name;

			#region CRYPTO_EX_DATA ex_data

			public IntPtr ex_data_sk;
			//public int ex_data_dummy;

			#endregion

			public int ex_pathlen;
			public int ex_pcpathlen;
			public uint ex_flags;
			public uint ex_kusage;
			public uint ex_xkusage;
			public uint ex_nscert;
			public IntPtr skid;
			public IntPtr akid;
			public IntPtr policy_cache;
			public IntPtr crldp;
			public IntPtr altname;
			public IntPtr nc;
			public IntPtr rfc3779_addr;
			public IntPtr rfc3779_asid;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.SHA_DIGEST_LENGTH)]
			public byte[] sha1_hash;
			public IntPtr aux;
            public IntPtr _lock;
            public int ex_cached;
		}

		#endregion

		#endregion

		#region Properties

		private X509 Raw
		{
			get { return (X509)Marshal.PtrToStructure(this._Ptr, typeof(X509)); }
		}

		private X509_CINF RawCertInfo
		{
			//get { return (X509_CINF)Marshal.PtrToStructure(Raw.cert_info, typeof(X509_CINF)); }
            get { return this.Raw.cert_info; }
		}

		private X509_VAL RawValidity
		{
			//get { return (X509_VAL)Marshal.PtrToStructure(RawCertInfo.validity, typeof(X509_VAL)); }
            get { return this.RawCertInfo.validity; }
		}

		/// <summary>
		/// Uses X509_get_subject_name() and X509_set_issuer_name()
		/// </summary>
		public X509Name Subject
		{
			get
			{
				// Get the native pointer for the subject name
				IntPtr p = Native.ExpectNonNull(Native.X509_get_subject_name(this._Ptr));
                X509Name x509Name = new X509Name(p, false);
				// Duplicate the native pointer, as the X509_get_subject_name returns a pointer
				// that is owned by the X509 object
				x509Name.AddRef();
				return x509Name;
			}
			set { Native.ExpectSuccess(Native.X509_set_subject_name(this._Ptr, value.Handle)); }
		}

		/// <summary>
		/// Uses X509_get_issuer_name() and X509_set_issuer_name()
		/// </summary>
		public X509Name Issuer
		{
			get
			{
                // Get the native pointer for the issuer name
                IntPtr p = Native.ExpectNonNull(Native.X509_get_issuer_name(this._Ptr));
                X509Name x509Name = new X509Name(p, false);
                // Duplicate the native pointer, as the X509_get_issuer_name returns a pointer
                // that is owned by the X509 object
				x509Name.AddRef();
				return x509Name;
			}
            set { Native.ExpectSuccess(Native.X509_set_issuer_name(this._Ptr, value.Handle)); }
		}

		/// <summary>
		/// Uses X509_get_serialNumber() and X509_set_serialNumber()
		/// </summary>
		public byte[] SerialNumber
		{
			get
            {
                ASN1_STRING sn = this.Raw.cert_info.serialNumber;

                if (sn.length > 0)
                {
                    byte[] result = new byte[sn.length];
                    Marshal.Copy(sn.data, result, 0, result.Length);
                    return result;
                }
                else
                    return null;

                //return Asn1Integer.ToInt32(Native.X509_get_serialNumber(ptr));
            }
            set
            {
                using (Asn1Integer asnInt = new Asn1Integer(BitConverter.ToInt32(value, 0)))
                {
                    Native.ExpectSuccess(Native.X509_set_serialNumber(this._Ptr, asnInt.Handle));
                }
            }
		}

		/// <summary>
		/// Uses the notBefore field and X509_set_notBefore()
		/// </summary>
		public DateTime NotBefore
		{
            get { return Asn1DateTime.ToDateTime(this.RawValidity.notBefore); }
			set
			{
                using (Asn1DateTime asnDateTime = new Asn1DateTime(value))
				{
                    Native.ExpectSuccess(Native.X509_set1_notBefore(this._Ptr, asnDateTime.Handle));
				}
			}
		}

		/// <summary>
		/// Uses the notAfter field and X509_set_notAfter()
		/// </summary>
		public DateTime NotAfter
		{
            get { return Asn1DateTime.ToDateTime(this.RawValidity.notAfter); }
			set
			{
                using (Asn1DateTime asnDateTime = new Asn1DateTime(value))
				{
                    Native.ExpectSuccess(Native.X509_set1_notAfter(this._Ptr, asnDateTime.Handle));
				}
			}
		}

		/// <summary>
		/// Uses the version field and X509_set_version()
		/// </summary>
		public int Version
		{
            get { return (int)Native.ASN1_INTEGER_get(this.RawCertInfo.version); }
            set { Native.ExpectSuccess(Native.X509_set_version(this._Ptr, value)); }
		}

		/// <summary>
		/// Uses X509_get_pubkey() and X509_set_pubkey()
		/// </summary>
		public CryptoKey PublicKey
		{
			get
			{
				// X509_get_pubkey() will increment the refcount internally
                IntPtr pKey = Native.ExpectNonNull(Native.X509_get_pubkey(this._Ptr));
				return new CryptoKey(pKey, true);
			}
            set { Native.ExpectSuccess(Native.X509_set_pubkey(this._Ptr, value.Handle)); }
		}

		/// <summary>
		/// Returns whether or not a Private Key is attached to this Certificate
		/// </summary>
		public bool HasPrivateKey
		{
			get { return this._PrivateKey != null; }
		}

		/// <summary>
		/// Gets and Sets the Private Key for this Certificate.
		/// The Private Key MUST match the Public Key.
		/// </summary>
		public CryptoKey PrivateKey
		{
			get
			{
                if (this._PrivateKey == null)
					return null;

                return this._PrivateKey.CopyRef();
			}
			set
			{
				if (value == null)
                    this._PrivateKey = null;
				else
				{
					if (this.CheckPrivateKey(value))
                        this._PrivateKey = value.CopyRef();
					else
						throw new ArgumentException("Private key doesn't correspond to the this certificate");
				}
			}
		}

		/// <summary>
		/// Returns the PEM formatted string of this object
		/// </summary>
		public string PEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.Write(bio);
					return bio.ReadString();
				}
			}
		}

		/// <summary>
		/// Returns the DER formatted byte array for this object
		/// </summary>
		public byte[] DER
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
                    this.Write_DER(bio);
					return bio.ReadBytes((int)bio.NumberWritten).Array;
				}
			}
		}

		#endregion

		#region Methods

		/// <summary>
		/// Returns a copy of this object.
		/// </summary>
		/// <returns></returns>
		public X509Certificate CopyRef()
		{
			return new X509Certificate(this);
		}

		/// <summary>
		/// Calls X509_sign()
		/// </summary>
		/// <param name="pkey"></param>
		/// <param name="digest"></param>
		public void Sign(CryptoKey pkey, MessageDigest digest)
		{
            if (Native.X509_sign(this._Ptr, pkey.Handle, digest.Handle) == 0)
				throw new OpenSslException();
		}

		/// <summary>
		/// Returns X509_check_private_key()
		/// </summary>
		/// <param name="pkey"></param>
		/// <returns></returns>
		public bool CheckPrivateKey(CryptoKey pkey)
		{
            return Native.X509_check_private_key(this._Ptr, pkey.Handle) == 1;
		}

		/// <summary>
		/// Returns X509_check_trust()
		/// </summary>
		/// <param name="id"></param>
		/// <param name="flags"></param>
		/// <returns></returns>
		public bool CheckTrust(int id, int flags)
		{
            return Native.X509_check_trust(this._Ptr, id, flags) == 1;
		}

		/// <summary>
		/// Returns X509_verify()
		/// </summary>
		/// <param name="pkey"></param>
		/// <returns></returns>
		public bool Verify(CryptoKey pkey)
		{
            int iRet = Native.X509_verify(this._Ptr, pkey.Handle);

			if (iRet < 0)
				throw new OpenSslException();

			return iRet == 1;
		}

		/// <summary>
		/// Returns X509_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public ArraySegment<byte> Digest(IntPtr type, byte[] digest)
		{
			uint wLen = (uint)digest.Length;

            Native.ExpectSuccess(Native.X509_digest(this._Ptr, type, digest, ref wLen));

			return new ArraySegment<byte>(digest, 0, (int)wLen);
		}

		/// <summary>
		/// Returns X509_pubkey_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public ArraySegment<byte> DigestPublicKey(IntPtr type, byte[] digest)
		{
			uint wLen = (uint)digest.Length;

            Native.ExpectSuccess(Native.X509_pubkey_digest(this._Ptr, type, digest, ref wLen));

			return new ArraySegment<byte>(digest, 0, (int)wLen);
		}

		/// <summary>
		/// Calls PEM_write_bio_X509()
		/// </summary>
		/// <param name="bio"></param>
		public void Write(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_X509(bio.Handle, this._Ptr));
		}

		/// <summary>
		/// Calls i2d_X509_bio()
		/// </summary>
		/// <param name="bio"></param>
		public void Write_DER(BIO bio)
		{
            Native.ExpectSuccess(Native.i2d_X509_bio(bio.Handle, this._Ptr));
		}

		/// <summary>
		/// Calls X509_print()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
            Native.ExpectSuccess(Native.X509_print(bio.Handle, this._Ptr));
		}

		/// <summary>
		/// Converts a X509 into a request using X509_to_X509_REQ()
		/// </summary>
		/// <param name="pkey"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public X509Request CreateRequest(CryptoKey pkey, MessageDigest digest)
		{
            return new X509Request(Native.ExpectNonNull(Native.X509_to_X509_REQ(this._Ptr, pkey.Handle, digest.Handle)), true);
		}

		/// <summary>
		/// Calls X509_add_ext()
		/// </summary>
		/// <param name="ext"></param>
		public void AddExtension(X509Extension ext)
		{
            Native.ExpectSuccess(Native.X509_add_ext(this._Ptr, ext.Handle, -1));
		}

		/// <summary>
		/// Calls X509_add1_ext_i2d()
		/// </summary>
		/// <param name="name"></param>
		/// <param name="value"></param>
		/// <param name="crit"></param>
		/// <param name="flags"></param>
		public void AddExtension(string name, byte[] value, int crit, uint flags)
		{
			Native.ExpectSuccess(Native.X509_add1_ext_i2d(this._Ptr, Native.TextToNID(name), value, crit, flags));
		}

		/// <summary>
		/// 
		/// </summary>
		public Core.Stack<X509Extension> Extensions
		{
			get
			{
				if (RawCertInfo.extensions != IntPtr.Zero)
					return new Core.Stack<X509Extension>(RawCertInfo.extensions, false);

				return new Core.Stack<X509Extension>();
			}
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="sk_ext"></param>
		public void AddExtensions(Core.Stack<X509Extension> sk_ext)
		{
            foreach (X509Extension ext in sk_ext)
			{
				this.AddExtension(ext);
			}
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls X509_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.X509_free(_Ptr);

            if (this._PrivateKey != null)
			{
                this._PrivateKey.Dispose();
                this._PrivateKey = null;
			}
		}

		/// <summary>
		/// Compares X509Certificate
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public override bool Equals(object obj)
		{
			var rhs = obj as X509Certificate;

			if (rhs == null)
				return false;

			return CompareTo(rhs) == 0;
		}

		/// <summary>
		/// Returns the hash code of the issuer's oneline xor'd with the serial number
		/// </summary>
		/// <returns></returns>
		public override int GetHashCode()
		{
			return Issuer.OneLine.GetHashCode() ^ SerialNumber.GetHashCode();
		}

		internal override CryptoLockTypes LockType
		{
			get { return CryptoLockTypes.CRYPTO_LOCK_X509; }
		}

		internal override Type RawReferenceType
		{
			get { return typeof(X509); }
		}

		#endregion

		#region IComparable Members

		/// <summary>
		/// Returns X509_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(X509Certificate other)
		{
			return Native.X509_cmp(_Ptr, other._Ptr);
		}

		#endregion

		#region Fields

		private CryptoKey _PrivateKey;

		#endregion
	}
}
