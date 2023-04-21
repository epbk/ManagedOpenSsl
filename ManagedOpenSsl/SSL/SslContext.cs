// Copyright (c) 2009 Ben Henderson
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
using OpenSSL.X509;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using OpenSSL.Extensions;

namespace OpenSSL.SSL
{
    /// <summary>
    ///     Wraps the SST_CTX structure and methods
    /// </summary>
    internal sealed class SslContext : Base
    {
        #region Members

        private AlpnExtension _AlpnExt;
        private ClientCertCallbackHandler _OnClientCert;
        private RemoteCertificateValidationHandler _OnVerifyCert;

        // hold down the thunk so it doesn't get collected
        private Native.client_cert_cb _ptrOnClientCertThunk;
        private Native.VerifyCertCallback _ptrOnVerifyCertThunk;
        private Native.alpn_cb _ptrOnAlpn;

        #endregion


        /// <summary>
        ///     Calls SSL_CTX_new()
        /// </summary>
        /// <param name="sslMethod"></param>
        /// <param name="end"></param>
        /// <param name="protoList"></param>
        public SslContext(SslMethod sslMethod, ConnectionEnd end, IEnumerable<string> protoList)
            : base(Native.ExpectNonNull(Native.SSL_CTX_new(sslMethod.Handle)), true)
        {
            this._AlpnExt = new AlpnExtension(this.Handle, protoList);

            this._ptrOnClientCertThunk = this.onClientCertThunk;
            this._ptrOnVerifyCertThunk = this.onVerifyCertThunk;
            this._ptrOnAlpn = this._AlpnExt.AlpnCb;

            if (end == ConnectionEnd.Server)
            {
                Native.SSL_CTX_set_alpn_select_cb(this.Handle, this._ptrOnAlpn, IntPtr.Zero);
            }
        }

        #region Properties

        /// <summary>
        ///     Calls SSL_CTX_set_options
        /// </summary>
        public SslOptions Options
        {
            set { Native.ExpectSuccess(Native.SSL_CTX_set_options(this._Ptr, (int)value)); }
            get { return (SslOptions)Native.SSL_CTX_get_options(this._Ptr); }
        }

        public SslMode Mode
        {
            set { Native.ExpectSuccess(Native.SSL_CTX_set_mode(this._Ptr, (int)value)); }
            get { return (SslMode)Native.SSL_CTX_get_mode(this._Ptr); }
        }

        public SslProtocols ProtocolMin
        {
            set { Native.ExpectSuccess(Native.SSL_CTX_ctrl(this._Ptr, Native.SSL_CTRL_SET_MIN_PROTO_VERSION, (int)value, IntPtr.Zero)); }
            get { return (SslProtocols)Native.SSL_CTX_ctrl(this._Ptr, Native.SSL_CTRL_GET_MIN_PROTO_VERSION, 0, IntPtr.Zero); }
        }

        public SslProtocols ProtocolMax
        {
            set { Native.ExpectSuccess(Native.SSL_CTX_ctrl(this._Ptr, Native.SSL_CTRL_SET_MAX_PROTO_VERSION, (int)value, IntPtr.Zero)); }
            get { return (SslProtocols)Native.SSL_CTX_ctrl(this._Ptr, Native.SSL_CTRL_GET_MAX_PROTO_VERSION, 0, IntPtr.Zero); }
        }

        #endregion

        private int onVerifyCertThunk(int iOK, IntPtr store)
        {
            X509StoreContext ctx = new X509StoreContext(store, false);

            // build the X509Chain from the store
#if _BUILD_CHAIN
            using (X509Chain chain = new X509Chain())
            {
                foreach (X509Object obj in ctx.Store.Objects)
                {
                    X509Certificate cert = obj.Certificate;
                    if (cert != null)
                        chain.Add(cert);

                    //Dispose the X509Object now !!!
                    obj.Dispose();
                }
#else
            {
#endif
                // Call the managed delegate
                return _OnVerifyCert(
                    this,
                    ctx.CurrentCert,
#if _BUILD_CHAIN
                    chain, 
#else
                    null,
#endif
                    ctx.ErrorDepth,
                    (VerifyResult)ctx.Error
                ) ? 1 : 0;
            }
        }

        private int onClientCertThunk(IntPtr ptrSsl, out IntPtr ptrCert, out IntPtr ptrKey)
        {
            ptrCert = IntPtr.Zero;
            ptrKey = IntPtr.Zero;

            Ssl ssl = new Ssl(ptrSsl, false);
            X509Certificate cert;
            CryptoKey key;

            int iRet = this._OnClientCert(ssl, out cert, out key);
            if (iRet != 0)
            {
                if (cert != null)
                    ptrCert = cert.Handle;

                if (key != null)
                    ptrKey = key.Handle;
            }
            return iRet;
        }

        #region Methods

        /// <summary>
        ///     Sets the certificate store for the context - calls SSL_CTX_set_cert_store
        ///     The X509Store object and contents will be freed when the context is disposed.
        ///     Ensure that the store object and it's contents have IsOwner set to false
        ///     before assigning them into the context.
        /// </summary>
        /// <param name="store"></param>
        public void SetCertificateStore(X509Store store)
        {
            store.AddRef();
            Native.SSL_CTX_set_cert_store(this._Ptr, store.Handle);
        }

        /// <summary>
        ///     Sets the certificate verification mode and callback - calls SSL_CTX_set_verify
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="callback"></param>
        public void SetVerify(VerifyMode mode, RemoteCertificateValidationHandler callback)
        {
            this._OnVerifyCert = callback;
            Native.SSL_CTX_set_verify(this._Ptr, (int)mode, callback == null ? null : this._ptrOnVerifyCertThunk);
        }

        /// <summary>
        ///     Sets the certificate verification depth - calls SSL_CTX_set_verify_depth
        /// </summary>
        /// <param name="iDepth"></param>
        public void SetVerifyDepth(int iDepth)
        {
            Native.SSL_CTX_set_verify_depth(this._Ptr, iDepth);
        }

        public Core.Stack<X509Name> LoadClientCAFile(string strFilename)
        {
            IntPtr ptr = Native.SSL_load_client_CA_file(strFilename);
            return new Core.Stack<X509Name>(ptr, true);
        }

        /// <summary>
        ///     Calls SSL_CTX_set_client_CA_list/SSL_CTX_get_client_CA_list
        ///     The Stack and the X509Name objects contined within them
        ///     are freed when the context is disposed.  Make sure that
        ///     the Stack and X509Name objects have set IsOwner to false
        ///     before assigning them to the context.
        /// </summary>
        public Core.Stack<X509Name> CAList
        {
            get
            {
                IntPtr ptr = Native.SSL_CTX_get_client_CA_list(this._Ptr);
                return new Core.Stack<X509Name>(ptr, false);
            }
            set
            {
                value.AddRef();
                Native.SSL_CTX_set_client_CA_list(this._Ptr, value.Handle);
            }
        }

        public int LoadVerifyLocations(string strCaFile, string strCaPath)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_load_verify_locations(this._Ptr, strCaFile, strCaPath));
        }

        public int SetDefaultVerifyPaths()
        {
            return Native.ExpectSuccess(Native.SSL_CTX_set_default_verify_paths(this._Ptr));
        }

        public int SetCipherList(string strCipherList)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_set_cipher_list(this._Ptr, strCipherList));
        }

        public int UseCertificate(X509Certificate cert)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_use_certificate(this._Ptr, cert.Handle));
        }

        public int UseCertificateChainFile(string strFilename)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_use_certificate_chain_file(this._Ptr, strFilename));
        }

        public int UsePrivateKey(CryptoKey key)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_use_PrivateKey(this._Ptr, key.Handle));
        }

        public int UsePrivateKeyFile(string strFilename, SslFileType type)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_use_PrivateKey_file(this._Ptr, strFilename, (int)type));
        }

        public int CheckPrivateKey()
        {
            return Native.ExpectSuccess(Native.SSL_CTX_check_private_key(this._Ptr));
        }

        public int SetSessionIdContext(byte[] sid_ctx)
        {
            return Native.ExpectSuccess(Native.SSL_CTX_set_session_id_context(this._Ptr, sid_ctx, (uint)sid_ctx.Length));
        }

        public void SetClientCertCallback(ClientCertCallbackHandler callback)
        {
            this._OnClientCert = callback;
            Native.SSL_CTX_set_client_cert_cb(this._Ptr, callback == null ? null : this._ptrOnClientCertThunk);
        }

        #endregion

        #region IDisposable Members

        /// <summary>
        ///     base override - calls SSL_CTX_free()
        /// </summary>
        protected override void OnDispose()
        {
            Native.SSL_CTX_free(this._Ptr);
        }

        #endregion
    }
}