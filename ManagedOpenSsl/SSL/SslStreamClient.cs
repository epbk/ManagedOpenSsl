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
using OpenSSL.Extensions;
using OpenSSL.X509;
using System.IO;
using OpenSSL;
using System;

namespace OpenSSL.SSL
{
	internal class SslStreamClient : SslStreamBase
	{
		private string _TargetHost;
        private X509List _ClientCertificates;
        private X509Chain _CaCertificates;

		public SslStreamClient(
			Stream stream,
			string strTargetHost,
			X509List clientCertificates,
			X509Chain caCertificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
            string strSslCiphers,
			bool bCheckCertificateRevocationStatus,
			RemoteCertificateValidationHandler remoteCallback,
			LocalCertificateSelectionHandler localCallback) : base(stream, strTargetHost)
		{
			this._TargetHost = strTargetHost;
			this._ClientCertificates = clientCertificates;
			this._CaCertificates = caCertificates;
			this._CheckCertificateRevocationStatus = bCheckCertificateRevocationStatus;
            this._OnRemoteCertificate = remoteCallback;
            this._OnLocalCertificate = localCallback;
			this.InitializeClientContext(clientCertificates, enabledSslProtocols, sslStrength, strSslCiphers, bCheckCertificateRevocationStatus);
		}

		protected void InitializeClientContext(
			X509List certificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
            string strSslCiphers,
			bool bCheckCertificateRevocation)
		{
			// Initialize the context with specified TLS version
            this._SslContext = new SslContext(SslMethod.TLS_client_method, ConnectionEnd.Client, new[] {
				Protocols.Http2,
				Protocols.Http1
			});
            
            //var options = sslContext.Options;

            //// Remove support for protocols not specified in the enabledSslProtocols
            //if (!EnumExtensions.HasFlag(enabledSslProtocols, SslProtocols.Ssl2))
            //{
            //    options |= SslOptions.SSL_OP_NO_SSLv2;
            //}

            //if (!EnumExtensions.HasFlag(enabledSslProtocols, SslProtocols.Ssl3))
            //{
            //    options |= SslOptions.SSL_OP_NO_SSLv3;
            //}

            //if (!EnumExtensions.HasFlag(enabledSslProtocols, SslProtocols.Tls))
            //{
            //    options |= SslOptions.SSL_OP_NO_TLSv1;
            //}

            //sslContext.Options = options;

            SslProtocols options = this._SslContext.ProtocolMin;

            options = enabledSslProtocols;

            this._SslContext.ProtocolMin = options;

            //Native.ExpectSuccess(Native.SSL_CTX_set_options(sslContext.Handle, Native.SSL_OP_NO_RENEGOTIATION));

			// Set the Local certificate selection callback
            this._SslContext.SetClientCertCallback(this.onClientCertificate);

			// Set the enabled cipher list
            if (!string.IsNullOrWhiteSpace(strSslCiphers))
                this._SslContext.SetCipherList(strSslCiphers);
            else
                this._SslContext.SetCipherList(SslCipher.MakeString(enabledSslProtocols, sslStrength));

			// Set the callbacks for remote cert verification and local cert selection
            if (this._OnRemoteCertificate != null)
                this._SslContext.SetVerify(VerifyMode.SSL_VERIFY_PEER | VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, this._OnRemoteCertificate);

			// Set the CA list into the store
			if (this._CaCertificates != null)
			{
                X509Store store = new X509Store(this._CaCertificates);
                this._SslContext.SetCertificateStore(store);
			}

			// Set up the read/write bio's
            this._BIO_read = BIO.MemoryBuffer(false);
            this._BIO_write = BIO.MemoryBuffer(false);
            this._Ssl = new Ssl(this._SslContext);

            this._SniCb = this._SniExt.ClientSniCb;
            this._SniExt.AttachSniExtensionClient(this._Ssl.Handle, this._SslContext.Handle, this._SniCb);

            this._Ssl.SetBIO(this._BIO_read, this._BIO_write);
            this._BIO_read.SetClose(BIO.CloseOption.Close);
            this._BIO_write.SetClose(BIO.CloseOption.Close);

			// Set the Ssl object into Client mode
            this._Ssl.SetConnectState();
		}

		protected override bool ProcessHandshake()
		{
			int iRet = 0;

            if (this._HandShakeState == HandshakeState.InProcess)
                iRet = this._Ssl.Connect();
            else if (this._HandShakeState == HandshakeState.RenegotiateInProcess || this._HandShakeState == HandshakeState.Renegotiate)
			{
                this._HandShakeState = HandshakeState.RenegotiateInProcess;
                iRet = this._Ssl.DoHandshake();
			}

			if (iRet <= 0)
			{
                SslError lastError = this._Ssl.GetError(iRet);
				if (lastError == SslError.SSL_ERROR_WANT_READ)
				{
					// Do nothing -- the base stream will write the data from the bio
					// when this call returns
				}
				else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
				{
					// unexpected error
					//!!TODO - debug log
				}
				else
				{
					// We should have alert data in the bio that needs to be written
					// We'll save the exception, allow the write to start, and then throw the exception
					// when we come back into the AsyncHandshakeCall
                    if (this._BIO_write.BytesPending > 0)
                        this._HandshakeException = new OpenSslException();
					else
						throw new OpenSslException();
				}
			}
			else
                return true; // Successful handshake

			return false;
		}

		private int onClientCertificate(Ssl ssl, out X509Certificate x509_cert, out CryptoKey key)
		{
			x509_cert = null;
			key = null;

            Core.Stack<X509Name> name_stack = ssl.CAList;
			string[] issuers = new string[name_stack.Count];
			int iCount = 0;

            foreach (X509Name name in name_stack)
			{
				issuers[iCount++] = name.OneLine;
			}

			if (this._OnLocalCertificate != null)
			{
                X509Certificate cert = this._OnLocalCertificate(this, this._TargetHost, this._ClientCertificates, ssl.GetPeerCertificate(), issuers);
				if (cert != null && cert.HasPrivateKey)
				{
					x509_cert = cert;
					key = cert.PrivateKey;
					// Addref the cert and private key
					x509_cert.AddRef();
					key.AddRef();
					// return success
					return 1;
				}
			}

			return 0;
		}
	}
}
