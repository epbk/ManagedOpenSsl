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
using OpenSSL.X509;
using System;
using System.IO;
using System.Text;
using OpenSSL;

namespace OpenSSL.SSL
{
	internal class SslStreamServer : SslStreamBase
	{
		public SslStreamServer(
			Stream stream,
            string strTargetHost,
			X509Certificate serverCertificate,
			bool bClientCertificateRequired,
			X509Chain caCerts,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
            string strSslCiphers,
			bool bCheckCertificateRevocation,
			RemoteCertificateValidationHandler remote_callback) : base(stream, strTargetHost)
		{
            this._CheckCertificateRevocationStatus = bCheckCertificateRevocation;
            this._OnRemoteCertificate = remote_callback;

			// Initialize the SslContext object
            this.initializeServerContext(serverCertificate, bClientCertificateRequired, caCerts, enabledSslProtocols, sslStrength, strSslCiphers, bCheckCertificateRevocation);
            
			// Initalize the Ssl object
            this._Ssl = new Ssl(this._SslContext);

            this._SniCb = this._SniExt.ServerSniCb;
            this._SniExt.AttachSniExtensionServer(this._Ssl.Handle, this._SslContext.Handle, this._SniCb);

			// Initialze the read/write bio
            this._BIO_read = BIO.MemoryBuffer(false);
            this._BIO_write = BIO.MemoryBuffer(false);

			// Set the read/write bio's into the the Ssl object
            this._Ssl.SetBIO(this._BIO_read, this._BIO_write);
            this._BIO_read.SetClose(BIO.CloseOption.Close);
            this._BIO_write.SetClose(BIO.CloseOption.Close);

			// Set the Ssl object into server mode
            this._Ssl.SetAcceptState();
		}

		protected override bool ProcessHandshake()
		{
			int iRet = 0;
            
			if (this._HandShakeState == HandshakeState.InProcess)
				iRet = this._Ssl.Accept();
            else if (this._HandShakeState == HandshakeState.RenegotiateInProcess)
                iRet = this._Ssl.DoHandshake();
            else if (this._HandShakeState == HandshakeState.Renegotiate)
			{
                iRet = this._Ssl.DoHandshake();
                this._Ssl.State = Ssl.SSL_ST_ACCEPT;
                this._HandShakeState = HandshakeState.RenegotiateInProcess;
			}

            SslError lastError = this._Ssl.GetError(iRet);
			if (lastError == SslError.SSL_ERROR_WANT_READ || 
				lastError == SslError.SSL_ERROR_WANT_WRITE || 
				lastError == SslError.SSL_ERROR_NONE)
			{
				return iRet == 1;
			}

			// Check to see if we have alert data in the write_bio that needs to be sent
            if (this._BIO_write.BytesPending > 0)
			{
				// We encountered an error, but need to send the alert
				// set the handshakeException so that it will be processed
				// and thrown after the alert is sent
                this._HandshakeException = new OpenSslException();
				return false;
			}

			// No alert to send, throw the exception
			throw new OpenSslException();
		}

		private void initializeServerContext(
			X509Certificate serverCertificate,
			bool bClientCertificateRequired,
			X509Chain caCerts,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
            string strSslCiphers,
			bool bCheckCertificateRevocation)
		{
			if (serverCertificate == null)
				throw new ArgumentNullException("serverCertificate", "Server certificate cannot be null");
			if (!serverCertificate.HasPrivateKey)
				throw new ArgumentException("Server certificate must have a private key", "serverCertificate");

			// Initialize the context with specified TLS version
            this._SslContext = new SslContext(SslMethod.TLSv12_server_method, ConnectionEnd.Server, new[] {Protocols.Http2, Protocols.Http1});
            
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

            //// Set the workaround options
            //sslContext.Options = options | SslOptions.SSL_OP_ALL;


            SslProtocols options = this._SslContext.ProtocolMin;

            options = enabledSslProtocols;

            this._SslContext.ProtocolMin = options;

			// Set the context mode
            this._SslContext.Mode = SslMode.SSL_MODE_AUTO_RETRY;

			// Set the client certificate verification callback if we are requiring client certs
			if (bClientCertificateRequired)
                this._SslContext.SetVerify(VerifyMode.SSL_VERIFY_PEER | VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, this._OnRemoteCertificate);
			else
                this._SslContext.SetVerify(VerifyMode.SSL_VERIFY_NONE, null);

			// Set the client certificate max verification depth
            this._SslContext.SetVerifyDepth(10);

			// Set the certificate store and ca list
			if (caCerts != null)
			{
				// Don't take ownership of the X509Store IntPtr.  When we
				// SetCertificateStore, the context takes ownership of the store pointer.
                this._SslContext.SetCertificateStore(new X509Store(caCerts, false));
                Core.Stack<X509Name> stack = new Core.Stack<X509Name>();
                foreach (X509Certificate cert in caCerts)
				{
                    X509Name subject = cert.Subject;
					stack.Add(subject);
				}
				// Assign the stack to the context
                this._SslContext.CAList = stack;
			}

			// Set the cipher string
            if (!string.IsNullOrWhiteSpace(strSslCiphers))
                this._SslContext.SetCipherList(strSslCiphers);
            else
                this._SslContext.SetCipherList(SslCipher.MakeString(enabledSslProtocols, sslStrength));
			
			// Set the certificate
            this._SslContext.UseCertificate(serverCertificate);

			// Set the private key
            this._SslContext.UsePrivateKey(serverCertificate.PrivateKey);

			// Set the session id context
            this._SslContext.SetSessionIdContext(Encoding.ASCII.GetBytes(AppDomain.CurrentDomain.FriendlyName));
		}
	}
}
