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

using OpenSSL.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;

namespace OpenSSL.SSL
{
	/// <summary>
	/// Implements an AuthenticatedStream and is the main interface to the SSL library.
	/// </summary>
    public class SslStream : AuthenticatedStream
    {
        #region Initialization

        /// <summary>
        /// Create an SslStream based on an existing stream.
        /// </summary>
        /// <param name="stream"></param>
        public SslStream(Stream stream)
            : this(stream, false)
        {
        }

        /// <summary>
        /// Create an SslStream based on an existing stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bLeaveInnerStreamOpen"></param>
        public SslStream(Stream stream, bool bLeaveInnerStreamOpen)
            : base(stream, bLeaveInnerStreamOpen)
        {
        }

        /// <summary>
        /// Create an SslStream based on an existing stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bLeaveInnerStreamOpen"></param>
        /// <param name="remote_callback"></param>
        public SslStream(Stream stream, bool bLeaveInnerStreamOpen, RemoteCertificateValidationHandler remote_callback)
            : this(stream, bLeaveInnerStreamOpen, remote_callback, null)
        {
        }

        /// <summary>
        /// Create an SslStream based on an existing stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="bLeaveInnerStreamOpen"></param>
        /// <param name="remote_callback"></param>
        /// <param name="local_callback"></param>
        public SslStream(
            Stream stream,
            bool bLeaveInnerStreamOpen,
            RemoteCertificateValidationHandler remote_callback,
            LocalCertificateSelectionHandler local_callback)
            : base(stream, bLeaveInnerStreamOpen)
        {
            this._RemoteCertificateValidationCallback = remote_callback;
            this._LocalCertificateSelectionCallback = local_callback;
        }

        #endregion

        #region AuthenticatedStream Members

        /// <summary>
        /// Returns whether authentication was successful.
        /// </summary>
        public override bool IsAuthenticated
        {
            get { return this._SslStream != null; }
        }

        /// <summary>
        /// Indicates whether data sent using this SslStream is encrypted.
        /// </summary>
        public override bool IsEncrypted
        {
            get { return this.IsAuthenticated; }
        }

        /// <summary>
        /// Indicates whether both server and client have been authenticated.
        /// </summary>
        public override bool IsMutuallyAuthenticated
        {
            get
            {
                if (this.IsAuthenticated &&
                    (this.IsServer ? this.Ssl.RemoteCertificate != null :
                        this.Ssl.LocalCertificate != null))
                {
                    return true;
                }

                return false;
            }
        }

        /// <summary>
        /// Indicates whether the local side of the connection was authenticated as the server.
        /// </summary>
        public override bool IsServer
        {
            get { return this._SslStream is SslStreamServer; }
        }

        /// <summary>
        /// Indicates whether the data sent using this stream is signed.
        /// </summary>
        public override bool IsSigned
        {
            get { return this.IsAuthenticated; }
        }

        #endregion

        #region Stream Members

        /// <summary>
        /// Gets a value indicating whether the current stream supports reading.
        /// </summary>
        public override bool CanRead
        {
            get { return this.InnerStream.CanRead; }
        }

        /// <summary>
        /// Gets a value indicating whether the current stream supports seeking.
        /// </summary>
        public override bool CanSeek
        {
            get { return this.InnerStream.CanSeek; }
        }

        /// <summary>
        /// Gets a value indicating whether the current stream supports writing.
        /// </summary>
        public override bool CanWrite
        {
            get { return this.InnerStream.CanWrite; }
        }

        /// <summary>
        /// Clears all buffers for this stream and causes any buffered data to be written to the underlying device.
        /// </summary>
        public override void Flush()
        {
            this.InnerStream.Flush();
        }

        /// <summary>
        /// Gets the length in bytes of the stream.
        /// </summary>
        public override long Length
        {
            get { return this.InnerStream.Length; }
        }

        /// <summary>
        /// Gets or sets the position within the current stream.
        /// </summary>
        public override long Position
        {
            get { return this.InnerStream.Position; }
            set { throw new NotSupportedException(); }
        }

        /// <summary>
        /// Gets or sets a value, in milliseconds, that determines how long the stream will attempt to read before timing out.
        /// </summary>
        public override int ReadTimeout
        {
            get { return this.InnerStream.ReadTimeout; }
            set { this.InnerStream.ReadTimeout = value; }
        }

        /// <summary>
        /// Gets or sets a value, in milliseconds, that determines how long the stream will attempt to write before timing out.
        /// </summary>
        public override int WriteTimeout
        {
            get { return this.InnerStream.WriteTimeout; }
            set { this.InnerStream.WriteTimeout = value; }
        }

        /// <summary>
        /// Reads a sequence of bytes from the current stream and advances the position within the stream by the number of bytes read.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            return this.EndRead(this.BeginRead(buffer, offset, count, null, null));
        }

        /// <summary>
        /// Begins an asynchronous read operation.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <param name="asyncCallback"></param>
        /// <param name="asyncState"></param>
        /// <returns></returns>
        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback asyncCallback, Object asyncState)
        {
            this.TestConnectionIsValid();

            return this._SslStream.BeginRead(buffer, offset, count, asyncCallback, asyncState);
        }

        /// <summary>
        /// Waits for the pending asynchronous read to complete.
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns></returns>
        public override int EndRead(IAsyncResult asyncResult)
        {
            this.TestConnectionIsValid();

            return this._SslStream.EndRead(asyncResult);
        }

        /// <summary>
        /// Not supported
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="origin"></param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Sets the length of the current stream.
        /// </summary>
        /// <param name="value"></param>
        public override void SetLength(long value)
        {
            this.InnerStream.SetLength(value);
        }

        /// <summary>
        /// Writes a sequence of bytes to the current stream and advances the current position within this stream by the number of bytes written.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            this.TestConnectionIsValid();

            this.EndWrite(this.BeginWrite(buffer, offset, count, null, null));
        }

        /// <summary>
        /// Begins an asynchronous write operation.
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <param name="asyncCallback"></param>
        /// <param name="asyncState"></param>
        /// <returns></returns>
        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback asyncCallback, Object asyncState)
        {
            this.TestConnectionIsValid();

            return this._SslStream.BeginWrite(buffer, offset, count, asyncCallback, asyncState);
        }

        /// <summary>
        /// Ends an asynchronous write operation.
        /// </summary>
        /// <param name="asyncResult"></param>
        public override void EndWrite(IAsyncResult asyncResult)
        {
            this.TestConnectionIsValid();

            this._SslStream.EndWrite(asyncResult);
        }

        /// <summary>
        /// Closes the current stream and releases any resources 
        /// (such as sockets and file handles) associated with the current stream.		
        /// </summary>
        public override void Close()
        {
            base.Close();

            if (this._SslStream != null)
                this._SslStream.Close();
        }

        #endregion

        #region Properties

        /// <summary>
        /// 
        /// </summary>
        public string AlpnSelectedProtocol { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        public bool CheckCertificateRevocationStatus
        {
            get
            {
                if (!this.IsAuthenticated)
                    return false;

                return this._SslStream.CheckCertificateRevocationStatus;
            }
        }

        /// <summary>
        /// Gets the ssl.
        /// </summary>
        /// <value>The ssl.</value>
        public Ssl Ssl
        {
            get
            {
                if (!this.IsAuthenticated)
                    return null;

                return this._SslStream.Ssl;
            }
        }


        #endregion

        #region Methods

        /// <summary>
        /// 
        /// </summary>
        /// <param name="strTargetHost"></param>
        public virtual void AuthenticateAsClient(string strTargetHost)
        {
            this.AuthenticateAsClient(strTargetHost, null, null, SslProtocols.TLS1_2_VERSION, SslStrength.Default, null, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="targetHost"></param>
        /// <param name="certificates"></param>
        /// <param name="caCertificates"></param>
        /// <param name="enabledSslProtocols"></param>
        /// <param name="sslStrength"></param>
        /// <param name="checkCertificateRevocation"></param>
        public virtual void AuthenticateAsClient(
            string targetHost,
            X509List certificates,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            string strSslCiphers,
            bool checkCertificateRevocation)
        {
            this.EndAuthenticateAsClient(this.BeginAuthenticateAsClient(
                targetHost,
                certificates,
                caCertificates,
                enabledSslProtocols,
                sslStrength,
                strSslCiphers,
                checkCertificateRevocation,
                null,
                null));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="targetHost"></param>
        /// <param name="asyncCallback"></param>
        /// <param name="asyncState"></param>
        /// <returns></returns>
        public virtual IAsyncResult BeginAuthenticateAsClient(
            string targetHost,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            return this.BeginAuthenticateAsClient(
                targetHost,
                null,
                null,
                SslProtocols.TLS1_2_VERSION,
                SslStrength.Default,
                null,
                false,
                asyncCallback,
                asyncState);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="targetHost"></param>
        /// <param name="clientCertificates"></param>
        /// <param name="caCertificates"></param>
        /// <param name="enabledSslProtocols"></param>
        /// <param name="sslStrength"></param>
        /// <param name="checkCertificateRevocation"></param>
        /// <param name="asyncCallback"></param>
        /// <param name="asyncState"></param>
        /// <returns></returns>
        public virtual IAsyncResult BeginAuthenticateAsClient(
            string targetHost,
            X509List clientCertificates,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            string strSslCiphers,
            bool checkCertificateRevocation,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            if (this.IsAuthenticated)
            {
                throw new InvalidOperationException("SslStream is already authenticated");
            }

            this.End = ConnectionEnd.Client;

            // Create the stream & set the internal stream
            this._SslStream = new SslStreamClient(
                                    this.InnerStream,
                                    targetHost,
                                    clientCertificates,
                                    caCertificates,
                                    enabledSslProtocols,
                                    sslStrength,
                                    strSslCiphers,
                                    checkCertificateRevocation,
                                    this._RemoteCertificateValidationCallback,
                                    this._LocalCertificateSelectionCallback);

            //Load CA list
            if (File.Exists(this.CAListFileName))
                this._SslStream.SslContext.LoadVerifyLocations(this.CAListFileName, null);

            // start the write operation
            return this.BeginWrite(new byte[0], 0, 0, asyncCallback, asyncState);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ar"></param>
        public virtual void EndAuthenticateAsClient(IAsyncResult ar)
        {
            this.TestConnectionIsValid();

            // Finish the async authentication.  The EndRead/EndWrite will complete successfully, or throw exception
            this.EndWrite(ar);

            this.AlpnSelectedProtocol = this._SslStream.Ssl.AlpnSelectedProtocol;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="serverCertificate"></param>
        public virtual void AuthenticateAsServer(X509Certificate serverCertificate)
        {
            this.AuthenticateAsServer(null, serverCertificate, false, null, SslProtocols.TLS1_2_VERSION, SslStrength.Default, null, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="targetHost"></param>
        /// <param name="serverCertificate"></param>
        public virtual void AuthenticateAsServer(string targetHost, X509Certificate serverCertificate)
        {
            this.AuthenticateAsServer(targetHost, serverCertificate, false, null, SslProtocols.TLS1_2_VERSION, SslStrength.Default, null, false);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="serverCertificate"></param>
        /// <param name="clientCertificateRequired"></param>
        /// <param name="caCertificates"></param>
        /// <param name="enabledSslProtocols"></param>
        /// <param name="sslStrength"></param>
        /// <param name="checkCertificateRevocation"></param>
        public virtual void AuthenticateAsServer(
            string targetHost,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            X509Chain caCertificates,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            string strSslCiphers,
            bool checkCertificateRevocation)
        {
            this.EndAuthenticateAsServer(this.BeginAuthenticateAsServer(
                targetHost,
                serverCertificate,
                clientCertificateRequired,
                caCertificates,
                enabledSslProtocols,
                sslStrength,
                strSslCiphers,
                checkCertificateRevocation,
                null,
                null));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="serverCertificate"></param>
        /// <param name="asyncCallback"></param>
        /// <param name="asyncState"></param>
        /// <returns></returns>
        public virtual IAsyncResult BeginAuthenticateAsServer(
            string targetHost,
            X509Certificate serverCertificate,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            return this.BeginAuthenticateAsServer(
                targetHost,
                serverCertificate,
                false,
                null,
                SslProtocols.TLS1_2_VERSION,
                SslStrength.Default,
                null,
                false,
                asyncCallback,
                asyncState);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="serverCertificate"></param>
        /// <param name="clientCertificateRequired"></param>
        /// <param name="caCerts"></param>
        /// <param name="enabledSslProtocols"></param>
        /// <param name="sslStrength"></param>
        /// <param name="checkCertificateRevocation"></param>
        /// <param name="asyncCallback"></param>
        /// <param name="asyncState"></param>
        /// <returns></returns>
        public virtual IAsyncResult BeginAuthenticateAsServer(
            string targetHost,
            X509Certificate serverCertificate,
            bool clientCertificateRequired,
            X509Chain caCerts,
            SslProtocols enabledSslProtocols,
            SslStrength sslStrength,
            string strSslCiphers,
            bool checkCertificateRevocation,
            AsyncCallback asyncCallback,
            Object asyncState)
        {
            if (this.IsAuthenticated)
            {
                throw new InvalidOperationException("SslStream is already authenticated");
            }

            this.End = ConnectionEnd.Server;

            // Initialize the server stream & Set the internal sslStream
            this._SslStream = new SslStreamServer(
                                    this.InnerStream,
                                    targetHost,
                                    serverCertificate,
                                    clientCertificateRequired,
                                    caCerts,
                                    enabledSslProtocols,
                                    sslStrength,
                                    strSslCiphers,
                                    checkCertificateRevocation,
                                    this._RemoteCertificateValidationCallback);

            // Start the read operation
            return this.BeginRead(new byte[0], 0, 0, asyncCallback, asyncState);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ar"></param>
        public virtual void EndAuthenticateAsServer(IAsyncResult ar)
        {
            this.TestConnectionIsValid();

            // Finish the async AuthenticateAsServer call - EndRead/Write call will throw exception on error
            this.EndRead(ar);

            this.AlpnSelectedProtocol = this._SslStream.Ssl.AlpnSelectedProtocol;
        }

        /// <summary>
        /// 
        /// </summary>
        public void Renegotiate()
        {
            this.TestConnectionIsValid();

            this.EndRenegotiate(this.BeginRenegotiate(null, null));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="callback"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        public IAsyncResult BeginRenegotiate(AsyncCallback callback, object state)
        {
            this.TestConnectionIsValid();

            this._SslStream.Renegotiate();

            if (this._SslStream is SslStreamClient)
                return this.BeginWrite(new byte[0], 0, 0, callback, state);

            return this.BeginRead(new byte[0], 0, 0, callback, state);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="asyncResult"></param>
        public void EndRenegotiate(IAsyncResult asyncResult)
        {
            this.TestConnectionIsValid();

            if (this._SslStream is SslStreamClient)
                this.EndWrite(asyncResult);
            else
                this.EndRead(asyncResult);
        }

        #endregion

        #region Helpers

        private void TestConnectionIsValid()
        {
            if (this._SslStream == null)
            {
                throw new InvalidOperationException("SslStream has not been authenticated");
            }
        }

        #endregion

        #region Properties

        /// <summary>
        /// 
        /// </summary>
        public ConnectionEnd End { get; private set; }

        #endregion

        #region Fields

        public string CAListFileName = null;

        private SslStreamBase _SslStream;
        internal RemoteCertificateValidationHandler _RemoteCertificateValidationCallback = null;
        internal LocalCertificateSelectionHandler _LocalCertificateSelectionCallback = null;

        #endregion


    }
 }
