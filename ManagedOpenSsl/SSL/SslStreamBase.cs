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
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Runtime.CompilerServices;
using OpenSSL.Extensions;

namespace OpenSSL.SSL
{
    internal abstract class SslStreamBase : Stream
    {
        private enum CloseStateEnum { None = 0, Started, Waiting, Closing, Closed }

        private object _PadlockClose = new object();

        private InternalAsyncResult _AsyncResultReadCurrent = null;
        private InternalAsyncResult _AsyncResultWriteCurrent = null;
        private object _PadlockAsyncResultReadCurrent = new object();
        private object _PadlockAsyncResultWriteCurrent = new object();

        protected Stream _InnerStream;
        private volatile bool _Disposed = false;
        private CloseStateEnum _CloseState = CloseStateEnum.None;
        private int _SyncTokenCounter = 0;
        protected SslContext _SslContext;
        protected Ssl _Ssl;
        protected BIO _BIO_read;
        protected BIO _BIO_write;
        // for reading from the stream
        private byte[] _ReadBuffer = new byte[16384];
        private byte[] _EncryptedBuffer = new byte[_SSL3_RT_MAX_PACKET_SIZE];
        private byte[] _DecryptedBuffer = new byte[_SSL3_RT_MAX_PACKET_SIZE];
        // decrypted data from Ssl.Read
        private MemoryStream _AvailableData = new MemoryStream();
        private const int _SSL3_RT_HEADER_LENGTH = 5;
        private const int _SSL3_RT_MAX_PLAIN_LENGTH = 16384;
        private const int _SSL3_RT_MAX_COMPRESSED_LENGTH = (1024 + _SSL3_RT_MAX_PLAIN_LENGTH);
        private const int _SSL3_RT_MAX_ENCRYPTED_LENGTH = (1024 + _SSL3_RT_MAX_COMPRESSED_LENGTH);
        private const int _SSL3_RT_MAX_PACKET_SIZE = (_SSL3_RT_MAX_ENCRYPTED_LENGTH + _SSL3_RT_HEADER_LENGTH);
        private const int _WAIT_TIME_OUT = 300 * 1000; // 5 minutes
        protected LocalCertificateSelectionHandler _OnLocalCertificate;
        protected RemoteCertificateValidationHandler _OnRemoteCertificate;
        protected bool _CheckCertificateRevocationStatus = false;
        protected HandshakeState _HandShakeState = HandshakeState.None;
        protected OpenSslException _HandshakeException = null;

        protected SniCallbackHandler _SniCb;
        protected Sni _SniExt;

        /// <summary>
        /// Override to implement client/server specific handshake processing
        /// </summary>
        /// <returns></returns>
        protected abstract bool ProcessHandshake();

        #region InternalAsyncResult class

        private class InternalAsyncResult : IAsyncResult
        {
            private object _Locker = new object();
            private AsyncCallback _UserCallback;
            private object _UserState;
            private Exception _AsyncException;
            private ManualResetEvent _AsyncWaitHandle;
            private bool _IsCompleted;
            private int _BytesRead;
            private bool _IsWriteOperation;
            private bool _ContinueAfterHandshake;

            private byte[] _Buffer;
            private int _Offset;
            private int _Count;

            public InternalAsyncResult(
                AsyncCallback userCallback,
                object userState,
                byte[] buffer,
                int iOffset,
                int iCount,
                bool bIsWriteOperation,
                bool bContinueAfterHandshake)
            {
                this._UserCallback = userCallback;
                this._UserState = userState;
                this._Buffer = buffer;
                this._Offset = iOffset;
                this._Count = iCount;
                this._IsWriteOperation = bIsWriteOperation;
                this._ContinueAfterHandshake = bContinueAfterHandshake;
            }

            public bool ContinueAfterHandshake
            {
                get { return this._ContinueAfterHandshake; }
            }

            public bool IsWriteOperation
            {
                get { return this._IsWriteOperation; }
                set { this._IsWriteOperation = value; }
            }

            public byte[] Buffer
            {
                get { return this._Buffer; }
            }

            public int Offset
            {
                get { return this._Offset; }
            }

            public int Count
            {
                get { return this._Count; }
            }

            public int BytesRead
            {
                get { return this._BytesRead; }
            }

            public object AsyncState
            {
                get { return this._UserState; }
            }

            public Exception AsyncException
            {
                get { return this._AsyncException; }
            }

            public bool CompletedWithError
            {
                get
                {
                    if (this.IsCompleted == false)
                    {
                        return false;
                    }
                    return (null != this._AsyncException);
                }
            }

            public WaitHandle AsyncWaitHandle
            {
                get
                {
                    lock (this._Locker)
                    {
                        // Create the event if we haven't already done so
                        if (this._AsyncWaitHandle == null)
                        {
                            this._AsyncWaitHandle = new ManualResetEvent(this._IsCompleted);
                        }
                    }
                    return this._AsyncWaitHandle;
                }
            }

            public bool CompletedSynchronously
            {
                get { return false; }
            }

            public bool IsCompleted
            {
                get
                {
                    lock (this._Locker)
                    {
                        return this._IsCompleted;
                    }
                }
            }

            private void SetComplete(Exception ex, int bytesRead)
            {
                lock (this._Locker)
                {
                    if (this._IsCompleted)
                    {
                        return;
                    }

                    this._IsCompleted = true;
                    this._AsyncException = ex;
                    this._BytesRead = bytesRead;
                    // If the wait handle isn't null, we should set the event
                    // rather than fire a callback
                    if (this._AsyncWaitHandle != null)
                    {
                        this._AsyncWaitHandle.Set();
                    }
                }
                // If we have a callback method, invoke it
                if (this._UserCallback != null)
                {
                    this._UserCallback.BeginInvoke(this, null, null);
                }
            }

            public void SetComplete(Exception ex)
            {
                this.SetComplete(ex, 0);
            }

            public void SetComplete(int bytesRead)
            {
                this.SetComplete(null, bytesRead);
            }

            public void SetComplete()
            {
                this.SetComplete(null, 0);
            }
        }

        #endregion

        public SslStreamBase(Stream stream, string strTargetHost)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            if (!stream.CanRead || !stream.CanWrite)
            {
                throw new ArgumentException("Stream must allow read and write capabilities", "stream");
            }

            this._InnerStream = stream;

            //sniExt = new Sni(srvName);
            this._SniExt = new Sni(strTargetHost);

        }

        public bool IsHandshakeComplete
        {
            get { return this._HandShakeState == HandshakeState.Complete; }
        }

        private bool _NeedHandshake
        {
            get { return ((this._HandShakeState == HandshakeState.None) || (this._HandShakeState == HandshakeState.Renegotiate)); }
        }

        public bool CheckCertificateRevocationStatus
        {
            get { return this._CheckCertificateRevocationStatus; }
            set { this._CheckCertificateRevocationStatus = value; }
        }

        public LocalCertificateSelectionHandler LocalCertSelectionCallback
        {
            get { return this._OnLocalCertificate; }
            set { this._OnLocalCertificate = value; }
        }

        public RemoteCertificateValidationHandler RemoteCertValidationCallback
        {
            get { return this._OnRemoteCertificate; }
            set { this._OnRemoteCertificate = value; }
        }

        public SslContext SslContext
        {
            get { return this._SslContext; }
        }

        public Ssl Ssl
        {
            get { return this._Ssl; }
        }

        #region Stream methods

        public override bool CanRead
        {
            get { return this._InnerStream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return this._InnerStream.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return this._InnerStream.CanWrite; }
        }

        public override void Flush()
        {
            try
            {
                if (!this.syncEnter())
                    throw new ObjectDisposedException("SslStreamBase");

                this._InnerStream.Flush();
            }
            finally
            {
                this.syncLeave();
            }
        }

        public override long Length
        {
            get { return this._InnerStream.Length; }
        }

        public override long Position
        {
            get { return this._InnerStream.Position; }
            set { throw new NotSupportedException(); }
        }

        public override int ReadTimeout
        {
            get { return this._InnerStream.ReadTimeout; }
            set { this._InnerStream.ReadTimeout = value; }
        }

        public override int WriteTimeout
        {
            get { return this._InnerStream.WriteTimeout; }
            set { this._InnerStream.WriteTimeout = value; }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            this._InnerStream.SetLength(value);
        }

        //!! - not implementing blocking read, but using BeginRead with no callbacks
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public void SendShutdownAlert()
        {
            try
            {
                if (!this.syncEnter())
                    return;

                int iShutdownRet = this._Ssl.Shutdown();
                if (iShutdownRet == 0)
                {
                    uint wBytesToWrite = this._BIO_write.BytesPending;
                    if (wBytesToWrite <= 0)
                    {
                        // unexpected error
                        //!!TODO log error
                        return;
                    }
                    ArraySegment<byte> buf = this._BIO_write.ReadBytes((int)wBytesToWrite);
                    if (buf.Count <= 0)
                    {
                        //!!TODO - log error
                    }
                    else
                    {
                        // Write the shutdown alert to the stream
                        this._InnerStream.Write(buf.Array, 0, buf.Count);
                    }
                }
            }
            finally
            {
                this.syncLeave();
            }
        }

        public override IAsyncResult BeginRead(
            byte[] buffer,
            int offset,
            int count,
            AsyncCallback asyncCallback,
            object asyncState)
        {
            if (buffer == null)
                throw new ArgumentNullException("buffer", "buffer can't be null");

            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset", "offset less than 0");

            if (offset > buffer.Length)
                throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");

            if (count < 0)
                throw new ArgumentOutOfRangeException("count", "count less than 0");

            if (count > (buffer.Length - offset))
                throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");

            bool bProceedAfterHandshake = count != 0;

            InternalAsyncResult internalAsyncResult = new InternalAsyncResult(
                asyncCallback,
                asyncState,
                buffer,
                offset,
                count,
                false,
                bProceedAfterHandshake);

            if (this._NeedHandshake)
                this.beginHandshake(internalAsyncResult);
            else
                this.internalBeginRead(internalAsyncResult);

            return internalAsyncResult;
        }

        private void internalBeginRead(InternalAsyncResult asyncResult)
        {
            try
            {
                if (!this.syncEnter())
                {
                    asyncResult.SetComplete(0);
                    return;
                }

                //Simultaneous read check
                Monitor.Enter(this._PadlockAsyncResultReadCurrent);
                if (this._AsyncResultReadCurrent != null && this._AsyncResultReadCurrent != asyncResult && !this._AsyncResultReadCurrent.IsCompleted)
                {
                    Monitor.Exit(this._PadlockAsyncResultReadCurrent);
                    asyncResult.SetComplete(new Exception("BeginRead: Simultaneous read"));
                    return;
                }
                else
                {
                    this._AsyncResultReadCurrent = asyncResult;
                    Monitor.Exit(this._PadlockAsyncResultReadCurrent);
                }

                // Check to see if the decrypted data stream should be reset
                if (this._AvailableData.Position == this._AvailableData.Length)
                {
                    if (this._AvailableData.Position > 0)
                    {
                        this._AvailableData.Seek(0, SeekOrigin.Begin);
                        this._AvailableData.SetLength(0);
                    }
                }
                // Check to see if we have data waiting in the decrypted data stream
                else if (this._AvailableData.Length > 0)
                {
                    // Process the pre-existing data
                    int iBytesRead = this._AvailableData.Read(asyncResult.Buffer, asyncResult.Offset, asyncResult.Count);
                    asyncResult.SetComplete(iBytesRead);
                    return;
                }

                // Start the async read from the inner stream
                this._InnerStream.BeginRead(this._ReadBuffer, 0, this._ReadBuffer.Length, this.internalReadCallback, asyncResult);
            }
            finally
            {
                this.syncLeave();
            }
        }

        private void internalReadCallback(IAsyncResult asyncResult)
        {
            InternalAsyncResult internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

            try
            {
                if (!this.syncEnter())
                {
                    //we need complete async result otherwise async read call will possibly remain in blocked state
                    internalAsyncResult.SetComplete(0);
                    return;
                }

                bool bHaveDataToReturn = false;

                try
                {
                    int iBytesRead = 0;
                    try
                    {
                        iBytesRead = this._InnerStream.EndRead(asyncResult);
                    }
                    catch (Exception ex)
                    {
                        // Set the exception into the internal async result
                        internalAsyncResult.SetComplete(ex);
                        return;
                    }

                    if (iBytesRead <= 0)
                    {
                        // Zero byte read most likely indicates connection closed (if it's a network stream)
                        internalAsyncResult.SetComplete(new IOException("Connection was closed by the remote endpoint"));
                        return;
                    }
                    else
                    {
                        // Copy encrypted data into the SSL read_bio
                        this._BIO_read.Write(this._ReadBuffer, iBytesRead);

                        if (this._HandShakeState == HandshakeState.InProcess ||
                            this._HandShakeState == HandshakeState.RenegotiateInProcess)
                        {
                            // We are in the handshake, complete the async operation to fire the async
                            // handshake callback for processing
                            internalAsyncResult.SetComplete(iBytesRead);
                            return;
                        }

                        uint wBytesPending = this._BIO_read.BytesPending;

                        while (wBytesPending > 0)
                        {
                            int iDecryptedBytesRead = this._Ssl.Read(this._DecryptedBuffer, this._DecryptedBuffer.Length);
                            if (iDecryptedBytesRead <= 0)
                            {
                                SslError lastError = this._Ssl.GetError(iDecryptedBytesRead);
                                if (lastError == SslError.SSL_ERROR_WANT_READ)
                                {
                                    // if we have bytes pending in the write bio.
                                    // the client has requested a renegotiation
                                    if (this._BIO_write.BytesPending > 0)
                                    {
                                        // Start the renegotiation by writing the write_bio data, and use the RenegotiationWriteCallback
                                        // to handle the rest of the renegotiation
                                        ArraySegment<byte> buf = this._BIO_write.ReadBytes((int)this._BIO_write.BytesPending);
                                        this._InnerStream.BeginWrite(buf.Array, 0, buf.Count, this.renegotiationWriteCallback, internalAsyncResult);
                                        return;
                                    }
                                    // no data in the out bio, we just need more data to complete the record
                                    //break;
                                }
                                else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
                                {
                                    // unexpected error!
                                    //!!TODO debug log
                                }
                                else if (lastError == SslError.SSL_ERROR_ZERO_RETURN)
                                {
                                    // Shutdown alert
                                    this.SendShutdownAlert();
                                    break;
                                }
                                else
                                {
                                    //throw new OpenSslException();
                                }
                            }

                            if (iDecryptedBytesRead > 0)
                            {
                                // Write decrypted data to memory stream
                                long lPos = this._AvailableData.Position;
                                this._AvailableData.Seek(0, SeekOrigin.End);
                                this._AvailableData.Write(this._DecryptedBuffer, 0, iDecryptedBytesRead);
                                this._AvailableData.Seek(lPos, SeekOrigin.Begin);
                                bHaveDataToReturn = true;
                            }

                            // See if we have more data to process
                            wBytesPending = this._BIO_read.BytesPending;
                        }

                        // Check to see if we have data to return, if not, fire the async read again
                        if (!bHaveDataToReturn)
                            this._InnerStream.BeginRead(this._ReadBuffer, 0, this._ReadBuffer.Length, this.internalReadCallback, internalAsyncResult);
                        else
                        {
                            int iBytesReadIntoUserBuffer = 0;

                            // Read the data into the buffer provided by the user (now hosted in the InternalAsyncResult)
                            iBytesReadIntoUserBuffer = this._AvailableData.Read(internalAsyncResult.Buffer, internalAsyncResult.Offset, internalAsyncResult.Count);

                            internalAsyncResult.SetComplete(iBytesReadIntoUserBuffer);
                        }
                    }
                }
                catch (Exception ex)
                {
                    internalAsyncResult.SetComplete(ex);
                }
            }
            finally
            {
                this.syncLeave();
            }
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            try
            {
                if (!this.syncEnter())
                    return 0;

                InternalAsyncResult internalAsyncResult = asyncResult as InternalAsyncResult;

                if (internalAsyncResult == null)
                    throw new ArgumentException("AsyncResult was not obtained via BeginRead", "asyncResult");

                // Check to see if the operation is complete, if not -- let's wait for it
                if (!internalAsyncResult.IsCompleted && !internalAsyncResult.AsyncWaitHandle.WaitOne(_WAIT_TIME_OUT, false))
                    throw new IOException("Failed to complete read operation");

                // If we completed with an error, throw the exceptions
                if (internalAsyncResult.CompletedWithError)
                    throw new Exception("AsyncException: " + internalAsyncResult.AsyncException, internalAsyncResult.AsyncException);

                // Success, return the bytes read
                return internalAsyncResult.BytesRead;
            }
            finally
            {
                this.syncLeave();
            }
        }

        //!! - not implmenting blocking Write, use BeginWrite with no callback
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override IAsyncResult BeginWrite(
            byte[] buffer,
            int offset,
            int count,
            AsyncCallback asyncCallback,
            object asyncState)
        {
            try
            {
                if (!this.syncEnter())
                    return null;

                if (buffer == null)
                    throw new ArgumentNullException("buffer", "buffer can't be null");

                if (offset < 0)
                    throw new ArgumentOutOfRangeException("offset", "offset less than 0");

                if (offset > buffer.Length)
                    throw new ArgumentOutOfRangeException("offset", "offset must be less than buffer length");

                if (count < 0)
                    throw new ArgumentOutOfRangeException("count", "count less than 0");

                if (count > (buffer.Length - offset))
                    throw new ArgumentOutOfRangeException("count", "count is greater than buffer length - offset");

                bool bProceedAfterHandshake = count != 0;

                InternalAsyncResult asyncResult = new InternalAsyncResult(asyncCallback, asyncState, buffer, offset, count, true, bProceedAfterHandshake);

                if (this._NeedHandshake)
                    this.beginHandshake(asyncResult); // Start the handshake
                else
                    this.internalBeginWrite(asyncResult);

                return asyncResult;
            }
            finally
            {
                this.syncLeave();
            }
        }

        private void internalBeginWrite(InternalAsyncResult asyncResult)
        {
            try
            {
                if (!this.syncEnter())
                {
                    asyncResult.SetComplete();
                    return;
                }

                //Simultaneous write check
                lock (this._PadlockAsyncResultWriteCurrent)
                {
                    if (this._AsyncResultWriteCurrent != null && this._AsyncResultWriteCurrent != asyncResult && !this._AsyncResultWriteCurrent.IsCompleted)
                        throw new Exception("BeginWrite: Simultaneous write");
                    else
                        this._AsyncResultWriteCurrent = asyncResult;
                }

                // Only write to the SSL object if we have data
                if (asyncResult.Count != 0)
                {
                    byte[] bufferSource;

                    if (asyncResult.Offset != 0)
                    {
                        //Buffer aligning
                        bufferSource = new byte[asyncResult.Count];
                        Array.Copy(asyncResult.Buffer, asyncResult.Offset, bufferSource, 0, asyncResult.Count);
                    }
                    else
                        bufferSource = asyncResult.Buffer;

                    int iBytesWritten = this._Ssl.Write(bufferSource, asyncResult.Count);
                    if (iBytesWritten < 0)
                    {
                        SslError lastError = this._Ssl.GetError(iBytesWritten);
                        if (lastError == SslError.SSL_ERROR_WANT_READ)
                        {
                            //!!TODO - Log - unexpected renogiation request
                        }

                        throw new OpenSslException();
                    }
                }

                uint wBytesPending = this._BIO_write.BytesPending;
                if (wBytesPending > 0)
                {
                    if (wBytesPending > this._EncryptedBuffer.Length)
                        this._EncryptedBuffer = new byte[(wBytesPending & ~1023) << 1];

                    int iToWr = this._BIO_write.ReadBytes(this._EncryptedBuffer);
                    if (iToWr > 0)
                    {
                        this._InnerStream.BeginWrite(this._EncryptedBuffer, 0, iToWr, this.internalWriteCallback, asyncResult);
                        return;
                    }
                }

                //No data to write to inner stream; complete the async result
                asyncResult.SetComplete();
            }
            finally
            {
                this.syncLeave();
            }
        }

        private void internalWriteCallback(IAsyncResult asyncResult)
        {
            InternalAsyncResult internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

            try
            {
                this._InnerStream.EndWrite(asyncResult);
                internalAsyncResult.SetComplete();
            }
            catch (Exception ex)
            {
                internalAsyncResult.SetComplete(ex);
            }
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            try
            {
                if (!this.syncEnter())
                    return;

                InternalAsyncResult internalAsyncResult = asyncResult as InternalAsyncResult;

                if (internalAsyncResult == null)
                    throw new ArgumentException("AsyncResult object was not obtained from SslStream.BeginWrite", "asyncResult");

                if (!internalAsyncResult.IsCompleted && !internalAsyncResult.AsyncWaitHandle.WaitOne(_WAIT_TIME_OUT, false))
                    throw new IOException("Failed to complete the Write operation");

                if (internalAsyncResult.CompletedWithError)
                    throw new Exception("AsyncException: " + internalAsyncResult.AsyncException, internalAsyncResult.AsyncException);

            }
            finally
            {
                this.syncLeave();
            }
        }

        private void renegotiationWriteCallback(IAsyncResult asyncResult)
        {
            InternalAsyncResult readwriteAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

            this._InnerStream.EndWrite(asyncResult);

            // Now start the read with the original asyncresult, as the ssl.Read will handle the renegoiation
            this.internalBeginRead(readwriteAsyncResult);
        }

        private IAsyncResult beginHandshake(InternalAsyncResult readwriteAsyncResult)
        {
            try
            {
                if (!this.syncEnter())
                    return null;

                //!!
                // Move the handshake state to the next state
                //if (handShakeState == HandshakeState.Renegotiate)
                //{
                //    handShakeState = HandshakeState.RenegotiateInProcess;
                //}
                //else
                if (this._HandShakeState != HandshakeState.Renegotiate)
                    this._HandShakeState = HandshakeState.InProcess;

                // Wrap the read/write InternalAsyncResult in the Handshake InternalAsyncResult instance
                InternalAsyncResult handshakeAsyncResult = new InternalAsyncResult(
                                               this.asyncHandshakeComplete,
                                               readwriteAsyncResult,
                                               null,
                                               0,
                                               0,
                                               readwriteAsyncResult.IsWriteOperation,
                                               readwriteAsyncResult.ContinueAfterHandshake);

                if (this.ProcessHandshake())
                {
                    this._HandShakeState = HandshakeState.Complete;
                    handshakeAsyncResult.SetComplete();
                }
                else
                {
                    //!! if (readwriteAsyncResult.IsWriteOperation)
                    if (this._BIO_write.BytesPending > 0)
                    {
                        handshakeAsyncResult.IsWriteOperation = true;
                        this.BeginWrite(new byte[0], 0, 0, this.asyncHandshakeCallback, handshakeAsyncResult);
                    }
                    else
                    {
                        handshakeAsyncResult.IsWriteOperation = false;
                        this.BeginRead(new byte[0], 0, 0, this.asyncHandshakeCallback, handshakeAsyncResult);
                    }
                }

                return handshakeAsyncResult;
            }
            finally
            {
                this.syncLeave();
            }
        }

        private void asyncHandshakeCallback(IAsyncResult asyncResult)
        {
            // Get the handshake internal result instance
            InternalAsyncResult internalAsyncResult = (InternalAsyncResult)asyncResult.AsyncState;

            try
            {
                if (!this.syncEnter())
                {
                    internalAsyncResult.SetComplete();
                    return;
                }

                int iBytesRead = 0;

                if (internalAsyncResult.IsWriteOperation)
                {
                    this.EndWrite(asyncResult);
                    // Check to see if the handshake is complete (this could have been
                    // the last response packet from the server.  If so, we want to finalize
                    // the async operation and call the HandshakeComplete callback
                    if (this._HandShakeState == HandshakeState.Complete)
                    {
                        internalAsyncResult.SetComplete();
                        return;
                    }
                    // Check to see if we saved an exception from the last Handshake process call
                    // the if the client gets an error code, it needs to send the alert, and then
                    // throw the exception here.
                    if (this._HandshakeException != null)
                    {
                        internalAsyncResult.SetComplete(this._HandshakeException);
                        return;
                    }
                    // We wrote out the handshake data, now read to get the response
                    internalAsyncResult.IsWriteOperation = false;
                    this.BeginRead(new byte[0], 0, 0, this.asyncHandshakeCallback, internalAsyncResult);
                }
                else
                {
                    try
                    {
                        iBytesRead = this.EndRead(asyncResult);
                        if (iBytesRead > 0)
                        {
                            if (this.ProcessHandshake())
                            {
                                this._HandShakeState = HandshakeState.Complete;
                                // We have completed the handshake, but need to send the
                                // last response packet.
                                if (this._BIO_write.BytesPending > 0)
                                {
                                    internalAsyncResult.IsWriteOperation = true;
                                    this.BeginWrite(new byte[0], 0, 0, this.asyncHandshakeCallback, internalAsyncResult);
                                }
                                else
                                {
                                    internalAsyncResult.SetComplete();
                                    return;
                                }
                            }
                            else
                            {
                                // Not complete with the handshake yet, write the handshake packet out
                                internalAsyncResult.IsWriteOperation = true;
                                this.BeginWrite(new byte[0], 0, 0, this.asyncHandshakeCallback, internalAsyncResult);
                            }
                        }
                        else
                        {
                            // Read read 0 bytes, the remote socket has been closed, so complete the operation
                            internalAsyncResult.SetComplete(new IOException("The remote stream has been closed"));
                        }
                    }
                    catch (Exception ex)
                    {
                        internalAsyncResult.SetComplete(ex);
                    }
                }
            }
            finally
            {
                this.syncLeave();
            }
        }

        private void asyncHandshakeComplete(IAsyncResult asyncResult)
        {
            this.endHandshake(asyncResult);
        }

        private void endHandshake(IAsyncResult asyncResult)
        {
            try
            {
                if (!this.syncEnter())
                    return;

                InternalAsyncResult handshakeAsyncResult = asyncResult as InternalAsyncResult;
                InternalAsyncResult readwriteAsyncResult = asyncResult.AsyncState as InternalAsyncResult;

                if (!handshakeAsyncResult.IsCompleted)
                    handshakeAsyncResult.AsyncWaitHandle.WaitOne(_WAIT_TIME_OUT, false);

                if (handshakeAsyncResult.CompletedWithError)
                {
                    // if there's a handshake error, pass it to the read asyncresult instance
                    readwriteAsyncResult.SetComplete(handshakeAsyncResult.AsyncException);
                    return;
                }

                if (readwriteAsyncResult.ContinueAfterHandshake)
                {
                    // We should continue the read/write operation since the handshake is complete
                    if (readwriteAsyncResult.IsWriteOperation)
                        this.internalBeginWrite(readwriteAsyncResult);
                    else
                        this.internalBeginRead(readwriteAsyncResult);
                }
                else
                {
                    // If we aren't continuing, we're done
                    readwriteAsyncResult.SetComplete();
                }
            }
            finally
            {
                this.syncLeave();
            }
        }

        public override void Close()
        {
            lock (this._PadlockClose)
            {
                if (this._CloseState != CloseStateEnum.None)
                    return; //already closing; exit

                this._CloseState = CloseStateEnum.Started;
            }

            //Close the inner stream first
            this._InnerStream.Close();

            lock (this._PadlockClose)
            {
                if (this._SyncTokenCounter != 0)
                {
                    this._CloseState = CloseStateEnum.Waiting;
                    Monitor.Wait(this._PadlockClose); //Some method is now executing the code; we need to wait
                }

                this._CloseState = CloseStateEnum.Closing;
            }

            //if (Interlocked.CompareExchange(ref this._Closing, 1, 0) != 0)
            //    return; //already closing; exit

            ////Close the inner stream first
            //this._InnerStream.Close();

            ////Check whether we can proceed with this closing process
            //while (Interlocked.CompareExchange(ref this._SyncTokenCounter, 0, 0) != 0)
            //{
            //    //Some method is now executing the code; we need try again later
            //    Thread.Sleep(20);
            //}

            //None method is in executing process; we can close everything now

            if (this._Ssl != null)
            {
                this._BIO_read = null;
                this._BIO_write = null;

                this._Ssl.Dispose(); //will also free BIO !!!
                this._Ssl = null;
            }

            if (this._SslContext != null)
            {
                this._SslContext.Dispose();
                this._SslContext = null;
            }

            base.Close();
            this.Dispose();

            this._CloseState = CloseStateEnum.Closed;
        }

        #endregion

        /// <summary>
        /// Renegotiate session keys - calls SSL_renegotiate
        /// </summary>
        public void Renegotiate()
        {
            try
            {
                if (this.syncEnter() && this._Ssl != null)
                {
                    // Call the SSL_renegotiate to reset the SSL object state
                    // to start handshake
                    Native.ExpectSuccess(Native.SSL_renegotiate(this._Ssl.Handle));
                    this._HandShakeState = HandshakeState.Renegotiate;
                }
            }
            finally
            {
                this.syncLeave();
            }
        }



        /// <summary>
        /// Enter safe area. Calling this method must be allways followed by calling syncLeave method.
        /// </summary>
        /// <returns>True if continuation condition is satisfied</returns>
        private bool syncEnter()
        {
            lock (this._PadlockClose)
            {
                this._SyncTokenCounter++;
                return this._CloseState == CloseStateEnum.None;
            }

            //Increment token counter first
            //Interlocked.Increment(ref this._SyncTokenCounter);

            //return Interlocked.CompareExchange(ref this._Closing, 0, 0) == 0;
        }

        /// <summary>
        /// Leave safe area. Calling this method must by allways preceeded by calling syncEnter method.
        /// </summary>
        private void syncLeave()
        {
            lock (this._PadlockClose)
            {
                if (--this._SyncTokenCounter == 0 && this._CloseState == CloseStateEnum.Waiting)
                    Monitor.Pulse(this._PadlockClose);
            }

            //Interlocked.Decrement(ref this._SyncTokenCounter);
        }


        #region IDisposable Members

        protected override void Dispose(bool disposing)
        {
            if (this._Disposed)
                return;

            this._Disposed = true;
            base.Dispose();
        }

        #endregion
    }
}
