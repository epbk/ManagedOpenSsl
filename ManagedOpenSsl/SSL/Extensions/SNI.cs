using System;
using System.Runtime.InteropServices;
using OpenSSL.Core;
using OpenSSL.SSL;

namespace OpenSSL.Extensions
{
	internal class Sni
	{
		internal const int TLSEXT_NAMETYPE_host_name = 0;
		internal const int SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = 53;
		internal const int SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54;
		internal const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
		internal const int SSL_CTRL_GET_SESSION_REUSED = 8;

		private readonly string _ServerName;
		private IntPtr _ServerNamePtr;

		public Sni(string strServerName)
		{
			this._ServerName = strServerName;
			this._ServerNamePtr = Marshal.StringToHGlobalAnsi(strServerName);
		}

        public string ServerName { get { return this._ServerName; } }


		public void AttachSniExtensionClient(IntPtr ssl, IntPtr sslCtx, SniCallbackHandler cb)
		{
			ssl_CTX_set_tlsext_servername_callback(cb, sslCtx);

            Native.SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, this._ServerNamePtr);
			ssl_set_tlsext_host_name(ssl);
		}

		public void AttachSniExtensionServer(IntPtr ssl, IntPtr sslCtx, SniCallbackHandler cb)
		{
			ssl_CTX_set_tlsext_servername_callback(cb, sslCtx);
			//SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, serverNamePtr);
		}

		private static long ssl_session_reused(IntPtr ssl)
		{
			return Native.SSL_ctrl(ssl, SSL_CTRL_GET_SESSION_REUSED, 0, IntPtr.Zero);
		}

		private int ssl_set_tlsext_host_name(IntPtr s)
		{
			return Native.SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME,
				TLSEXT_NAMETYPE_host_name,
                this._ServerNamePtr);
		}

		private int ssl_CTX_set_tlsext_servername_callback(SniCallbackHandler cb, IntPtr ctx)
		{
			IntPtr cbPtr = Marshal.GetFunctionPointerForDelegate(cb);
			return Native.SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cbPtr);
		}

		//This callback just checks was session reused or not.
		//If we renegotiate each time we make a connection then clientSniArgAck
		//should be true
		public int ClientSniCb(IntPtr ssl, IntPtr ad, IntPtr arg)
		{
			IntPtr hnPtr = Native.SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

			if (Native.SSL_get_servername_type(ssl) != -1)
			{
				bool bIsReused = ssl_session_reused(ssl) != 0;
				bool bClientSniArgAck = !bIsReused && hnPtr != IntPtr.Zero;
#if DEBUG
                Console.WriteLine("Servername ack is {0}", bClientSniArgAck);
#endif
			}
			else
			{
#if DEBUG
				Console.WriteLine("Can't use SSL_get_servername");
#endif
				throw new Exception("Cant use servername extension");
			}

			return (int)Errors.SSL_TLSEXT_ERR_OK;
		}

		public int ServerSniCb(IntPtr ssl, IntPtr ad, IntPtr arg)
		{
			//Hostname in TLS extension
			IntPtr extServerNamePtr = Native.SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
			string strExtServerName = Marshal.PtrToStringAnsi(extServerNamePtr);

            if (!string.IsNullOrWhiteSpace(this._ServerName) && !this._ServerName.Equals(strExtServerName))
			{
#if DEBUG
				Console.WriteLine("Server names are not equal");
#endif
				throw new Exception("Server names are not equal");    
			}

			return (int)Errors.SSL_TLSEXT_ERR_OK;
		}

		~Sni()
		{
            Marshal.FreeHGlobal(this._ServerNamePtr);
		}
	}
}
