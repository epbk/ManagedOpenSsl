using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OpenSSL.X509;
using OpenSSL.Crypto;

namespace OpenSSL.SSL
{
    internal delegate int ClientCertCallbackHandler(Ssl ssl, out X509Certificate cert, out CryptoKey key);
}
