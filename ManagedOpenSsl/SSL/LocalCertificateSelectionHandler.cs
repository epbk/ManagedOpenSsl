using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OpenSSL.X509;

namespace OpenSSL.SSL
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="targetHost"></param>
    /// <param name="localCerts"></param>
    /// <param name="remoteCert"></param>
    /// <param name="acceptableIssuers"></param>
    /// <returns></returns>
    public delegate X509Certificate LocalCertificateSelectionHandler(
        Object sender,
        string targetHost,
        X509List localCerts,
        X509Certificate remoteCert,
        string[] acceptableIssuers
    );
}
