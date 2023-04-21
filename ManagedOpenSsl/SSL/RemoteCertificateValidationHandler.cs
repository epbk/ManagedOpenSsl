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
    /// <param name="cert"></param>
    /// <param name="chain"></param>
    /// <param name="depth"></param>
    /// <param name="result"></param>
    /// <returns></returns>
    public delegate bool RemoteCertificateValidationHandler(
        Object sender,
        X509Certificate cert,
        X509Chain chain,
        int depth,
        VerifyResult result
    );
}
