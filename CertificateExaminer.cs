using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace EvCertParser
{
    class CertificateExaminer
    {

        private EvCertificate _certificate;
        public async Task<EvCertificate> Request(string url)
        {
            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = true,
                ServerCertificateCustomValidationCallback = (sender, cert, chain, error) =>
                {
                    var export = cert.Export(X509ContentType.SerializedCert);
                    _certificate = new EvCertificate(export);
                    return error == SslPolicyErrors.None;
                }
            };
            using var client = new HttpClient(handler);
            using var response = await client.GetAsync(url);
            return _certificate;
        }

       
    }
}
