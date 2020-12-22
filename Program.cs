using System;

namespace EvCertParser
{
    class Program
    {
        static void Main(string[] args)
        {
            var examiner = new CertificateExaminer();
            var cert = examiner.Request("https://www.ibm.com/").Result;
            Console.WriteLine(cert.Subject);
            Console.WriteLine(cert.Address);
        }
    }
}
