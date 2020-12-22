using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace EvCertParser
{
    class EvCertificate : X509Certificate2
    {
        public string Address
        {
            get
            {
                var addressComponents = new List<string>();
                if (Organization != null) addressComponents.Add(Organization);
                if (Locality != null) addressComponents.Add(Locality);
                if (StateOrProvinceName != null) addressComponents.Add(StateOrProvinceName);
                if (Country != null) addressComponents.Add(Country);
                return string.Join(", ", addressComponents.ToArray());
            }
        }

        // country (countryName, C),
        public string Country { get; set; }
        // organization (organizationName, O),
        public string Organization { get; set; }
        // organizational unit (organizationalUnitName, OU),
        public string OrganizationalUnitName { get; set; }
        // distinguished name qualifier (dnQualifier),
        public string DistinguishedNameQualifier { get; set; }
        // state or province name (stateOrProvinceName, ST),
        public string StateOrProvinceName { get; set; }
        // common name (commonName, CN) and
        public string CommonName { get; set; }
        // serial number (serialNumber).
        public string EvSerialNumber { get; set; }
        // locality (locality, L),
        public string Locality { get; set; }
        // title (title),
        public string Title { get; set; }
        // surname (surName, SN),
        public string Surname { get; set; }
        // given name (givenName, GN),
        public string GivenName { get; set; }
        // initials (initials),
        public string Initials { get; set; }
        // pseudonym (pseudonym) and
        public string Pseudonym { get; set; }
        // generation qualifier (generationQualifier).
        public string GenerationQualifier { get; set; }

        public Dictionary<string, string> ParsedData;

        public EvCertificate(byte[] rawData) : base(rawData)
        {
            ParsedData = ParseSubject(Subject);
            var dMap = new Dictionary<string, Action<EvCertificate, string>>
            {
                {"C", (cert, s) => cert.Country = s},
                {"countryName", (cert, s) => cert.Country = s},
                {"O", (cert, s) => cert.Organization = s},
                {"organizationName", (cert, s) => cert.Organization = s},
                {"OU", (cert, s) => cert.OrganizationalUnitName = s},
                {"organizationalUnitName", (cert, s) => cert.Organization = s},
                {"dnQualifier", (cert, s) => cert.DistinguishedNameQualifier = s},
                {"stateOrProvinceName", (cert, s) => cert.StateOrProvinceName = s},
                {"ST", (cert, s) => cert.StateOrProvinceName = s},
                {"S", (cert, s) => cert.StateOrProvinceName = s},
                {"commonName", (cert, s) => cert.CommonName = s},
                {"CN", (cert, s) => cert.CommonName = s},
                {"serialNumber", (cert, s) => cert.EvSerialNumber = s},
                {"locality", (cert, s) => cert.Locality = s},
                {"L", (cert, s) => cert.Locality = s},
                {"title", (cert, s) => cert.Title = s},
                {"surName", (cert, s) => cert.Surname = s},
                {"SN", (cert, s) => cert.Surname = s},
                {"givenName", (cert, s) => cert.GivenName = s},
                {"GN", (cert, s) => cert.GivenName = s},
                {"initials", (cert, s) => cert.Initials = s},
                {"pseudonym", (cert, s) => cert.Pseudonym = s},
                {"generationQualifier", (cert, s) => cert.GenerationQualifier = s}
            };
            foreach (var kvp in
                dMap.Where(kvp => ParsedData.ContainsKey(kvp.Key)))
            {
                kvp.Value(this, ParsedData[kvp.Key]);
            }
        }


        private static Dictionary<string, string> ParseSubject(string subject)
        {
            // To-do: handle quotes
            // "CN=www.ebay.com, OU=Slot9428 v2, O=\"eBay, Inc.\", L=San Jose, S=California, C=US"
            const string strSubjectRegex = @"(?<Name>[\w.]+)=(?<Value>.+?),";
            var mc = Regex.Matches(subject + ",", strSubjectRegex);
            return mc
                .ToDictionary(
                    n => n.Groups["Name"].Value,
                    v => v.Groups["Value"].Value);

        }

    }
}
