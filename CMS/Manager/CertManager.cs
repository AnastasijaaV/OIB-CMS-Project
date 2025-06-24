using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Manager
{
    public class CertManager
    {
        /// <summary>
		/// Get a certificate with the specified subject name from the predefined certificate storage
		/// Only valid certificates should be considered
		/// </summary>
		/// <param name="storeName"></param>
		/// <param name="storeLocation"></param>
		/// <param name="subjectName"></param>
		/// <returns> The requested certificate. If no valid certificate is found, returns null. </returns>
		/*public static X509Certificate2 GetCertificateFromStorage(StoreName storeName, StoreLocation storeLocation, string subjectName)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, true);

            /// Check whether the subjectName of the certificate is exactly the same as the given "subjectName"
            foreach (X509Certificate2 c in certCollection)
            {
                if (c.SubjectName.Name.Equals(string.Format("CN={0}", subjectName)))
                {
                    return c;
                }
            }

            return null;
        }*/

        public static X509Certificate2 GetCertificateFromStorage(StoreName storeName, StoreLocation storeLocation, string subjectName)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certCollection = store.Certificates
                .Find(X509FindType.FindBySubjectName, subjectName, true);

            string[] revokedLines = File.Exists(@"C:\Certificates\RevocationList.txt")
                ? File.ReadAllLines(@"C:\Certificates\RevocationList.txt")
                : new string[0];

            foreach (X509Certificate2 c in certCollection.Cast<X509Certificate2>().OrderByDescending(x => x.NotBefore))
            {
                if (!revokedLines.Contains(c.SerialNumber, StringComparer.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"[CertManager] ✅ Pronađen VALIDAN sertifikat: {c.Subject} (SN={c.SerialNumber})");
                    return c;
                }
            }

            Console.WriteLine($"[CertManager] ❌ Nijedan validan sertifikat nije pronađen za {subjectName}.");
            return null;
        }

        public static bool IsCertificateRevoked(string commonName)
        {
            string revocationFile = @"C:\Certificates\RevocationList.txt";

            if (!File.Exists(revocationFile))
                return false;

            string[] lines = File.ReadAllLines(revocationFile);
            foreach (var line in lines)
            {
                if (line.Trim().Equals(commonName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
