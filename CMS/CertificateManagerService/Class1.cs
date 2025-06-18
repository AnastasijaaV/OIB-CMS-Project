using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Diagnostics;
using System.Security.Principal;
using Contracts;

namespace CertificateManager
{
    public class CertificateManagerService : ICertificateManagerService
    {
        private static readonly string CertificateFolder = "C:\\Certificates";
        private static readonly string RevocationListPath = Path.Combine(CertificateFolder, "RevocationList.txt");

        public CertificateManagerService()
        {
            if (!Directory.Exists(CertificateFolder))
                Directory.CreateDirectory(CertificateFolder);

            if (!File.Exists(RevocationListPath))
                File.Create(RevocationListPath).Dispose();
        }

        public void CreateCertificate(string subjectName, bool includePrivateKey)
        {
            try
            {
                string certPath = Path.Combine(CertificateFolder, $"{subjectName}.pfx");

                using (var rsa = RSA.Create(2048))
                {
                    var request = new CertificateRequest(
                        new X500DistinguishedName($"CN={subjectName}"),
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    var certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

                    byte[] certData = includePrivateKey
                        ? certificate.Export(X509ContentType.Pfx, "password")
                        : certificate.Export(X509ContentType.Cert);

                    File.WriteAllBytes(certPath, certData);
                }

                LogEvent($"Certificate created for {subjectName}. Path: {certPath}", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                LogEvent($"Error creating certificate: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        public void RevokeCertificate(string serialNumber)
        {
            //2
            Console.WriteLine($"[RevokeCertificate] Poziv sa serialNumber: {serialNumber}");
            //--

            try
            {
                File.AppendAllText(RevocationListPath, serialNumber + Environment.NewLine);
                NotifyClientsOfRevocation(serialNumber);
                CreateCertificate("NewCertFor_" + serialNumber, true);

                LogEvent($"Certificate revoked and renewed. Serial Number: {serialNumber}", EventLogEntryType.Warning);
            }
            catch (Exception ex)
            {
                LogEvent($"Error revoking certificate: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        public void ReplicateData()
        {
            try
            {
                string backupPath = Path.Combine(CertificateFolder, "Backup");
                if (!Directory.Exists(backupPath))
                    Directory.CreateDirectory(backupPath);

                foreach (var file in Directory.GetFiles(CertificateFolder))
                {
                    File.Copy(file, Path.Combine(backupPath, Path.GetFileName(file)), overwrite: true);
                }

                LogEvent("Data replicated to backup successfully.", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                LogEvent($"Error replicating data: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        public void NotifyClientsOfRevocation(string serialNumber)
        {
            Console.WriteLine($"Clients notified of certificate revocation: {serialNumber}");
        }

        public bool RequestCertificate(string windowsUsername)
        {
            try
            {
                Console.WriteLine($">> RequestCertificate called for {windowsUsername}");

                // ✅ koristi aktivno prijavljenog korisnika
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);

                string[] allowedGroups = { "RegionEast", "RegionWest", "RegionNorth", "RegionSouth" };
                string userGroup = null;

                foreach (string group in allowedGroups)
                {
                    if (principal.IsInRole(group))
                    {
                        userGroup = group;
                        break;
                    }
                }

                if (userGroup == null)
                {
                    Console.WriteLine("❌ Korisnik NIJE u dozvoljenoj grupi.");
                    LogEvent($"Korisnik {identity.Name} NIJE u dozvoljenoj grupi.", EventLogEntryType.Warning);
                    return false;
                }

                string subject = $"CN={identity.Name}, OU={userGroup}";
                string sanitizedUser = identity.Name.Replace("\\", "_");
                string certPath = Path.Combine(CertificateFolder, $"{sanitizedUser}.pfx");

                Console.WriteLine($">> Kreiram sertifikat na putanji: {certPath}");

                using (var rsa = RSA.Create(2048))
                {
                    var request = new CertificateRequest(
                        new X500DistinguishedName(subject),
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                    var certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
                    byte[] certData = certificate.Export(X509ContentType.Pfx, "password");
                    File.WriteAllBytes(certPath, certData);

                    X509Certificate2 newCert = new X509Certificate2(certPath, "password", X509KeyStorageFlags.PersistKeySet);

                    using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        store.Add(newCert);

                        store.Close();
                    }
                    Console.WriteLine("✔ Sertifikat dodat u CurrentUser//My store.");

                    using (X509Store trusted = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine))
                    {
                        trusted.Open(OpenFlags.ReadWrite);
                        trusted.Add(newCert);
                        trusted.Close();
                    }

                    Console.WriteLine("✔ Sertifikat dodat u CurrentUser/My i TrustedPeople store.");
                }

                Console.WriteLine($"✔ Sertifikat izdat za {identity.Name} sa OU={userGroup}");
                LogEvent($"✔ Sertifikat izdat za {identity.Name} sa OU={userGroup}.", EventLogEntryType.Information);


                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ GRESKA: " + ex.Message);
                LogEvent($"❌ Greška prilikom izdavanja sertifikata: {ex.Message}", EventLogEntryType.Error);
                return false;
            }
        }
        private void LogEvent(string message, EventLogEntryType entryType)
        {
            string source = "CertificateManagerService";
            string log = "Application";

            if (!EventLog.SourceExists(source))
                EventLog.CreateEventSource(source, log);

            EventLog.WriteEntry(source, message, entryType);
        }
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            string address = "net.tcp://localhost:8888/CertificateManagerService";
            ServiceHost host = new ServiceHost(typeof(CertificateManagerService));

            NetTcpBinding binding = new NetTcpBinding(SecurityMode.None); // ⬅️ bitno

            host.AddServiceEndpoint(typeof(ICertificateManagerService), binding, address);

            try
            {
                host.Open();
                Console.WriteLine("CertificateManagerService is running. Press <Enter> to stop.");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                host.Close();
            }
        }
    }
}