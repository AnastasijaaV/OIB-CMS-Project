using Contracts;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Description;

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
                string safeFileName = subjectName.Replace("\\", "").Replace(" / ", "");
                string certPath = Path.Combine(CertificateFolder, $"{safeFileName}.pfx");

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

                ReplicateData();
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
            Console.WriteLine($"[RevokeCertificate] Poziv sa serialNumber: {serialNumber}");

            try
            {
                string commonName = GetCommonNameBySerialNumber(serialNumber);

                if (string.IsNullOrWhiteSpace(commonName))
                {
                    string msg = $"Nije pronađen CN za serialNumber: {serialNumber}. Preskačem kreiranje novog sertifikata.";
                    Console.WriteLine(msg);
                    LogEvent(msg, EventLogEntryType.Warning);
                    return; // Ovde prekidamo sve daljnje korake
                }

                // Upis u listu povučenih
                File.AppendAllText(RevocationListPath, serialNumber + Environment.NewLine);

                // Obaveštavanje klijenata
                NotifyClientsOfRevocation(serialNumber);

                // Kreiraj novi sertifikat
                CreateCertificate(commonName, true);

                // Replikacija i logovanje
                ReplicateData();
                LogEvent($"Certificate revoked and renewed. Serial Number: {serialNumber}", EventLogEntryType.Warning);
            }
            catch (Exception ex)
            {
                LogEvent($"Error revoking certificate: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        private string GetCommonNameBySerialNumber(string serialNumber)
        {
            string certFolder = @"C:\Certificates";

            foreach (var file in Directory.GetFiles(certFolder, "*.pfx"))
            {
                var cert = new X509Certificate2(file, "password", X509KeyStorageFlags.PersistKeySet);
                Console.WriteLine($"🔍 Proveravam fajl: {file}, SN={cert.SerialNumber}");

                if (cert.SerialNumber.Equals(serialNumber, StringComparison.OrdinalIgnoreCase))
                {
                    string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                    Console.WriteLine($"✅ Pronađen CN: {cn}");
                    return cn;
                }
            }

            Console.WriteLine($"Nije pronađen nijedan sertifikat sa SN={serialNumber}");
            return null;
        }

        public void ReplicateData()
        {
            try
            {
                NetTcpBinding binding = new NetTcpBinding(SecurityMode.Transport);
                binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;

                string backupAddress = "net.tcp://localhost:9000/BackupService";

                ChannelFactory<IBackupContract> factory = new ChannelFactory<IBackupContract>(
                    binding,
                    new EndpointAddress(backupAddress));

                // Dozvoli impersonaciju za Windows autentifikaciju
                factory.Credentials.Windows.AllowedImpersonationLevel = TokenImpersonationLevel.Impersonation;

                IBackupContract proxy = factory.CreateChannel();

                foreach (var file in Directory.GetFiles(CertificateFolder))
                {
                    string fileName = Path.GetFileName(file);
                    if (fileName == "RevocationList.txt" || fileName.EndsWith(".pfx"))
                    {
                        byte[] content = File.ReadAllBytes(file);
                        proxy.ReceiveBackup(fileName, content);
                        Console.WriteLine($"Poslat fajl za backup: {fileName}");
                    }
                }

                LogEvent("Podaci uspešno replicirani na BackupService.", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greška pri replikaciji: {ex.Message}");
                LogEvent($"Greška pri repliciranju: {ex.Message}", EventLogEntryType.Error);
            }
        }

        public void NotifyClientsOfRevocation(string serialNumber)
        {
            try
            {
                string msg = $"Obaveštenje o revokaciji poslato (simulacija) za sertifikat sa SN={serialNumber}.";
                Console.WriteLine($" {msg}");

                string notifPath = Path.Combine(CertificateFolder, "RevocationNotifications.txt");
                File.AppendAllText(notifPath, $"{DateTime.Now:dd.MM.yyyy. HH:mm:ss} - {msg}{Environment.NewLine}");

                LogEvent(msg, EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                LogEvent($"Greška prilikom slanja obaveštenja: {ex.Message}", EventLogEntryType.Error);
            }
        }

        public bool RequestCertificate(string windowsUsername)
        {
            try
            {
                Console.WriteLine($">> RequestCertificate called for {windowsUsername}");

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
                    Console.WriteLine("Sertifikat dodat u CurrentUser//My store.");

                    using (X509Store trusted = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine))
                    {
                        trusted.Open(OpenFlags.ReadWrite);
                        trusted.Add(newCert);
                        trusted.Close();
                    }

                    Console.WriteLine("Sertifikat dodat u CurrentUser/My i TrustedPeople store.");
                }

                Console.WriteLine($"Sertifikat izdat za {identity.Name} sa OU={userGroup}");
                LogEvent($"Sertifikat izdat za {identity.Name} sa OU={userGroup}.", EventLogEntryType.Information);

                ReplicateData();

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("GRESKA: " + ex.Message);
                LogEvent($"Greška prilikom izdavanja sertifikata: {ex.Message}", EventLogEntryType.Error);
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

            NetTcpBinding binding = new NetTcpBinding(SecurityMode.None);

            host.AddServiceEndpoint(typeof(ICertificateManagerService), binding, address);

            // ✅ Omogući prikaz detaljnih grešaka na klijentu
            var debugBehavior = host.Description.Behaviors.Find<ServiceDebugBehavior>();
            if (debugBehavior == null)
            {
                host.Description.Behaviors.Add(new ServiceDebugBehavior
                {
                    IncludeExceptionDetailInFaults = true
                });
            }
            else
            {
                debugBehavior.IncludeExceptionDetailInFaults = true;
            }

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