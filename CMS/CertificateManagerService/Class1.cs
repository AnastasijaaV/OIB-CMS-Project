using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Diagnostics;
using System.Threading;

namespace CertificateManager
{
    [ServiceContract]
    public interface ICertificateManagerService
    {
        [OperationContract]
        void CreateCertificate(string subjectName, bool includePrivateKey);

        [OperationContract]
        void RevokeCertificate(string serialNumber);

        [OperationContract]
        void ReplicateData();

        [OperationContract]
        void NotifyClientsOfRevocation(string serialNumber);
    }

    public class CertificateManagerService : ICertificateManagerService
    {
        private static readonly string CertificateFolder = "C:\\Certificates";
        private static readonly string RevocationListPath = Path.Combine(CertificateFolder, "RevocationList.txt");

        public CertificateManagerService()
        {
            if (!Directory.Exists(CertificateFolder))
            {
                Directory.CreateDirectory(CertificateFolder);
            }

            if (!File.Exists(RevocationListPath))
            {
                File.Create(RevocationListPath).Dispose();
            }
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
            try
            {
                File.AppendAllText(RevocationListPath, serialNumber + Environment.NewLine);
                NotifyClientsOfRevocation(serialNumber);

                // Generate a new certificate for the revoked one
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
                {
                    Directory.CreateDirectory(backupPath);
                }

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
            // Placeholder for client notification logic
            Console.WriteLine($"Clients notified of certificate revocation: {serialNumber}");
        }

        private void LogEvent(string message, EventLogEntryType entryType)
        {
            string source = "CertificateManagerService";
            string log = "Application";

            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, log);
            }

            EventLog.WriteEntry(source, message, entryType);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string address = "net.tcp://localhost:8888/CertificateManagerService";
            ServiceHost host = new ServiceHost(typeof(CertificateManagerService));

            NetTcpBinding binding = new NetTcpBinding();
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
