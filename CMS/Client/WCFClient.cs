using System;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;
using Manager;
using System.Security.Principal;
using Contracts;
using System.ServiceModel.Security;
using System.Diagnostics;

namespace Client
{
    public class WCFClient : ChannelFactory<IWCFContract>, IWCFContract, IDisposable
    {
        IWCFContract factory;

        public WCFClient(NetTcpBinding binding, EndpointAddress address)
            : base(binding, address)
        {
            string cltCertCN = WindowsIdentity.GetCurrent().Name;

            X509Certificate2 cert = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, cltCertCN);

            // Ako ne postoji validan sertifikat (nema ga ili je povučen)
            if (cert == null)
            {
                Console.WriteLine($"Sertifikat za klijenta \"{cltCertCN}\" nije pronađen ili je povučen. Zahtevam novi...");

                try
                {
                    var certBinding = new NetTcpBinding();
                    certBinding.Security.Mode = SecurityMode.Transport;
                    certBinding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                    ChannelFactory<ICertificateManagerService> channelFactory = new ChannelFactory<ICertificateManagerService>(
                        certBinding,
                        new EndpointAddress("net.tcp://localhost:9999/ICertificateManagerService")
                    );

                    ICertificateManagerService serviceProxy = channelFactory.CreateChannel();

                    // Poziv za izdavanje sertifikata
                    serviceProxy.RequestCertificate(cltCertCN);
                    channelFactory.Close();

                    // Ponovno učitavanje novog sertifikata
                    cert = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, cltCertCN);

                    if (cert == null)
                    {
                        Console.WriteLine("Novi sertifikat nije pronađen nakon zahteva. Komunikacija neće biti moguća.");
                        return;
                    }
                    else
                    {
                        Console.WriteLine("Novi sertifikat uspešno kreiran i dodat.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Greška prilikom zahteva za novi sertifikat: {ex.Message}");
                    return;
                }
            }
            else
            {
                Console.WriteLine($"Sertifikat pronađen: {cert.Subject}");
            }

            this.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.ChainTrust;
            this.Credentials.ServiceCertificate.Authentication.RevocationMode = X509RevocationMode.NoCheck;
            this.Credentials.ClientCertificate.Certificate = cert;

            factory = this.CreateChannel();
        }

        public void TestCommunication(int id)
        {
            try
            {
                Console.WriteLine($"[Client] Slanje ID={id} serveru...");
                factory?.TestCommunication(id);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[TestCommunication] ERROR = {e.Message}");
            }
        }

        public void Dispose()
        {
            try
            {
                string username = WindowsIdentity.GetCurrent().Name;
                string msg = $"Klijent {username} zatvara konekciju.";

                Console.WriteLine($"🔴 {msg}");
                LogEvent($"Prekinuta komunikacija: {msg}", EventLogEntryType.Information);

                // Poziv serveru da evidentira prekid
                factory?.DisconnectNotice(); // <-- DODATO OVO

                if (factory is ICommunicationObject commObj && commObj.State == CommunicationState.Opened)
                {
                    commObj.Close();
                }

                this.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Greška pri zatvaranju: {ex.Message}");
            }
        }

        private void LogEvent(string message, EventLogEntryType entryType)
        {
            string source = "WCFClient";
            string log = "Application";

            if (!EventLog.SourceExists(source))
                EventLog.CreateEventSource(source, log);

            EventLog.WriteEntry(source, message, entryType);
        }
        public void DisconnectNotice()
        {
            try
            {
                factory?.DisconnectNotice(); // <-- poziva server
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DisconnectNotice] Greška: {ex.Message}");
            }
        }
    }
}