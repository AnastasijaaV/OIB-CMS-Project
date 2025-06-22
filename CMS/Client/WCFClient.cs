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

            var cert = CertManager.GetCertificateFromStorage(StoreName.My, StoreLocation.LocalMachine, cltCertCN);

            if (cert == null)
            {
                Console.WriteLine($"❌ Klijentski sertifikat sa CN={cltCertCN} NIJE pronađen u LocalMachine\\My store.");
                return;
            }
            else
            {
                Console.WriteLine($"✅ Klijentski sertifikat pronađen: {cert.Subject}");
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
                factory?.TestCommunication(id);
            }
            catch (Exception e)
            {
                Console.WriteLine("[TestCommunication] ERROR = {0}", e.Message);
            }
        }

        public void Dispose()
        {
            if (factory != null)
            {
                factory = null;
            }

            try
            {
                LogEvent($"Prekinuta komunikacija: Klijent {WindowsIdentity.GetCurrent().Name} zatvorio konekciju.", EventLogEntryType.Information);
                this.Close();
            }
            catch { }
        }

        private void LogEvent(string message, EventLogEntryType entryType)
        {
            string source = "WCFClient";
            string log = "Application";

            if (!EventLog.SourceExists(source))
                EventLog.CreateEventSource(source, log);

            EventLog.WriteEntry(source, message, entryType);
        }
    }
}