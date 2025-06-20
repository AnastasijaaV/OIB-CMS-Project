﻿using System;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;
using Manager;
using System.Security.Principal;
using Contracts;
using System.ServiceModel.Security;

namespace Client
{
    public class WCFClient : ChannelFactory<IWCFContract>, IWCFContract, IDisposable
    {
        IWCFContract factory;

        public WCFClient(NetTcpBinding binding, EndpointAddress address)
            : base(binding, address)
        {
            // ✅ Koristimo puni CN iz Windows identiteta
            string cltCertCN = WindowsIdentity.GetCurrent().Name; // npr: DESKTOP-CNKKSF4\wcfclient

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

            // ⚙️ Podešavanje validacije
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
                this.Close();
            }
            catch { }
        }
    }
}