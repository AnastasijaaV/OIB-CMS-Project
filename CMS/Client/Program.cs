using Contracts;
using Manager;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceModel;
using System.Threading;

namespace Client
{
    public class Program
    {
        static void Main(string[] args)
        {
            NetTcpBinding binding = new NetTcpBinding(SecurityMode.None);
            string certServiceAddress = "net.tcp://localhost:8888/CertificateManagerService";

            ChannelFactory<ICertificateManagerService> factory = new ChannelFactory<ICertificateManagerService>(
                binding, new EndpointAddress(certServiceAddress));
            ICertificateManagerService certService = factory.CreateChannel();

            string currentUser = WindowsIdentity.GetCurrent().Name;
            string sanitized = currentUser.Replace("\\", "_");
            string certPath = $"C:\\Certificates\\{sanitized}.pfx";

            while (true)
            {
                Console.WriteLine("\n📋 MENI:");
                Console.WriteLine("1. Kreiraj sertifikat");
                Console.WriteLine("2. Povuci (revoke) sertifikat");
                Console.WriteLine("3. Auto provera i automatska revokacija");
                Console.WriteLine("4. Pokreni periodičnu komunikaciju");
                Console.WriteLine("5. Izlaz");
                Console.Write("Izbor: ");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        bool success = certService.RequestCertificate(currentUser);
                        if (success)
                            Console.WriteLine($"✔ Sertifikat izdat za korisnika {currentUser}.");
                        else
                            Console.WriteLine("❌ Korisnik nije u dozvoljenoj grupi ili greška.");
                        break;

                    case "2":
                        Console.Write("🔑 Unesi serial number sertifikata za povlačenje: ");
                        string serialInput = Console.ReadLine();
                        certService.RevokeCertificate(serialInput);
                        Console.WriteLine("🔁 Revokacija pokrenuta.");
                        break;

                    case "3":
                        if (!File.Exists(certPath))
                        {
                            Console.WriteLine("❌ Sertifikat nije pronađen na disku.");
                            break;
                        }

                        X509Certificate2 cert = new X509Certificate2(certPath, "password");
                        string serial = cert.SerialNumber.ToLower();

                        Console.WriteLine($"🔍 Serial number: {serial}");

                        string revPath = "C:\\Certificates\\RevocationList.txt";
                        if (File.Exists(revPath) &&
                            File.ReadAllLines(revPath).Contains(serial))
                        {
                            Console.WriteLine("⚠️ Sertifikat je kompromitovan. Pokrećem automatsku revokaciju...");
                            certService.RevokeCertificate(serial);
                        }
                        else
                        {
                            Console.WriteLine("✅ Sertifikat je važeći.");
                        }
                        break;

                    case "4":
                        Console.WriteLine("🚀 Pokrećem periodičnu komunikaciju (CTRL+C za prekid)...");

                        string receiverAddress = "net.tcp://localhost:9999/Receiver";
                        NetTcpBinding receiverBinding = new NetTcpBinding(SecurityMode.Transport);
                        receiverBinding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Certificate;

                        // ✔ DNS identitet mora da se poklapa sa CN iz server sertifikata (npr. "wcfservice")
                        var identity = new DnsEndpointIdentity("wcfservice");

                        // ✔ Endpoint sa eksplicitnim DNS identitetom
                        var client = new WCFClient(receiverBinding, new EndpointAddress(new Uri(receiverAddress), identity));

                        int id = 1;
                        while (true)
                        {
                            client.TestCommunication(id++); // bez parametra jer metoda nema parametar
                            int delay = new Random().Next(1000, 10000); // 1–10 sekundi
                            Thread.Sleep(delay);
                        }

                    case "5":
                        Console.WriteLine("👋 Izlaz iz programa.");
                        return;

                    default:
                        Console.WriteLine("⚠️ Nevažeća opcija. Pokušaj ponovo.");
                        break;
                }
            }
        }
    }
}
