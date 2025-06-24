using System;
using System.ServiceModel;
using System.ServiceModel.Description;
using Contracts;

namespace Backup
{
    public class Program
    {
        static void Main(string[] args)
        {
            string address = "net.tcp://localhost:9000/BackupService";

            NetTcpBinding binding = new NetTcpBinding(SecurityMode.Transport);
            binding.Security.Transport.ClientCredentialType = TcpClientCredentialType.Windows;

            ServiceHost host = new ServiceHost(typeof(BackupService));
            host.AddServiceEndpoint(typeof(IBackupContract), binding, address);

            var debug = host.Description.Behaviors.Find<ServiceDebugBehavior>();
            if (debug == null)
                host.Description.Behaviors.Add(new ServiceDebugBehavior { IncludeExceptionDetailInFaults = true });
            else
                debug.IncludeExceptionDetailInFaults = true;

            try
            {
                host.Open();
                Console.WriteLine("BackupService je pokrenut na " + address);
                Console.WriteLine("Pritisni Enter za prekid...");
                Console.ReadLine();
                host.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Greška: {ex.Message}");
            }
        }
    }
}