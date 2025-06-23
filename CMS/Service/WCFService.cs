using Contracts;
using System;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

namespace Service
{
    [ServiceBehavior(IncludeExceptionDetailInFaults = true, InstanceContextMode = InstanceContextMode.PerSession)]
    public class WCFService : IWCFContract
    {
        private string _cachedClientCN = "Nepoznat";

        [OperationBehavior(Impersonation = ImpersonationOption.NotAllowed)]
        public void TestCommunication(int id)
        {
            foreach (var cs in ServiceSecurityContext.Current.AuthorizationContext.ClaimSets)
            {
                foreach (var claim in cs)
                {
                    Console.WriteLine($"[CLAIM] {claim.ClaimType} = {claim.Resource}");
                }
            }

            try
            {
                OperationContext.Current.InstanceContext.Closed += (sender, e) =>
                {
                    LogEvent($"🔴 Komunikacija prekinuta: Klijent {_cachedClientCN}.", EventLogEntryType.Information);
                };

                OperationContext.Current.InstanceContext.Faulted += (sender, e) =>
                {
                    LogEvent($"⚠️ Komunikacija faultovana: Klijent {_cachedClientCN}.", EventLogEntryType.Warning);
                };

                var certClaim = ServiceSecurityContext.Current.AuthorizationContext.ClaimSets
                    .SelectMany(cs => cs)
                    .FirstOrDefault(c => c.ClaimType == System.IdentityModel.Claims.ClaimTypes.X500DistinguishedName);

                if (certClaim == null)
                {
                    Console.WriteLine("❌ Sertifikat nije pronađen u zahtevu.");
                    return;
                }

                string dn = (certClaim.Resource as X500DistinguishedName)?.Name;
                if (string.IsNullOrWhiteSpace(dn))
                {
                    Console.WriteLine("❌ Prazan DistinguishedName iz sertifikata.");
                    return;
                }

                _cachedClientCN = dn.Split(',').Select(p => p.Trim()).FirstOrDefault(p => p.StartsWith("CN="))?.Substring(3);
                string ou = dn.Split(',').Select(p => p.Trim()).FirstOrDefault(p => p.StartsWith("OU="))?.Substring(3);

                if (string.IsNullOrWhiteSpace(_cachedClientCN) || string.IsNullOrWhiteSpace(ou))
                {
                    Console.WriteLine("❌ Ne mogu da pročitam CN ili OU iz DN: " + dn);
                    return;
                }

                string[] allowedGroups = { "RegionEast", "RegionWest", "RegionNorth", "RegionSouth" };
                if (!allowedGroups.Contains(ou))
                {
                    Console.WriteLine($"❌ Klijent {_cachedClientCN} NIJE član dozvoljene grupe OU={ou}. Preskačem logovanje.");
                    return;
                }

                LogEvent($"Nova konekcija: Klijent {_cachedClientCN} iz OU={ou} je uspešno pristupio.", EventLogEntryType.Information);

                string certFolder = @"C:\Certificates";
                string logPath = Path.Combine(certFolder, "Log.txt");

                if (!Directory.Exists(certFolder))
                    Directory.CreateDirectory(certFolder);

                if (!File.Exists(logPath))
                    File.WriteAllText(logPath, "");

                string[] lines = File.ReadAllLines(logPath);
                int newId = lines.Length + 1;

                string timestamp = DateTime.Now.ToString("dd.MM.yyyy. HH:mm:ss");
                string logLine = $"{newId}:{timestamp};{_cachedClientCN}";

                File.AppendAllText(logPath, logLine + Environment.NewLine);
                Console.WriteLine($"🟢 Upisano u log: {logLine}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ GRESKA u TestCommunication: " + ex.Message);
            }
        }

        private void LogEvent(string message, EventLogEntryType entryType)
        {
            string source = "WCFService";
            string log = "Application";

            if (!EventLog.SourceExists(source))
                EventLog.CreateEventSource(source, log);

            EventLog.WriteEntry(source, message, entryType);
        }
    }
}