using Contracts;
using System;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Security.Cryptography.X509Certificates;

namespace Service
{
    [ServiceBehavior(IncludeExceptionDetailInFaults = true)]
    public class WCFService : IWCFContract
    {
        [OperationBehavior(Impersonation = ImpersonationOption.NotAllowed)]
        public void TestCommunication(int id)
        {
            // Prikaz svih claim-ova za debagovanje
            foreach (var cs in ServiceSecurityContext.Current.AuthorizationContext.ClaimSets)
            {
                foreach (var claim in cs)
                {
                    Console.WriteLine($"[CLAIM] {claim.ClaimType} = {claim.Resource}");
                }
            }

            try
            {
                var certClaim = ServiceSecurityContext.Current.AuthorizationContext.ClaimSets
                    .SelectMany(cs => cs)
                    .FirstOrDefault(c => c.ClaimType == System.IdentityModel.Claims.ClaimTypes.X500DistinguishedName);

                if (certClaim == null)
                {
                    Console.WriteLine("❌ Sertifikat nije pronađen u zahtevu.");
                    return;
                }

                // Pravilno parsiranje DistinguishedName iz sertifikata
                string dn = (certClaim.Resource as X500DistinguishedName)?.Name;
                if (string.IsNullOrWhiteSpace(dn))
                {
                    Console.WriteLine("❌ Prazan DistinguishedName iz sertifikata.");
                    return;
                }

                // Parsiranje CN i OU iz DN stringa
                string cn = dn.Split(',')
                              .Select(p => p.Trim())
                              .FirstOrDefault(p => p.StartsWith("CN="))?
                              .Substring(3);
                string ou = dn.Split(',')
                              .Select(p => p.Trim())
                              .FirstOrDefault(p => p.StartsWith("OU="))?
                              .Substring(3);

                if (string.IsNullOrWhiteSpace(cn) || string.IsNullOrWhiteSpace(ou))
                {
                    Console.WriteLine("❌ Ne mogu da pročitam CN ili OU iz DN: " + dn);
                    return;
                }

                // Provera dozvoljenih grupa
                string[] allowedGroups = { "RegionEast", "RegionWest", "RegionNorth", "RegionSouth" };
                if (!allowedGroups.Contains(ou))
                {
                    Console.WriteLine($"❌ Klijent {cn} NIJE član dozvoljene grupe OU={ou}. Preskačem logovanje.");
                    return;
                }

                // Logovanje u fajl
                string certFolder = @"C:\Certificates";
                string logPath = Path.Combine(certFolder, "Log.txt");

                if (!Directory.Exists(certFolder))
                    Directory.CreateDirectory(certFolder);

                if (!File.Exists(logPath))
                    File.WriteAllText(logPath, "");

                string[] lines = File.ReadAllLines(logPath);
                int newId = lines.Length + 1;

                string timestamp = DateTime.Now.ToString("dd.MM.yyyy. HH:mm:ss");
                string logLine = $"{newId}:{timestamp};{cn}";

                File.AppendAllText(logPath, logLine + Environment.NewLine);
                Console.WriteLine($"🟢 Upisano u log: {logLine}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ GRESKA u TestCommunication: " + ex.Message);
            }
        }
    }
}