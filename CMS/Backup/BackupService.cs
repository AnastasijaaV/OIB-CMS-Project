using Contracts;
using System;
using System.IO;

namespace Backup
{
    public class BackupService : IBackupContract
    {
        public void ReceiveBackup(string fileName, byte[] content)
        {
            string backupFolder = @"C:\Certificates\RealBackup";

            if (!Directory.Exists(backupFolder))
                Directory.CreateDirectory(backupFolder);

            string path = Path.Combine(backupFolder, fileName);
            File.WriteAllBytes(path, content);

            Console.WriteLine($"✅ Fajl primljen i sačuvan: {fileName}");
        }
    }
}