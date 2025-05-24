using System;
using System.ServiceProcess;
using System.Diagnostics;
using System.Management;
using System.Threading;

namespace security_check
{
    internal class Program
    {
        private static string GetCommandLine(Process pro)
        {
            using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT CommandLine FORM Win32_Process WHERE ProcessId = " + pro.Id))
            {
                using (ManagementObjectCollection moc = mos.Get())
                {
                    foreach (ManagementBaseObject mbo in moc)
                    {
                        return mbo["CommandLine"]?.ToString();
                    }
                }
            }
            return String.Empty;
        }

        private static void Poweroff()
        {
            Process.Start("shutdown", "/s /t 0");
        }
      
        static void Main(string[] args)
        {
            Console.Error.WriteLine("Checking security...");
            string DefPath = "C:\\Program Files\\Windows Defender\\MsMpEng.exe";
            string[] cli = { "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", "wmic.exe", "powershell.exe" };
            string[] flags = { "delete", "remove" };
            bool alarm = false;
            bool alarm2 = false;
            int DefId = -1;
            ServiceController sc = new ServiceController("MpsSvc");
            try
            {
                while (true)
                {
                    ManagementObjectSearcher mos = ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string displayname = mo["displayName"]?.ToString();
                        if (displayname == null || (!displayname.Contains("Windows Defender") && !displayname.Contains("Microsoft Defender")))
                        {
                            Poweroff();
                        }
                    }
                    if (alarm || alarm2)
                    {
                        Console.Error.WriteLine("Fake process terminated!");
                        Poweroff();
                    }
                    else
                    {
                        alarm = true;
                        alarm2 = true;
                    }

                     sc.Refresh();
                     if(sc.Status == ServiceControllerStatus.Stopped || sc.Status == ServiceControllerStatus.StopPending)
                     {
                         Poweroff();
                     }
                    
                    foreach (Process pro in Process.GetProcesses())
                    {
                        try
                        {
                            if (Array.IndexOf(cli, pro.ProcessName.ToLower() + ".exe") >= 0)
                            {
                                string arg = GetCommandLine(pro).ToLower();
                                if (arg != String.Empty)
                                {
                                    foreach (string flag in flags)
                                    {
                                        if (arg.Contains(flag))
                                        {
                                            Console.Error.WriteLine("Attempting to delete backups!");
                                            Poweroff();
                                            return;
                                        }
                                    }
                                }
                            }
                            
                            if ((pro.ProcessName.ToLower() + ".exe").Equals("ollydbg.exe"))
                            {
                                alarm = false;
                            }
                            
                            if (Process.GetProcessById(DefId).HasExited)
                            {
                                alarm2 = false;
                            }
                        }
                        catch { }
                    }
                    Thread.Sleep(500);
                }
            }
            catch { }
        }
    }
}
