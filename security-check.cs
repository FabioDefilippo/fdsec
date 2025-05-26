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

        private static void CheckService(ServiceController svcchk)
        {
           svcchk.Refresh();
           if(svcchk.Status == ServiceControllerStatus.Stopped || svcchk.Status == ServiceControllerStatus.StopPending)
           {
                Poweroff();
           } 
        }

        private static void Poweroff()
        {
            Process.Start("shutdown", "/s /t 0");
        }
      
        static void Main(string[] args)
        {
            Console.Error.WriteLine("Checking security...");
            string[] cli = { "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", "wmic.exe", "powershell.exe" };
            string[] flags = { "delete", "remove" };
            bool alarm = false;
            ServiceController scmps = new ServiceController("MpsSvc");
            ServiceController scwd = new ServiceController("WinDefend");
            ServiceController scsc = new ServiceController("wscsvc");
            ServiceController scwua = new ServiceController("wuauserv");
            ServiceController scvss = new ServiceController("vssvc");
            
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
                    if (alarm)
                    {
                        Console.Error.WriteLine("Fake process terminated!");
                        Poweroff();
                    }
                    else
                    {
                        alarm = true;
                    }

                     CheckService(scmps);
                     
                     CheckService(scwd);

                    CheckService(scsc);

                    CheckService(scwua);

                    CheckService(scvss);
                    
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
                        }
                        catch { }
                    }
                    Thread.Sleep(100);
                }
            }
            catch { }
        }
    }
}
