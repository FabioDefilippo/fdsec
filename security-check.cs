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
            if (svcchk.Status == ServiceControllerStatus.Stopped || svcchk.Status == ServiceControllerStatus.StopPending)
            {
                Console.Error.Write(svcchk.DisplayName + " service stopped");
                Poweroff();
                return;
            }
        }

        private static void Poweroff()
        {
            Process.Start("shutdown", "/s /t 0");
        }

        static async Task Main(string[] args)
        {
            Console.Error.WriteLine("Checking security...");
            try
            {
                Task t1 = Task.Run(() => CheckServices());
                Task t2 = Task.Run(() => CheckProcesses());
                await Task.WhenAll(t1, t2);
            }
            catch { }
        }
        
        private static async Task CheckProcesses()
        {
            string[] cli = { "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", "wmic.exe", "powershell.exe" };
            string[] flags = { "delete", "remove" };
            bool alarm = false, alarm2 = false;
            try
            {
                while (true)
                {
                    if (alarm || alarm2)
                    {
                        Console.Error.WriteLine("Fake process terminated!");
                        Poweroff();
                        return;
                    }
                    else
                    {
                        alarm = true;
                        alarm2 = true;
                    }
                
                    ManagementObjectSearcher mos = new ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string displayname = mo["displayName"]?.ToString();
                        if (displayname != null || (displayname.Contains("Windows Defender") || displayname.Contains("Microsoft Defender")))
                        {
                            alarm2 = false;
                        }
                        
                        if (mo["State"].ToString().ToLower().Equals("running"))
                        {
                            alarm2 = false;
                        }
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
                        }
                        catch { }
                    }
                    Thread.Sleep(100);
                }
            }
            catch { }
        }
        
        private static async Task CheckServices()
        {
            ServiceController scmps = new ServiceController("MpsSvc");
            ServiceController scwd = new ServiceController("WinDefend");
            ServiceController scsc = new ServiceController("wscsvc");
            ServiceController scwua = new ServiceController("wuauserv");
            ServiceController scvss = new ServiceController("VSS");

            try
            {
                while (true)
                {
               
                    CheckService(scmps);

                    CheckService(scwd);

                    CheckService(scsc);

                    CheckService(scwua);

                    CheckService(scvss);
                
                    Thread.Sleep(100);
                }
            }
            catch { }
        }
    }
}
