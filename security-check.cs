using System;
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
            string[] cli = { "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", "wmic.exe" };
            string[] flags = { "delete", "revoke" };
            bool alarm = false;
            bool alarm2 = false;
            try
            {
                while (true)
                {
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
                    foreach (Process pro in Process.GetProcesses())
                    {
                        try
                        {
                            if (Array.IndexOf(cli, pro.ProcessName.ToLower() + ".exe") >= 0)
                            {
                                string arg = GetCommandLine(pro);
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
                            
                            if ((pro.ProcessName.ToLower() + ".exe").Equals("msmpeng.exe"))
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
