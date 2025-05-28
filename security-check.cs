using System;
using System.Security.Principal;
using System.ServiceProcess;
using System.Diagnostics;
using System.Management;
using System.Threading;
using System.Threading.Tasks;

namespace security_check
{
    internal class Program
    {
        private static string GetCommandLine(Process pro) //GET COMMAND LINE FROM PROCESS
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
            svcchk.Refresh(); //REFRESH SERVICE STATE
            if (svcchk.Status == ServiceControllerStatus.Stopped || svcchk.Status == ServiceControllerStatus.StopPending) //CHECK IF A SERVICE IS STOPPING OR STOPPED
            {
                Console.Error.Write(svcchk.DisplayName + " service stopped");
                Poweroff();
                return;
            }
        }

        private static void Poweroff()
        {
            Process.Start("shutdown", "/s /f /t 0"); //SHUTDOWN THE OS IMMEDIATELY
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
            string[] cli = { "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", "wmic.exe", "wevtutil", "auditpol.exe", "powershell.exe" }; //ALL BINARIES COULD DELETE SHADOW COPIES, LOGS AND BACKUPS
            string[] flags = { "delete", "remove", "clear-eventlog", "cl", "disable", "eventlog" }; //FLAGS IN COMMAND LINES DELETING, REMOVING OR DISABLING SHADOW COPIES, BACKUPS AND LOGS
            bool alarm1 = false, alarm2 = false, alarm3 = false; //ALARMS FOR CONDITIONS
            ManagementObjectSearcher mos;
            string AppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLower();
            WindowsIdentity wi;
            WindowsPrincipal wp;
            try
            {
                while (true)
                {
                    if (alarm1 || alarm2 || alarm3) //HERE WE CAN CHOOSE CONDITIONS TO SHUTDOWN THE OS
                    {
                        Console.Error.WriteLine("Fake process terminated!");
                        Poweroff();
                        return;
                    }
                    else //SET ALARMS TO CHECK NEGATIVE CONDITIONS
                    {
                        alarm1 = true;
                        alarm2 = true;
                        alarm3 = true;
                    }
                
                    mos = new ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string displayname = mo["displayName"]?.ToString();
                        if (displayname != null || (displayname.Contains("Windows Defender") || displayname.Contains("Microsoft Defender")))
                        {
                            if (mo["State"].ToString().ToLower().Equals("running"))
                            {
                                alarm2 = false;
                            }
                        }
                    }

                    mos = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name = 'EventLog'"); //CHECK LOG SERVICE
                    foreach (ManagementObject mo in mos.Get())
                    {
                        if (mo["State"].ToString().ToLower().Equals("running"))
                        {
                            alarm2 = false;
                        }
                    }

                    foreach (Process pro in Process.GetProcesses()) //CHECK ALL PROCESSES
                    {
                        try
                        {
                            wi = new WindowsIdentity(pro.Handle);
                            wp = new WindowsPrincipal(wi);
                            //CHECK IF A PROCESS FROM APPADATA PATH HAS ADMIN PRIVILEGES
                            if (wp.IsInRole(WindowsBuiltInRole.Administrator) && pro.MainModule.FileName.ToLower().StartsWith(AppDataPath, StringComparison.OrdinalIgnoreCase))
                            {
                                alarm3 = true;
                            }
                            
                            if (Array.IndexOf(cli, pro.ProcessName.ToLower() + ".exe") >= 0)
                            {
                                string arg = GetCommandLine(pro).ToLower();
                                if (arg != String.Empty)
                                {
                                    foreach (string flag in flags) //CHECK IF THERE IS A PROCESS DELETING OR REMOVING SHADOW COPIES OR DISABLING LOG
                                    {
                                        if (arg.Contains(flag.ToLower()))
                                        {
                                            Console.Error.WriteLine("Attempting to delete backups!");
                                            Poweroff();
                                            return;
                                        }
                                    }
                                }
                            }
                            
                            if ((pro.ProcessName.ToLower() + ".exe").Equals("ollydbg.exe")) //CHECK IF FAKE PROCESS IS RUNNING
                            {
                                alarm1 = false;
                            }
                        }
                        catch { }
                    }
                    Thread.Sleep(100);
                }
            }
            catch { }
        }
        
        private static async Task CheckServices() //CHECK IF DEFENDER, FIREWALL, UPDATES, SHADOW COPIES AND OTHER IMPORTANT SERVICES ARE RUNNING
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
