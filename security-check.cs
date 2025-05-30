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
        private static void PrintErr(string error)
        {
            Console.Error.WriteLine(error);
        }
        
        private static string GetCommandLine(Process pro) //GET COMMAND LINE FROM PROCESS
        {
            try
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
            }
            catch (Exception ex)
            {
                PrintErr(ex.Message);
            }
            return String.Empty;
        }

        private static void CheckService(ServiceController svcchk)
        {
            try
            {
                svcchk.Refresh(); //REFRESH SERVICE STATE
                if (svcchk.Status == ServiceControllerStatus.Stopped || svcchk.Status == ServiceControllerStatus.StopPending) //CHECK IF A SERVICE IS STOPPING OR STOPPED
                {
                    PrintErr(svcchk.DisplayName + " service stopped");
                    Poweroff();
                    return;
                }
            }
            catch (Exception ex)
            {
                PrintErr(ex.Message);
            }
        }

        private static void Poweroff()
        {
            try
            {
                Process.Start("shutdown", "/s /f /t 0"); //SHUTDOWN THE OS IMMEDIATELY
            }
            catch (Exception ex)
            {
                PrintErr(ex.Message);
            }
        }

        static async Task Main(string[] args)
        {
            PrintErr("Checking security...");
            try
            {
                Task t1 = Task.Run(() => CheckServices());
                Task t2 = Task.Run(() => CheckProcesses());
                await Task.WhenAll(t1, t2);
            }
            catch (Exception ex)
            {
                PrintErr(ex.Message);
            }
        }
        
        private static async Task CheckProcesses()
        {
            try
            {
            string[] cli = { "vssadmin.exe", "wbadmin.exe", "diskshadow.exe", "wmic.exe", "wevtutil", "auditpol.exe", "fsutil.exe", "net.exe", "sc.exe", "powershell.exe" }; //ALL BINARIES COULD DELETE SHADOW COPIES, LOGS AND BACKUPS
            string[] flags = { "delete", "remove", "clear-eventlog", "cl", "disable", "eventlog", "stop", "pause", "setzerodata" }; //FLAGS IN COMMAND LINES DELETING, REMOVING OR DISABLING SHADOW COPIES, BACKUPS AND LOGS
            bool alarm1 = false, alarm2 = false, alarm3 = false; //ALARMS FOR CONDITIONS
            ManagementObjectSearcher mos;
            string AppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLower();
            WindowsIdentity wi;
            WindowsPrincipal wp;

                while (true)
                {
                    if (alarm1 || alarm2 || alarm3) //HERE WE CAN CHOOSE CONDITIONS TO SHUTDOWN THE OS
                    {
                        PrintErr("Fake process terminated!");
                        Poweroff();
                        return;
                    }
                    else //SET ALARMS TO CHECK NEGATIVE CONDITIONS
                    {
                        alarm1 = true; //FAKE PROCESS KILLED
                        alarm2 = true; //DEFENDER AND EVENTLOG
                        alarm3 = true; //ADMIN PRIVILEGES IN APPDATA
                    }
                
                    mos = new ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM AntiVirusProduct");
                    foreach (ManagementObject mo in mos.Get())
                    {
                        string displayname = mo["displayName"]?.ToString();
                        if (displayname != null && (displayname.Contains("Windows Defender") || displayname.Contains("Microsoft Defender")))
                        {
                            try
                            {
                                if (mo["State"].ToString().ToLower().Equals("running"))
                                {
                                    alarm2 = false;
                                }
                            }
                            catch {}
                            alarm2 = false;
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

                            string tcommandline = pro.ProcessName.ToLower() + ".exe";
                            string arg = GetCommandLine(pro).ToLower();
                            if (Array.IndexOf(cli, tcommandline) >= 0)
                            {
                                if (arg != String.Empty)
                                {
                                    foreach (string flag in flags) //CHECK IF THERE IS A PROCESS DELETING OR REMOVING SHADOW COPIES OR DISABLING LOG
                                    {
                                        if (arg.Contains(flag.ToLower()))
                                        {
                                            PrintErr("Attempting to delete backups!");
                                            Poweroff();
                                            return;
                                        }
                                    }
                                }
                            }
                            else if (tcommandline.Equals("del.exe")) // CHECK IF A MALWARE RUNS DEL /F /S /Q * COMMANDLINE
                            {
                                if (arg.Contains("/f") && arg.Contains("/s") && arg.Contains("/q"))
                                {
                                    if (arg.IndexOf('*') > -1)
                                    {
                                        Poweroff();
                                    }
                                }
                            }
                            
                            if ((pro.ProcessName.ToLower() + ".exe").Equals("ollydbg.exe")) //CHECK IF FAKE PROCESS IS RUNNING
                            {
                                alarm1 = false;
                            }
                        }
                        catch (Exception ey)
                        {
                            PrintErr(ey.Message);
                        }
                    }
                    Thread.Sleep(100);
                }
            }
            catch (Exception ex)
            {
                PrintErr(ex.Message);
            }
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
            catch (Exception ex)
            {
                PrintErr(ex.Message);
            }
        }
    }
}
