using System;
using System.Linq;
using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using System.Management;



namespace KeyLoggerDetectionTool
{
    class Program
    {

        private const string api_key = "5429af75345a02345dd254d1b6811392ec3d35f990bbfb7fa266493441a10937";
        static void Main(string[] args)
        {
            Console.WriteLine("Running Keylogger Detection Tool...");


            {
                bool isRunningInBox = isRunningInSandBox();
                Console.WriteLine("Is isRunningInBox: " + isRunningInSandBox);
            }
            while (true)
            {
                //CHECKS FOR NETWORK ACTIVITY ON PORTS 80(HTTP), 443(HTTPS), 21(FTP), 20(FTP), 25(SMTP), 8080(HTTP ALTERNATE) AND 8443(HTTPS ALTERNATE)

                string pythonPath = "networkScanner.py";
                ProcessStartInfo startInfo = new ProcessStartInfo("python", $"\"{pythonPath}\"");
                startInfo.Verb = "runas";
                Process.Start(startInfo);

                // GET A LIST OF ALL RUNNING PROCESSES
                var processes = Process.GetProcesses();

                //RUNS THE FILESYSTEM CHECKER FOR FILES CONTAINING CAPTURED KEYS
                Thread fileSystemThread = new Thread(checkFileSystem);
                fileSystemThread.Start();



                // ITERATE THROUGH EACH PROCESS
                foreach (var process in processes)
                {
                    //WHITELISTING PROCESS KNOWN TO BE CLEAR TO REMOVE CHANCES OF FALSE POSITIVES
                    if (process.ProcessName == ("conhost") || process.ProcessName == ("Code") || process.ProcessName == ("msteams") || process.ProcessName == ("DataExchangeHost") || process.ProcessName == ("explorer") || process.ProcessName == "svchost" || process.ProcessName == "Widgets" || process.ProcessName == "WindowsTerminal" || process.ProcessName == "OpenConsole" || process.ProcessName == "prl_cc" || process.ProcessName == "SecurityHealthSystray")
                    {
                        continue;
                    }


                    // CHECK IF THE PROCESS IS A POTENTIAL KEYLOGGER
                    if (IsPotentialKeylogger(process))
                    {
                        Console.WriteLine("Potential keylogger detected: " + process.ProcessName + " | Process ID: " + process.Id + " | " + " Path: " + process.MainModule.FileName);

                        //WRITE TO REPORT FILE (TRUE TO NOT OVERWRITE THE FILE)

                        StreamWriter writer = new StreamWriter("Report.txt", true);

                        using (writer)
                        {
                            writer.WriteLine("Potential keylogger detected: " + process.ProcessName + " | Process ID: " + process.Id + " | " + " Path: " + process.MainModule.FileName);
                            writer.WriteLine("Time: " + DateTime.Now);
                        }

                        //VIRUSTOTAL REPORT GENERATION
                        string logFilePath = "VTotallogs.txt";


                        using (StreamWriter writer1 = new StreamWriter(logFilePath, true))
                        {
                            Console.WriteLine("Checking with Virus Total.....");

                            string fileHash = GetFileHash(process);
                            if (fileHash != null)
                            {
                                writer1.WriteLine("FileHash = " + fileHash);

                                string resultFromVirusTotal = QueryVirusTotal(fileHash);
                                if (resultFromVirusTotal != null)
                                {
                                    writer1.WriteLine("VirusTotal Report : " + resultFromVirusTotal);
                                    writer1.WriteLine("Process Name: " + process.ProcessName);
                                    Console.WriteLine("Virus Total Report Generated");
                                }

                                else
                                {
                                    writer1.WriteLine("Could not retrieve report");
                                }
                            }
                            else
                            {
                                writer1.WriteLine("Could not get file hash");
                            }
                            writer1.WriteLine(DateTime.Now);
                            writer1.WriteLine("---------------------------------------------------");
                            writer1.WriteLine("---------------------------------------------------");
                            writer1.WriteLine("---------------------------------------------------");

                            Console.WriteLine("---------------------------------------------------");
                            Console.WriteLine("---------------------------------------------------");

                        }

                        //KILL THE POTENTIAL KEYLOGGER PROCESS YES OR NO 

                        string answer = "";
                        do
                        {
                            // ask the user if they want to kill the process
                            Console.WriteLine("Do you want to kill this process? (y/n)");
                            answer = Console.ReadLine().ToLower();
                            if (answer.ToLower() == "y")
                            {
                                process.Kill();
                                Console.WriteLine("Process Terminated");
                            }
                            else if (answer.ToLower() == "n")
                            {
                                Console.WriteLine("Process not terminated");
                            }
                            else
                            {
                                Console.WriteLine("Invalid answer. Please enter 'y' or 'n'.");
                            }
                        } while (answer.ToLower() != "y" && answer.ToLower() != "n");


                    }



                }
                // WAIT 2 SECONDS THEN GO AGAIN
                Thread.Sleep(2000);
            }
        }

        static bool IsPotentialKeylogger(Process process)
        {



            // CHECK FOR SUSPICIOUS FILENAMES
            try
            {
                string[] susNames = { "keylogger", "Keylogger", "Keylog", "stealth", "keytrap", "spy", "monitor", "Logger" };

                if (susNames.Any(s => process.ProcessName.Contains(s)))
                {
                    return true;
                }
            }

            catch (Exception)
            {

            }

            // CHECK FOR COMMON FUNCTION CALLS KNOWN TO BE USED BY KEYLOGGERS 
            try
            {
                // GET THE TOTAL SIZE OF THE PROCESS MEMORY 
                var processMemory = process.WorkingSet64;

                // CREATE A BYTE ARRAY TO STORE THE PROCESS MEMORY 
                var memory = new byte[processMemory];

                // OPEN A HANDLE TO THE PROCESS MEMORY
                IntPtr pHandle = OpenProcess(0x001F0FFF, false, process.Id);

                // READ THE CONTENTS OF THE PROCESS MEMORY INTO THE BYTE ARRAY
                if (process.MainModule != null)
                {
                    ReadProcessMemory(pHandle, process.MainModule.BaseAddress, memory, (int)processMemory, out int bytesRead);
                }
                // CONVERT THE MEMORY BYTES TO A STRING
                string memoryString = System.Text.Encoding.ASCII.GetString(memory);

                string[] suspiciousFuncs = {"FtpPutFileA","GetAsyncKeyState","GetKeyState","SetWindowsHookExA",
                "SetWindowsHookExW","SetWindowsHookEx","GetKeyboardState","BitBlt","PrintWindow","CreateWindowEx",
                "InternetOpenA","InternetOpen","InternetConnectA","InternetConnect","InternetCloseHandle","UnhookWindowsHookEx",
                "CallNextHookEx","ShowWindow","GetDC","keylog","keylogger","GetModuleHandle","SetHook","keyPressed"
                };

                List<string> susList = new List<string>();

                // LOOP THROUGH THE ARRAY TO CHECK FOR SUSPICIOUS FUNCTION CALLS IN MEMORY 

                for (int i = 0; i < suspiciousFuncs.Length; i++)
                {
                    if (memoryString.Contains(suspiciousFuncs[i]))
                    {

                        susList.Add(suspiciousFuncs[i]);
                    }
                }
                //IF AT LEAST TWO OF THE SUSPICIOUS FUNCTIONS ARE FOUND IT IS A POTENTIAL KEYLOGGER
                if (susList.Count >= 2)
                {
                    foreach (string suspiciousFunc in susList)
                    {
                        Console.WriteLine("API call used: " + suspiciousFunc);
                    }
                    return true;
                }

            }
            catch (Exception)
            {
                //MAY NOT HAVE ACCESS, IGNORE                
            }


            // IF ALL CHECKS ARE PASSED IT IS NOT A POTENTIAL KEYLOGGER
            return false;
        }

        //CHECK IF PROCESSES IS RUNNING IN SANDBOX OR VM ENVIRONMENT
        public static bool isRunningInSandBox()
        {
            bool isRunningInSandBox = false;
            try
            {
                // CHECK IF THE CURRENT PROCESS IS RUNNING IN A VIRTUALIZED ENVIRONMENT BY QUERYING THE 'Win32_ComputerSystem' WMI CLASS
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem");
                foreach (ManagementObject item in searcher.Get())
                {
                    string manufacturer = item["Manufacturer"].ToString().ToLower();
                    if ((manufacturer == "microsoft corporation" && item["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) ||
                        manufacturer.Contains("vmware") ||
                        item["Model"].ToString() == "VirtualBox")
                    {
                        isRunningInSandBox = true;
                        break;
                    }
                }

                // CHECK IF THE CURRENT PROCESS IS RUNNING IN A SANDBOXED ENVIRONMENT BY QUERYING THE 'WIN32_PROCESS' WMI CLASS.
                if (!isRunningInSandBox)
                {
                    searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
                    foreach (ManagementObject item in searcher.Get())
                    {
                        if (item["CommandLine"] != null && item["CommandLine"].ToString().Contains("sbiedll.dll"))
                        {
                            isRunningInSandBox = true;
                            break;
                        }
                    }
                }

                if (isRunningInSandBox)
                {
                    Console.WriteLine("THIS PROCESS IS RUNNING IN A VIRTUALIZED OR SANDBOXED ENVIRONMENT!!! THIS COULD MEAN IT IS MALWARE!!!");
                    Console.Write("Do you want to proceed running it? (Y/N) ");
                    string answer = Console.ReadLine().ToLower();

                    if (answer == "n")
                    {
                        Process.GetCurrentProcess().Kill();
                    }
                    else
                    {
                        // Get all processes running on the system
                        Process[] processes = Process.GetProcesses();

                        // Loop through each process and check if it's a potential keylogger using the IsPotentialKeylogger() function
                        foreach (Process process in processes)
                        {
                            if (IsPotentialKeylogger(process))
                            {
                                // Kill the potential keylogger process
                                Console.WriteLine($"Killing potential keylogger process: {process.ProcessName} ({process.Id})");
                                process.Kill();
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("ALL PROCESSES DETECTED ARE RUNNING IN THE HOST MACHINE!!!");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return false;
        }





        //METHOD USED TO CHECK FILE SYSTEM FOR LOG FILES BEING CREATED OR MODIFIED
        static void checkFileSystem()
        {
            while (true)
            {
                try
                {
                    FileSystemWatcher watcher = new FileSystemWatcher();
                    string pathToWatch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                    watcher.IncludeSubdirectories = true;
                    watcher.Path = pathToWatch;

                    // LOOK ONLY IN .TXT FILES
                    watcher.Filter = ("*.txt");

                    // WAIT FOR A CHANGE IN A FILE'S LAST MODIFIED TIME 
                    watcher.NotifyFilter = NotifyFilters.LastWrite;

                    watcher.Changed += new FileSystemEventHandler(OnChanged);
                    watcher.Created += new FileSystemEventHandler(OnChanged);

                    // ENABLE THE WATCHER TO RAISE EVENTS
                    watcher.EnableRaisingEvents = true;

                    // STOP WATCHING FOR CHANGES
                    watcher.EnableRaisingEvents = false;

                }
                catch (Exception)
                {
                    // MAY NOT HAVE PERMISSION TO ACCESS FILE DIRECTORY
                }
            }
        }

        private static void OnChanged(Object source, FileSystemEventArgs e)
        {
            Console.WriteLine("Suspicious file created or modified: " + e.FullPath);
        }


        public static string GetFileHash(Process process)
        {
            string hash = "";
            try
            {
                string pathToFile = process.MainModule.FileName;
                using (var sha256 = SHA256.Create())
                {

                    using (var stream = new FileStream(pathToFile, FileMode.Open, FileAccess.Read))
                    {
                        byte[] fileHash = sha256.ComputeHash(stream);
                        hash = BitConverter.ToString(fileHash).Replace("-", string.Empty);

                    }
                }
            }

            catch (Exception)
            {

            }
            return hash;
        }

        public static string QueryVirusTotal(string fileHash)
        {
            using (var client = new WebClient())
            {
                // URL FOR THE API REQUEST
                string apiUrl = $"https://www.virustotal.com/api/v3/files/{fileHash}";

                // SET THE API KEY HEADER
                client.Headers.Add("x-apikey", api_key);

                try
                {
                    // SEND API REQUEST AND GET THE RESPONSE
                    string response = client.DownloadString(apiUrl);

                    //GET DETECTION DETAILS 
                    using (JsonDocument jdoc = JsonDocument.Parse(response))
                    {
                        JsonElement data = jdoc.RootElement.GetProperty("data");

                        // GET THE last_analysis_results OBJECT
                        JsonElement lastAnalysisResults = data.GetProperty("attributes").GetProperty("last_analysis_results");

                        int numDetected = 0;
                        int numAntivirus = 0;

                        // ITERATE THROUGH EACH PROPERTY OF THE last_analysis_results OBJECT
                        foreach (JsonProperty antivirusProgram in lastAnalysisResults.EnumerateObject())
                        {
                            numAntivirus++;

                            if (antivirusProgram.Value.GetProperty("category").GetString() == "malicious")
                            {
                                numDetected++;
                            }
                        }

                        // MAKE THE RESPONSE STRING

                        if (numAntivirus > 0)
                        {
                            response = $"Detected by {numDetected} out of {numAntivirus} antivirus programs";
                        }
                        else
                        {
                            response = "No antivirus programs were able to check the file";
                        }
                    }


                    // RETURN THE RESPONSE
                    return response;
                }

                catch (WebException ex)
                {
                    Console.WriteLine("Could not query virus total " + ex.Message);
                }
                return "";
            }

        }
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, int size, out int lpNumberOfBytesRead);
    }


}
