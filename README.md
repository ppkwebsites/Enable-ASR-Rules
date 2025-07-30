ASR RulesDescriptionEnable-ASRRules.ps1 is a PowerShell script that enables seven specific Attack Surface Reduction (ASR) rules in Block mode for Microsoft Defender Antivirus on Windows systems. These rules enhance security by mitigating common attack vectors, making it ideal for securing systems used for browsing, gaming, and LAN file transfers (e.g., SMB sharing). The script requires administrative privileges, checks prerequisites (e.g., Microsoft Defender status, pending reboots), clears existing ASR rules to avoid conflicts, and verifies the application of the rules, logging all actions for transparency.FeaturesEnables Seven ASR Rules in Block Mode:Block abuse of exploited vulnerable signed drivers.
Block credential stealing from lsass.exe.
Block execution of potentially obfuscated scripts.
Block persistence through WMI event subscription.
Use advanced protection against ransomware.
Block rebooting machine in Safe Mode (preview).
Block use of copied or impersonated system tools (preview).

Prerequisite Checks:Verifies administrative privileges (exits if not elevated).
Checks for pending system reboots, exiting if a reboot is required.
Ensures Microsoft Defender Antivirus is enabled and Real-time Protection is active (enables it if disabled).

Robust Configuration:Clears existing ASR rules to prevent conflicts.
Applies each rule individually with immediate verification.
Restarts the Windows Defender service (WinDefend) to ensure changes take effect.

Logging and Verification:Logs all actions to C:\Users\ppk\Desktop\ASR-Log.txt for troubleshooting.
Performs final verification of all rules, reporting their status.
Provides clear success/failure feedback with actionable suggestions (e.g., reboot if needed).

Safe Execution: Modifies only ASR settings, with error handling to prevent system disruption.
Companion Script: Works with check.ps1 to verify ASR rule status after execution.

UsagePrerequisites:PowerShell 5.1 or later (tested with PowerShell 7.5.2 and Windows PowerShell 5.1).
Windows 11 (tested on IoT Enterprise LTSC; compatible with other Windows 10/11 editions).
Administrative privileges (required).
Microsoft Defender Antivirus enabled (no conflicting third-party antivirus).

Running the Script:powershell

cd C:\Path\To\Script
.\Enable-ASRRules.ps1

If script execution is restricted:powershell

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

Sample Output:

Microsoft Defender is active (AntivirusEnabled: True, RealTimeProtectionEnabled: True).
Clearing existing ASR rules...
Existing ASR rules cleared.
Enabling ASR rules...
Enabling Block abuse of exploited vulnerable signed drivers (56A863A9-875E-4185-98A7-B882C64B5CE5)...
Successfully enabled: Block abuse of exploited vulnerable signed drivers (56A863A9-875E-4185-98A7-B882C64B5CE5) - Block mode
...
Final verification of applied ASR rules...
Rule active: Block abuse of exploited vulnerable signed drivers (56A863A9-875E-4185-98A7-B882C64B5CE5) - Block mode
...
Windows Defender service restarted successfully.
ASR rules configuration completed.
All specified ASR rules have been successfully enabled.
Please run check.ps1 to verify the updated ASR rule status.
Log saved to C:\Users\ppk\Desktop\ASR-Log.txt

Verification:Run check.ps1 (companion script) to confirm all seven ASR rules are enabled in Block mode.
Check the log file at C:\Users\ppk\Desktop\ASR-Log.txt for detailed execution details.

CompatibilityPowerShell: Windows PowerShell 5.1 or PowerShell 7.0+ (tested with 7.5.2).
Operating System: Windows 11 IoT Enterprise LTSC (compatible with Windows 10/11).
Use Case: Optimized for systems used for browsing, gaming, and LAN file transfers (SMB sharing).

NotesRun as Administrator: Required to modify Defender settings and restart services.
Reboot Handling: Exits if a reboot is pending; a reboot may be needed if the WinDefend service restart fails.
Defender Dependency: Requires Microsoft Defender to be active (disables conflicting third-party antivirus if present).
Companion Script: Use with check.ps1 to verify ASR rule status before and after execution.
Log File: Review ASR-Log.txt for troubleshooting or to confirm successful rule application.

LicenseThis project is licensed under the MIT License:

MIT License

Copyright (c) 2025 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Implementation NotesCreate LICENSE File:In your GitHub repository, create a LICENSE file (or LICENSE.md).
Copy the MIT License text above, replacing [Your Name] with your name or organization and ensuring the year is 2025.

Add README:Save the content above as README.md in the repository (or a subdirectory for Enable-ASRRules.ps1 if separate from check.ps1).
Ensure Enable-ASRRules.ps1 is in the repository root or a subdirectory.

Test the Script:Save Enable-ASRRules.ps1 to C:\Users\ppk\Desktop\Enable-ASRRules.ps1 (use Notepad, UTF-8 encoding, “All Files” type).
Run as Administrator:powershell

cd C:\Users\ppk\Desktop
.\Enable-ASRRules.ps1

Verify with check.ps1:powershell

.\check.ps1

Check C:\Users\ppk\Desktop\ASR-Log.txt for logs.

Troubleshooting:If errors occur, share:Output of .\Enable-ASRRules.ps1.
Contents of C:\Users\ppk\Desktop\ASR-Log.txt.
Output of Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled.
Output of Get-Service -Name WinDefend.

Check for Group Policy/MDM restrictions:powershell

Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AttackSurfaceReductionRules" -ErrorAction SilentlyContinue
