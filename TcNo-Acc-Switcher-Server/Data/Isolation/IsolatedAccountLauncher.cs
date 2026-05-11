using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.JSInterop;
using Newtonsoft.Json;
using TcNo_Acc_Switcher_Globals;
using TcNo_Acc_Switcher_Server.Pages.General;
using SteamSettings = TcNo_Acc_Switcher_Server.Data.Settings.Steam;
using BasicSettings = TcNo_Acc_Switcher_Server.Data.Settings.Basic;

namespace TcNo_Acc_Switcher_Server.Data.Isolation
{
    [SupportedOSPlatform("windows")]
    public static class IsolatedAccountLauncher
    {
        private static readonly Lang Lang = Lang.Instance;
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("TcNo Account Switcher isolated account credentials");
        private static string StorePath => Path.Join(Globals.UserDataFolder, "Isolation", "accounts.json");

        private sealed class IsolatedAccount
        {
            public string Platform { get; set; } = "";
            public string AccountId { get; set; } = "";
            public string WindowsUser { get; set; } = "";
            public string ProtectedPassword { get; set; } = "";
        }

        [JSInvokable]
        public static bool LaunchSteam(string steamId = "", string args = "")
        {
            if (!OperatingSystem.IsWindows()) return false;
            if (SteamSettings.StartSilent) args += " -silent";
            if (SteamSettings.OldUi) args += " -vgui";
            return Launch("Steam", string.IsNullOrWhiteSpace(steamId) ? "new" : steamId, SteamSettings.Exe(), args);
        }

        [JSInvokable]
        public static bool LaunchEpic(string accountId = "", string args = "")
        {
            if (!OperatingSystem.IsWindows()) return false;
            var originalPlatform = CurrentPlatform.IsInit ? CurrentPlatform.FullName : "";
            if (originalPlatform != "Epic Games") new CurrentPlatform().CurrentPlatformInit("Epic Games");

            var id = string.IsNullOrWhiteSpace(accountId) ? "new" : accountId;
            var result = Launch("Epic Games", id, BasicSettings.Exe(), args);
            if (!string.IsNullOrWhiteSpace(originalPlatform) && originalPlatform != "Epic Games")
                new CurrentPlatform().CurrentPlatformInit(originalPlatform);
            return result;
        }

        public static bool Launch(string platform, string accountId, string exePath, string args = "")
        {
            if (!OperatingSystem.IsWindows()) return false;
            if (!File.Exists(exePath))
            {
                _ = GeneralInvocableFuncs.ShowToast("error", Lang["Toast_StartingPlatformFailed", new { platform }], renderTo: "toastarea");
                return false;
            }

            var account = GetOrCreateAccount(platform, accountId);
            var password = GetPassword(account);
            if (password == "") return false;

            if (!EnsureWindowsUser(account.WindowsUser, password)) return false;

            var started = Globals.StartProgramAsUser(exePath, account.WindowsUser, password, args);
            if (!started && Globals.IsAdministrator)
            {
                password = ResetPassword(account);
                if (password != "") started = Globals.StartProgramAsUser(exePath, account.WindowsUser, password, args);
            }

            _ = started
                ? GeneralInvocableFuncs.ShowToast("info", $"Starting isolated {platform} as {account.WindowsUser}", renderTo: "toastarea")
                : GeneralInvocableFuncs.ShowToast("error", $"Failed to start isolated {platform}. Check the log.", renderTo: "toastarea");
            return started;
        }

        private static string GetPassword(IsolatedAccount account)
        {
            try
            {
                return Unprotect(account.ProtectedPassword);
            }
            catch (Exception e)
            {
                Globals.WriteToLog($"Could not decrypt isolated account password for {account.WindowsUser}.", e);
                if (Globals.IsAdministrator) return ResetPassword(account);

                _ = GeneralInvocableFuncs.ShowToast("error", "Restart as administrator to repair this isolated account.", renderTo: "toastarea");
                return "";
            }
        }

        private static string ResetPassword(IsolatedAccount account)
        {
            var password = GeneratePassword();
            if (WindowsUserExists(account.WindowsUser))
                if (!RunNetUser($"user \"{account.WindowsUser}\" \"{password}\"", "reset isolated user password")) return "";

            account.ProtectedPassword = Protect(password);
            var accounts = LoadAccounts();
            var index = accounts.FindIndex(x => x.Platform == account.Platform && x.AccountId == account.AccountId);
            if (index >= 0) accounts[index] = account;
            else accounts.Add(account);
            SaveAccounts(accounts);
            return password;
        }

        private static IsolatedAccount GetOrCreateAccount(string platform, string accountId)
        {
            var accounts = LoadAccounts();
            var existing = accounts.FirstOrDefault(x => x.Platform == platform && x.AccountId == accountId);
            if (existing != null) return existing;

            var password = GeneratePassword();
            var account = new IsolatedAccount
            {
                Platform = platform,
                AccountId = accountId,
                WindowsUser = BuildUserName(platform, accountId),
                ProtectedPassword = Protect(password)
            };
            accounts.Add(account);
            SaveAccounts(accounts);
            return account;
        }

        private static bool EnsureWindowsUser(string userName, string password)
        {
            if (WindowsUserExists(userName)) return true;
            if (!Globals.IsAdministrator)
            {
                _ = GeneralInvocableFuncs.ShowToast("error", "Restart as administrator to create isolated Windows users.", renderTo: "toastarea");
                return false;
            }

            if (!RunNetUser($"user \"{userName}\" \"{password}\" /add", "create isolated user")) return false;
            _ = RunNetUser($"user \"{userName}\" /passwordchg:no", "disable isolated user password changes");
            return true;
        }

        private static bool WindowsUserExists(string userName) => RunNetUser($"user \"{userName}\"", "check isolated user", false);

        private static bool RunNetUser(string arguments, string description, bool logErrors = true)
        {
            try
            {
                using var proc = new Process();
                proc.StartInfo = new ProcessStartInfo
                {
                    FileName = "net.exe",
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                proc.Start();
                var output = proc.StandardOutput.ReadToEnd();
                var error = proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                if (proc.ExitCode == 0) return true;
                if (logErrors) Globals.WriteToLog($"net.exe failed to {description}: {output}\n{error}");
                return false;
            }
            catch (Exception e)
            {
                if (logErrors) Globals.WriteToLog($"net.exe failed to {description}.", e);
                return false;
            }
        }

        private static List<IsolatedAccount> LoadAccounts()
        {
            if (!File.Exists(StorePath)) return new List<IsolatedAccount>();
            return JsonConvert.DeserializeObject<List<IsolatedAccount>>(File.ReadAllText(StorePath)) ?? new List<IsolatedAccount>();
        }

        private static void SaveAccounts(List<IsolatedAccount> accounts)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(StorePath) ?? Globals.UserDataFolder);
            File.WriteAllText(StorePath, JsonConvert.SerializeObject(accounts, Formatting.Indented));
        }

        private static string BuildUserName(string platform, string accountId)
        {
            var hash = Globals.GetSha256HashString(platform + ":" + accountId);
            return ("TcNo" + hash[..16]).ToLowerInvariant();
        }

        private static string GeneratePassword()
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=";
            var bytes = RandomNumberGenerator.GetBytes(32);
            return new string(bytes.Select(b => chars[b % chars.Length]).ToArray());
        }

        [SupportedOSPlatform("windows")]
        private static string Protect(string value) => Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.CurrentUser));

        [SupportedOSPlatform("windows")]
        private static string Unprotect(string value) => Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(value), Entropy, DataProtectionScope.CurrentUser));
    }
}
