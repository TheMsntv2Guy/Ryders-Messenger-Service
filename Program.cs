using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Text.Unicode;
using System.Threading.Tasks;
using System.Transactions;
using System.Xml;
using System.Xml.Linq;
using static System.Net.Mime.MediaTypeNames;

public static class XmlHelper
{
    private static readonly XmlWriterSettings WriterSettings = new XmlWriterSettings
    {
        Indent = true,
        IndentChars = "  ",
        NewLineChars = "\n",
        NewLineHandling = NewLineHandling.Replace
    };

    public static async Task<string> FormatXmlAsync(string xml)
    {
        return await Task.Run(() =>
        {
            try
            {
                using (var reader = new StringReader(xml))
                using (var xmlReader = XmlReader.Create(reader))
                using (var stringWriter = new StringWriter())
                {
                    using (var xmlWriter = XmlWriter.Create(stringWriter, WriterSettings))
                    {
                        xmlWriter.WriteNode(xmlReader, true);
                    }
                    return stringWriter.ToString();
                }
            }
            catch
            {
                return xml; // Return original if formatting fails
            }
        });
    }

    public static async Task<XDocument> ParseXmlAsync(string xml)
    {
        return await Task.Run(() =>
        {
            try
            {
                return XDocument.Parse(xml);
            }
            catch
            {
                return null;
            }
        });
    }
}

class MsnServer
{
    // Notification Server (NS) configuration
    private const int NsPort = 1863;
    private const string UsersDbFile = "users.json";
    private const string ContactsDbFile = "contacts.json";

    // Switchboard Server (SB) configuration
    private const int SbPort = 1864;

    private static List<User> _users = new List<User>();
    private static readonly object _userLock = new object();
    private static List<Contact> _contacts = new List<Contact>();
    private static Dictionary<string, User> _activeUsers = new Dictionary<string, User>();
    private static Dictionary<string, SwitchboardSession> _sessions = new Dictionary<string, SwitchboardSession>();


    public static async Task Main()
    {
        // Load databases
        await LoadDatabases();

        // Start Notification Server
        var nsTask = Task.Run(() => StartNotificationServer());
        Console.WriteLine("[+] Starting Notification Server...");

        // Start Switchboard Server
        var sbTask = Task.Run(() => StartSwitchboardServer());
        Console.WriteLine("[+] Starting Switchboard Server...");

        // Start HTTP SOAP Server
        var httpTask = Task.Run(() => HttpSoapServer.Start());
        Console.WriteLine("[+] Starting HTTP SOAP Server...");

        await Task.WhenAll(nsTask, sbTask, httpTask);


    }

    private static async Task StartNotificationServer()
    {
        TcpListener listener = new TcpListener(IPAddress.Any, NsPort);
        listener.Start();
        Console.WriteLine($"[+] Notification Server started on port {NsPort}");

        while (true)
        {
            TcpClient client = await listener.AcceptTcpClientAsync();
            Console.WriteLine("[*] NS Client connected");
            _ = HandleNsClientAsync(client);
        }
    }

    private static async Task StartSwitchboardServer()
    {
        TcpListener listener = new TcpListener(IPAddress.Any, SbPort);
        listener.Start();
        Console.WriteLine($"[+] Switchboard Server started on port {SbPort}");

        while (true)
        {
            TcpClient client = await listener.AcceptTcpClientAsync();
            Console.WriteLine("[*] SB Client connected");
            _ = HandleSbClientAsync(client);
        }
    }

    #region Database Operations
    private static async Task LoadDatabases()
    {
        try
        {
            if (File.Exists(UsersDbFile))
            {
                var json = await File.ReadAllTextAsync(UsersDbFile);
                _users = JsonSerializer.Deserialize<List<User>>(json) ?? new List<User>();
            }
            else
            {
                _users = new List<User>();
                await SaveUsers();
            }

            if (File.Exists(ContactsDbFile))
            {
                var json = await File.ReadAllTextAsync(ContactsDbFile);
                _contacts = JsonSerializer.Deserialize<List<Contact>>(json) ?? new List<Contact>();
            }
            else
            {
                _contacts = new List<Contact>();
                await SaveContacts();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading databases: {ex.Message}");
            _users = new List<User>();
            _contacts = new List<Contact>();
        }
    }

    private static async Task SaveUsers()
    {
        var json = JsonSerializer.Serialize(_users, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(UsersDbFile, json);
    }

    private static async Task SaveContacts()
    {
        var json = JsonSerializer.Serialize(_contacts, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(ContactsDbFile, json);
    }
    #endregion

    #region User and Contact Operations
    internal static User GetUserByEmail(string email)
    {
        // Normalize the email by converting to lowercase and handling both @hotmail.com and @a.com
        string normalizedEmail = email.ToLower();

        // If the email ends with @a.com, also check for @hotmail.com equivalent
        if (normalizedEmail.EndsWith("@a.com"))
        {
            string hotmailEmail = normalizedEmail.Replace("@a.com", "@hotmail.com");
            return _users.FirstOrDefault(u =>
                u.Email.Equals(normalizedEmail, StringComparison.OrdinalIgnoreCase) ||
                u.Email.Equals(hotmailEmail, StringComparison.OrdinalIgnoreCase));
        }

        return _users.FirstOrDefault(u => u.Email.Equals(normalizedEmail, StringComparison.OrdinalIgnoreCase));
    }

    internal static User GetUserById(int id)
    {
        return _users.FirstOrDefault(u => u.Id == id);
    }

    internal static List<Contact> GetContacts(int userId, string list = null)
    {
        return _contacts.Where(c =>
            c.UserId == userId &&
            (list == null || c.List.Equals(list, StringComparison.OrdinalIgnoreCase))
        ).ToList();
    }

    internal static List<Contact> GetReverseContacts(int contactId, string list = "FL")
    {
        return _contacts.Where(c =>
            c.ContactId == contactId &&
            c.List.Equals(list, StringComparison.OrdinalIgnoreCase)
        ).ToList();
    }
    #endregion

    #region Notification Server (NS) Handlers

    private static string ExtractCommandFromXml(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        Console.WriteLine($"[RAW INPUT] {input}");

        // Extract all XML content (between < and >)
        var extractedXml = new StringBuilder();
        int lastClosingBracketPos = -1;
        bool inTag = false;
        int tagStartPos = 0;

        for (int i = 0; i < input.Length; i++)
        {
            if (input[i] == '<')
            {
                inTag = true;
                tagStartPos = i;
            }
            else if (input[i] == '>' && inTag)
            {
                extractedXml.Append(input.Substring(tagStartPos, i - tagStartPos + 1));
                inTag = false;
                lastClosingBracketPos = i; // Track the last closing '>'
            }
        }

        // If XML was found, log it
        if (extractedXml.Length > 0)
        {
            string xmlContent = extractedXml.ToString();
            Console.WriteLine($"[EXTRACTED XML CONTENT]\n{FormatXml(xmlContent)}");
        }

        // Check if there's any non-XML text after the last '>'
        if (lastClosingBracketPos >= 0 && lastClosingBracketPos < input.Length - 1)
        {
            string remainingText = input.Substring(lastClosingBracketPos + 1).Trim();
            if (!string.IsNullOrEmpty(remainingText))
            {
                Console.WriteLine($"[CLEAN COMMAND] {remainingText}");
                return remainingText;
            }
        }

        // If no trailing command, return XML (if any) or original input
        return extractedXml.Length > 0 ? extractedXml.ToString() : input;
    }

    private static void UpdateUserConnection(string email, TcpClient client, int version)
    {
        lock (_userLock)
        {
            if (_activeUsers.TryGetValue(email, out var user))
            {
                user.ActiveConnection = client;
                user.ActiveStream = client?.GetStream();
                user.Version = version;
                user.LastActivity = DateTime.UtcNow;
                Console.WriteLine($"[CONN] Updated connection for {email} (v{version})");
            }
        }
    }

    // Helper method to clean up a user connection
    private static void CleanupUserConnection(string email)
    {
        lock (_userLock)
        {
            if (_activeUsers.TryGetValue(email, out var user))
            {
                try
                {
                    user.ActiveStream?.Dispose();
                    user.ActiveConnection?.Dispose();
                }
                catch { }

                user.ActiveConnection = null;
                user.ActiveStream = null;
                Console.WriteLine($"[CONN] Cleaned up connection for {email}");
            }
        }
    }

    private static string FormatXml(string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            return doc.ToString();
        }
        catch (XmlException)
        {
            return xml; // Return as-is if not valid XML
        }
    }

    private static async Task HandleNsClientAsync(TcpClient client)
    {
        using NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[1024];
        User currentUser = null;
        int version = 0;
        StringBuilder incomingData = new StringBuilder();

        while (client.Connected)
        {
            int byteCount;
            try
            {
                byteCount = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (byteCount == 0) break;
            }
            catch (IOException)
            {
                break; // Client disconnected
            }

            incomingData.Append(Encoding.UTF8.GetString(buffer, 0, byteCount));

            string data = incomingData.ToString();
            string[] lines = data.Split(new[] { "\r\n" }, StringSplitOptions.None);

            incomingData.Clear();
            if (!data.EndsWith("\r\n"))
            {
                incomingData.Append(lines[^1]);
                lines = lines[..^1];
            }



            foreach (string rawLine in lines)
            {
                string cleanCommand = ExtractCommandFromXml(rawLine);

                // Print the cleaned command (without XML if it was separated)
                Console.WriteLine($"[NS> CLEAN COMMAND] {cleanCommand}");

                string[] parts = cleanCommand.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;

                string command = parts[0];
                string trid = parts.Length > 1 ? parts[1] : "0";

                switch (command)
                {
                    case "OUT":
                        await HandleOutCommand(stream, currentUser);
                        return; // End the connection

                    case "VER":
                        version = await HandleVerCommand(stream, parts, version);
                        break;

                    case "CVR":
                        await SendAsync(stream, $"CVR {trid} 1.0.0000 1.0.0000 1.0.0000 http://example.com/download http://example.com/info\r\n");
                        break;

                    case "XFR":
                        await HandleXfrCommand(stream, currentUser, version, parts);
                        break;

                    case "ADC":
                        await HandleAdcCommand(stream, currentUser, parts);
                        break;

                    case "PRP":
                        await HandlePrpCommand(stream, currentUser, parts, version);
                        break;

                    case "ADG":
                        await HandleAdgCommand(stream, currentUser, parts, version);
                        break;

                    case "ADL":
                        await HandleAdlCommand(stream, parts);
                        break;

                    case "PNG":
                        Console.WriteLine("[PNG] Ping received");
                        await SendAsync(stream, $"QNG {trid}\r\n");
                        break;

                    case "BLP":
                        await HandleBlpCommand(stream, parts);
                        break;

                    case "UUX":
                        await HandleUuxCommand(stream, parts, currentUser, _activeUsers, _contacts, rawLine);
                        break;

                    case "INF":
                        await SendAsync(stream, $"INF {trid} MD5\r\n");
                        break;

                    case "USR":
                        var (updatedUser, updatedVersion) = await HandleUsrCommand(stream, parts, currentUser, version);
                        currentUser = updatedUser;
                        version = updatedVersion;
                        break;

                    case "REG":
                        await HandleRegCommand(stream, currentUser, parts, version);
                        break;

                    case "SYN":
                        await HandleSynCommand(stream, currentUser, version, trid, parts.Length > 2 ? parts[2] : "0");
                        break;

                    case "URL":
                        await HandleURLCommand(stream, parts, version);
                        break;

                    case "CHG":
                        await HandleChgCommand(stream, currentUser, parts, version);
                        break;

                    case "REA":
                        await HandleReaCommand(stream, currentUser, parts, version);
                        break;

                    case "ADD":
                        await HandleAddCommand(stream, currentUser, parts);
                        break;

                    case "GCF":
                        await HandleGcfCommand(stream, parts);
                        break;

                    default:
                        break;
                }
            }
        }

        // Clean up on disconnect
        if (currentUser != null)
        {
            _activeUsers.Remove(currentUser.Email);
            await NotifyBuddiesOfPresence(currentUser, "FLN");
        }
        Console.WriteLine("[*] NS Client disconnected");
    }

    private static async Task HandleRegCommand(NetworkStream stream, User currentUser, string[] parts, int version)
    {
        if (currentUser == null || parts.Length < 3)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string transactionId = parts[1];
        string groupIdentifier = parts[2];
        string newGroupName = parts.Length > 3 ? parts[3] : string.Empty;
        string unusedZero = parts.Length > 4 ? parts[4] : "0"; // MSNP7-9 only

        // Validate transaction ID is a number
        if (!int.TryParse(transactionId, out _))
        {
            await SendAsync(stream, "OUT\r\n");
            return;
        }

        // Check if we're using MSNP13+ where this command was removed
        if (version >= 13)
        {
            await SendAsync(stream, "OUT\r\n");
            return;
        }

        try
        {
            // URL decode the new group name
            string decodedNewGroupName = WebUtility.UrlDecode(newGroupName);

            // Validate new group name length (127 bytes max, URL encoded characters count as 3 bytes)
            if (Encoding.UTF8.GetByteCount(newGroupName) > 127)
            {
                Console.WriteLine($"[REG] New group name too long: {newGroupName}");
                await SendAsync(stream, "OUT\r\n"); // Disconnect client for extremely long names
                return;
            }

            // Initialize groups list if null
            currentUser.Groups = currentUser.Groups ?? new List<Group>();

            Group groupToRename = null;
            bool usingGuid = false;

            // Check if we're using GUIDs (ABCHMigrated: 1)
            if (version >= 10 && currentUser.Status.Contains("ABCHMigrated: 1"))
            {
                // Validate GUID format
                if (!Guid.TryParse(groupIdentifier, out _))
                {
                    Console.WriteLine($"[REG] Invalid GUID format: {groupIdentifier}");
                    await SendAsync(stream, "OUT\r\n");
                    return;
                }

                groupToRename = currentUser.Groups.FirstOrDefault(g => g.Guid?.Equals(groupIdentifier, StringComparison.OrdinalIgnoreCase) ?? false);
                usingGuid = true;
            }
            else
            {
                // Using numeric ID
                if (!int.TryParse(groupIdentifier, out int groupId))
                {
                    Console.WriteLine($"[REG] Invalid group ID: {groupIdentifier}");
                    await SendAsync(stream, $"224 {transactionId}\r\n");
                    return;
                }

                // Check for out-of-bounds group IDs
                if (groupId < 0 || groupId > currentUser.Groups.Count)
                {
                    Console.WriteLine($"[REG] Out-of-bounds group ID: {groupId}");
                    await SendAsync(stream, "OUT\r\n"); // Disconnect client for invalid IDs
                    return;
                }

                groupToRename = currentUser.Groups.FirstOrDefault(g => g.Id == groupId);
            }

            // Check if group exists
            if (groupToRename == null)
            {
                Console.WriteLine($"[REG] Group doesn't exist: {groupIdentifier}");
                await SendAsync(stream, $"224 {transactionId}\r\n");
                return;
            }

            // Check if new name already exists
            if (currentUser.Groups.Any(g =>
                g.Name.Equals(decodedNewGroupName, StringComparison.OrdinalIgnoreCase) &&
                g.Id != groupToRename.Id))
            {
                Console.WriteLine($"[REG] Group name already exists: {decodedNewGroupName}");
                await SendAsync(stream, $"215 {transactionId}\r\n");
                return;
            }

            // Save old name for logging
            string oldName = groupToRename.Name;

            // Rename the group
            groupToRename.Name = decodedNewGroupName;
            await MsnServer.SaveUserToDatabase(currentUser);

            // Send response based on protocol version
            if (version >= 10)
            {
                // MSNP10+ response
                string responseIdentifier = usingGuid ? groupToRename.Guid : groupToRename.Id.ToString();
                await SendAsync(stream, $"REG {transactionId} {responseIdentifier} {newGroupName}\r\n");
            }
            else
            {
                // MSNP7-9 includes list version and trailing zero
                int listVersion = currentUser.Groups.Count;
                await SendAsync(stream, $"REG {transactionId} {listVersion} {groupToRename.Id} {newGroupName} 0\r\n");
            }

            Console.WriteLine($"[REG] Renamed group from '{oldName}' to '{decodedNewGroupName}' for {currentUser.Email}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REG ERROR] {ex.Message}");
            await SendAsync(stream, $"911 {transactionId}\r\n");
        }
    }

    private static async Task HandleAdgCommand(NetworkStream stream, User currentUser, string[] parts, int version)
    {
        if (currentUser == null || parts.Length < 3)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string transactionId = parts[1];
        string groupName = parts[2];
        string unusedZero = parts.Length > 3 ? parts[3] : "0"; // MSNP7-9 only

        // Validate transaction ID is a number
        if (!int.TryParse(transactionId, out _))
        {
            await SendAsync(stream, "OUT\r\n");
            return;
        }

        // Check if we're using MSNP13+ where this command was removed
        if (version >= 13)
        {
            await SendAsync(stream, "OUT\r\n");
            return;
        }

        try
        {
            // URL decode the group name
            string decodedGroupName = WebUtility.UrlDecode(groupName);

            // Validate group name length (61 bytes max, URL encoded characters count as 3 bytes)
            if (Encoding.UTF8.GetByteCount(groupName) > 61)
            {
                Console.WriteLine($"[ADG] Group name too long: {groupName}");
                await SendAsync(stream, $"229 {transactionId}\r\n");
                return;
            }

            // Check maximum number of groups (30)
            if (currentUser.Groups?.Count >= 30)
            {
                Console.WriteLine($"[ADG] User {currentUser.Email} has reached group limit (30)");
                await SendAsync(stream, $"223 {transactionId}\r\n");
                return;
            }

            // Initialize groups list if null
            currentUser.Groups = currentUser.Groups ?? new List<Group>();

            // Check if group already exists
            if (currentUser.Groups.Any(g => g.Name.Equals(decodedGroupName, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine($"[ADG] Group already exists: {decodedGroupName}");
                await SendAsync(stream, $"215 {transactionId}\r\n");
                return;
            }

            // Create new group
            int newGroupId = currentUser.Groups.Count > 0 ? currentUser.Groups.Max(g => g.Id) + 1 : 1;
            var newGroup = new Group
            {
                Id = newGroupId,
                Name = decodedGroupName
            };

            currentUser.Groups.Add(newGroup);
            await MsnServer.SaveUserToDatabase(currentUser);

            // Send response based on protocol version
            if (version >= 10)
            {
                // MSNP10+ with ABCHMigrated: 1 uses GUIDs
                if (currentUser.Version >= 10 && currentUser.Status.Contains("ABCHMigrated: 1"))
                {
                    string groupGuid = Guid.NewGuid().ToString();
                    await SendAsync(stream, $"ADG {transactionId} {groupName} {groupGuid}\r\n");
                }
                // MSNP10 without ABCHMigrated: 1 uses numeric IDs
                else
                {
                    await SendAsync(stream, $"ADG {transactionId} {groupName} {newGroupId}\r\n");
                }
            }
            else
            {
                // MSNP7-9 includes list version and trailing zero
                int listVersion = currentUser.Groups.Count;
                await SendAsync(stream, $"ADG {transactionId} {listVersion} {groupName} {newGroupId} 0\r\n");
            }

            Console.WriteLine($"[ADG] Created group '{decodedGroupName}' (ID: {newGroupId}) for {currentUser.Email}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ADG ERROR] {ex.Message}");
            await SendAsync(stream, $"911 {transactionId}\r\n");
        }
    }

    private static async Task<int> HandleVerCommand(NetworkStream stream, string[] parts, int currentVersion)
    {
        string trid = parts[1];
        if (parts.Length >= 3)
        {
            var versions = parts.Skip(2)
                .Where(v => v.StartsWith("MSNP"))
                .Select(v => new
                {
                    Original = v,
                    Number = int.TryParse(v.Substring(4), out int n) ? n : 0
                })
                .OrderByDescending(v => v.Number)
                .ToList();

            if (versions.Any())
            {
                string latestVersion = versions.First().Original;
                string response = $"VER {trid} {latestVersion}\r\n";
                await SendAsync(stream, response);
                return versions.First().Number;
            }
        }
        await SendAsync(stream, string.Join(" ", parts) + "\r\n");
        return currentVersion;
    }

    private static async Task<int> HandleURLCommand(NetworkStream stream, string[] parts, int currentVersion)
    {
        string trid = parts[1];
        string MD5_AUTH_URL = "https://loginnet.passport.com/ppsecure/md5auth.srf?lc=1033";
        string INBOX_DIRECTORY = "/cgi-bin/HoTMaiL";
        string COMPOSE_DIRECTORY = "/cgi-bin/compose";
        string COMPOSE_DIRECTORY_TARGET = "/cgi-bin/compose?mailto=1&to=";
        string SETUP_MSN_MOBILE = "http://mobile.msn.com/hotmail/confirmUser.asp?URL=%2Fmessengerok.htm&mobID=1";
        string EDIT_MEMBER_DIRECTORY_PROFILE = "http://members.msn.com/Edit.asp?lc=1033";
        string MANAGE_N2P_ACCOUNT = "https://ocs.net2phone.com/account/msnaccount/default.asp?_lang=";
        string OPEN_CHAT_ROOMS = " http://chat.msn.com/Messenger.msnw?lc=1033";

        switch (parts[2])
        {
            case "INBOX":
                await SendAsync(stream, $"URL {trid} {INBOX_DIRECTORY} {MD5_AUTH_URL} 2\r\n");
                break;

            case "COMPOSE":
                if (parts.Length>2) // I think theres a better way on doing this
                {
                    string email = parts[3];
                    await SendAsync(stream, $"URL {trid} {COMPOSE_DIRECTORY_TARGET}{email} {MD5_AUTH_URL} 2\r\n");
                    break;
                }
                await SendAsync(stream, $"URL {trid} {COMPOSE_DIRECTORY} {MD5_AUTH_URL} 2\r\n");
                break;

            case "MOBILE":
                await SendAsync(stream, $"URL {trid} {SETUP_MSN_MOBILE} {MD5_AUTH_URL} 961\r\n");
                break;

            case "PROFILE":
                await SendAsync(stream, $"URL {trid} {EDIT_MEMBER_DIRECTORY_PROFILE} {MD5_AUTH_URL} 4236\r\n");
                break;

            case "N2PACCOUNT":
                string lang = parts[3];
                await SendAsync(stream, $"URL {trid} {MANAGE_N2P_ACCOUNT}{lang} {MD5_AUTH_URL} 2823\r\n");
                break;

            case "CHAT":
                await SendAsync(stream, $"URL {trid} {OPEN_CHAT_ROOMS} {MD5_AUTH_URL} 2260\r\n");
                break;
        }
        return 0;
    }

    private static async Task<int> HandleBlpCommand(NetworkStream stream, string[] parts)
    {
        string response = string.Join(" ", parts) + "\r\n";
        await SendAsync(stream, response);
        return 0;
    }

    private static async Task<int> HandleAdlCommand(NetworkStream stream, string[] parts)
    {
        string trid = parts[1];
        string response = $"ADL {trid} OK\r\n";
        await SendAsync(stream, response);
        return 0;
    }

    private static async Task MonitorConnections()
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromMinutes(1));
            CleanupInactiveConnections();
        }
    }

    private static void CleanupInactiveConnections()
    {
        lock (_userLock)
        {
            var toRemove = _activeUsers
                .Where(kvp => !kvp.Value.IsActive)
                .ToList();

            foreach (var user in toRemove)
            {
                Console.WriteLine($"[PRESENCE] {user.Key} timed out");
                user.Value.ActiveConnection?.Dispose();
                _activeUsers.Remove(user.Key);

                // Notify their contacts they went offline
                _ = NotifyBuddiesOfPresence(user.Value, "FLN");
            }
        }
    }

    private static (long high, long low) UuidToHighLow(string uuidString)
    {
        if (!Guid.TryParse(uuidString, out var uuid))
        {
            uuid = Guid.NewGuid();
        }

        var bytes = uuid.ToByteArray();
        return (BitConverter.ToInt64(bytes, 0), BitConverter.ToInt64(bytes, 8));
    }
public static void UpdateActiveUser(User user, TcpClient connection = null)
    {
        lock (_userLock)
        {
            if (connection != null)
            {
                user.ActiveConnection = connection;
                user.ActiveStream = connection?.GetStream();
            }

            user.LastActivity = DateTime.UtcNow;
            _activeUsers[user.Email] = user;

            bool isConnected = user.ActiveConnection?.Connected ?? false;
            Console.WriteLine($"[PRESENCE] Updated {user.Email} " +
                            $"(Connected: {isConnected} " +
                            $"LastActive: {(DateTime.UtcNow - user.LastActivity).TotalSeconds}s ago)");
        }
    }

    private static async Task<(User updatedUser, int updatedVersion)> HandleUsrCommand(
        NetworkStream stream, string[] parts, User currentUser, int version)
    {
        try
        {
            string cleanRequest = ExtractCommandFromXml(string.Join(" ", parts));
            parts = cleanRequest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string transactionId = parts.Length > 1 ? parts[1] : "0";

            Console.WriteLine($"[USR] Handling USR command: {string.Join(" ", parts)}");

            if (parts.Length >= 5 && (parts[2] == "TWN" || parts[2] == "SSO" || parts[2] == "MD5") && parts[3] == "I")
            {
                string email = parts[4];

                // For MD5 I requests, replace @hotmail.com with @a.com for database lookup
                if (parts[2] == "MD5")
                {
                    email = email.Replace("@hotmail.com", "@a.com");
                }

                Console.WriteLine($"[USR] Initial authentication for {email}");

                // Handle existing connection
                if (_activeUsers.TryGetValue(email, out var existingUser))
                {
                    Console.WriteLine($"[USR] Existing session found for {email}, forcing logout");
                    await ForceLogoutExistingUser(existingUser, email);
                }

                currentUser = GetUserByEmail(email);
                if (currentUser == null)
                {
                    Console.WriteLine($"[USR ERROR] User {email} not found");
                    await SendAsync(stream, $"911 {transactionId}\r\n");
                    return (null, version);
                }

                // Handle different authentication methods
                switch (parts[2])
                {
                    case "TWN":
                        Console.WriteLine($"[USR] TWN authentication for {email}");
                        await SendAsync(stream, $"USR {transactionId} TWN S ct=1,rver=1,wp=FS_40SEC_0_COMPACT,lc=1,id=1\r\n");
                        break;

                    case "SSO":
                        Console.WriteLine($"[USR] SSO authentication for {email}");
                        string mbiKey = GenerateMbiKey();
                        await SendAsync(stream, $"USR {transactionId} SSO S MBI_KEY_OLD 8CLhG/xfgYZ7TyRQ/jIAWyDmd/w4R4GF2yKLS6tYrnjzi4cFag/Nr+hxsfg5zlCf\r\n");

                        if (version >= 13)
                        {
                            await SendShieldsPolicy(stream);
                        }
                        break;

                    case "MD5":
                        Console.WriteLine($"[USR] MD5 authentication for {email}");
                        // For MD5 response, use the original @hotmail.com domain
                        string responseEmail = parts[4]; // Keep original email with @hotmail.com
                        await SendAsync(stream, $"USR {transactionId} MD5 S 1013928519.693957190 {responseEmail}\r\n");
                        break;
                }
            }
            else if (parts.Length >= 4 && (parts[2] == "TWN" || parts[2] == "SSO" || parts[2] == "MD5") && parts[3] == "S")
            {
                if (currentUser == null)
                {
                    Console.WriteLine($"[USR ERROR] No current user for authentication");
                    await SendAsync(stream, $"911 {transactionId}\r\n");
                    return (null, version);
                }

                string token = parts.Length > 4 ? parts[4] : string.Empty;
                Console.WriteLine($"[USR] Successful authentication for {currentUser.Email}");

                // Get client endpoint info
                var ipEndpoint = stream.Socket.RemoteEndPoint as IPEndPoint;
                string ip = ipEndpoint?.Address.ToString().Replace("::ffff:", "") ?? "0.0.0.0";
                int port = ipEndpoint?.Port ?? 0;

                // Update user connection info
                lock (_userLock)
                {
                    currentUser.Version = version;
                    currentUser.Status = "NLN";
                    currentUser.LastActivity = DateTime.UtcNow;
                    currentUser.ActiveStream = stream;
                    currentUser.ActiveConnection = new TcpClient { Client = stream.Socket };
                    _activeUsers[currentUser.Email] = currentUser;
                }

                Console.WriteLine($"[CONN] {currentUser.Email} connected from {ip}:{port}");

                if (parts[2] == "MD5")
                {
                    if (version == 2) // MSNP2
                    {
                        await SendAsync(stream, $"USR {transactionId} OK {currentUser.Email} {currentUser.FriendlyName}\r\n");
                    }
                    else // MSNP6+
                    {
                        await SendAsync(stream, $"USR {transactionId} OK {currentUser.Email} {currentUser.FriendlyName} 1 0\r\n");
                    }
                }
                else
                {
                    await SendAuthenticationResponse(stream, currentUser, version, transactionId, token, ip, port);
                }

                // Send initial status to client
                await SendInitialStatusToClient(stream, currentUser, version);

                // Notify contacts of new online status
                await NotifyBuddiesOfPresence(currentUser, "NLN");
            }
            else if (cleanRequest.Contains("SHA"))
            {
                if (currentUser != null)
                {
                    Console.WriteLine($"[USR] SHA authentication for {currentUser.Email}");
                    await SendAsync(stream, $"USR {transactionId} OK {currentUser.Email} 0 0\r\n");
                }
                else
                {
                    Console.WriteLine($"[USR ERROR] No current user for SHA authentication");
                    await SendAsync(stream, $"911 {transactionId}\r\n");
                }
            }

            return (currentUser, version);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[USR ERROR] Exception in HandleUsrCommand: {ex.Message}");
            return (null, version);
        }
    }
    private static async Task ForceLogoutExistingUser(User existingUser, string email)
    {
        try
        {
            // Notify contacts that user went offline first
            await NotifyBuddiesOfPresence(existingUser, "FLN");

            // Then close the connection
            if (existingUser.ActiveConnection?.Connected == true)
            {
                try
                {
                    await SendAsync(existingUser.ActiveStream, "OUT OTH\r\n");
                }
                catch { }

                try
                {
                    existingUser.ActiveStream?.Dispose();
                    existingUser.ActiveConnection?.Dispose();
                }
                catch { }
            }

            // Remove from active users
            lock (_userLock)
            {
                _activeUsers.Remove(email);
                existingUser.ActiveConnection = null;
                existingUser.ActiveStream = null;
                existingUser.Status = "FLN";
            }

            Console.WriteLine($"[FORCE LOGOUT] Successfully logged out {email}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FORCE LOGOUT ERROR] Error forcing logout for {email}: {ex.Message}");

            // Ensure user is removed from active users even if logout fails
            lock (_userLock)
            {
                _activeUsers.Remove(email);
                existingUser.ActiveConnection?.Dispose();
                existingUser.ActiveStream?.Dispose();
                existingUser.Status = "FLN";
            }
        }
    }

    private static string GenerateMbiKey()
    {
        byte[] randomBytes = new byte[48];
        new Random().NextBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    private static async Task SendShieldsPolicy(NetworkStream stream)
    {
        string shields = @"<Policies>
	<Policy type=""SHIELDS"" checksum=""D9705A71BA841CB38955822E048970C3""><config> <shield>\
<cli maj=""7"" min=""0"" minbld=""0"" maxbld=""9999"" deny="" "" /></shield> <block></block></config></Policy>
	<Policy type=""ABCH"" checksum=""03DC55910A9CB79133F1576221A80346""><policy><set id=""push"" service=""ABCH"" priority=""200"">\
      <r id=""pushstorage"" threshold=""180000"" />    </set><set id=""delaysup"" service=""ABCH"" priority=""150"">\
  <r id=""whatsnew"" threshold=""1800000"" />  <r id=""whatsnew_storage_ABCH_delay"" timer=""1800000"" />\
  <r id=""whatsnewt_link"" threshold=""900000"" trigger=""QueryActivities"" /></set>  <c id=""PROFILE_Rampup"">100</c></policy></Policy>
	<Policy type=""ERRORRESPONSETABLE"" checksum=""6127EEDCE860F45C1692896F5248AF6F""><Policy> <Feature type=""3"" name=""P2P"">\
  <Entry hr=""0x81000398"" action=""3""/>  <Entry hr=""0x82000020"" action=""3""/> </Feature> <Feature type=""4"">\
  <Entry hr=""0x81000440"" /> </Feature> <Feature type=""6"" name=""TURN"">  <Entry hr=""0x8007274C"" action=""3"" />\
  <Entry hr=""0x82000020"" action=""3"" />  <Entry hr=""0x8007274A"" action=""3"" /> </Feature></Policy></Policy>
	<Policy type=""P2P"" checksum=""815D4F1FF8E39A85F1F97C4B16C45177""><ObjStr SndDly=""1"" /></Policy>
</Policies>"; // Your existing shields XML
        byte[] shieldData = Encoding.UTF8.GetBytes(shields);
        await SendAsync(stream, $"GCF 0 {shieldData.Length}\r\n");
        await stream.WriteAsync(shieldData, 0, shieldData.Length);
    }

    private static async Task SendAuthenticationResponse(
        NetworkStream stream, User user, int version,
        string transactionId, string token, string ip, int port)
    {
        await SendAsync(stream, $"USR {transactionId} OK {user.Email} {user.FriendlyName} 0 0\r\n");

        var (high, low) = UuidToHighLow(user.UUID);
        var messageTemplate = BuildProfileMessage(user, version, token, ip, port, high, low);
        var messageLength = Encoding.UTF8.GetByteCount(messageTemplate);

        await SendAsync(stream, $"MSG Hotmail Hotmail {messageLength}\r\n{messageTemplate}");

        if (version >= 11)
        {
            await SendAsync(stream, "SBS 0 null\r\n");
        }

        if (version >= 16)
        {
            await SendAsync(stream, $"UBX 1:{user.Email} 0\r\n");
        }
    }

    private static string BuildProfileMessage(User user, int version, string token,
        string ip, int port, long high, long low)
    {
        var sb = new StringBuilder();
        sb.AppendLine("MIME-Version: 1.0");
        sb.AppendLine("Content-Type: text/x-msmsgsprofile; charset=UTF-8");
        sb.AppendLine($"LoginTime: {DateTimeOffset.UtcNow.ToUnixTimeSeconds()}");
        sb.AppendLine("EmailEnabled: 0");
        sb.AppendLine($"MemberIdHigh: {high}");
        sb.AppendLine($"MemberIdLow: {low}");
        sb.AppendLine("lang_preference: 1033");
        sb.AppendLine($"preferredEmail: {user.Email}");
        sb.AppendLine("country: GB");
        sb.AppendLine("PostalCode: 42069");
        sb.AppendLine("Gender: U");
        sb.AppendLine("Kid: 0");
        sb.AppendLine("Age: 21");
        sb.AppendLine("BDayPre: 1");
        sb.AppendLine("Birthday: 1999");
        sb.AppendLine("Wallet: ");
        sb.AppendLine("Flags: 536872513");
        sb.AppendLine("sid: 1027");
        sb.AppendLine("sid: 0");
        sb.AppendLine("kv: 0");
        sb.AppendLine($"MSPAuth: Tokenherebitch");
        sb.AppendLine($"ClientIP: {ip}");
        sb.AppendLine($"ClientPort: {port}");
        sb.AppendLine("ABCHMigrated: 1");
        sb.AppendLine("MPOPEnabled: 0");

        if (version >= 8)
        {
            sb.AppendLine($"ClientIP: {ip}");
            sb.AppendLine($"ClientPort: {port}");
        }

        if (version >= 10)
        {
            sb.AppendLine("BetaInvites: 1");
        }

        sb.AppendLine();
        return sb.ToString();
    }


    private static async Task HandleUuxCommand(
        NetworkStream stream,
        string[] parts,
        User currentUser,
        Dictionary<string, User> activeUsers,
        List<Contact> contacts,
        string fullCommand)
    {
        if (parts.Length < 2)
        {
            await SendAsync(stream, "OUT\r\n");
            return;
        }

        string transactionID = parts[1];

        // Check if the transaction ID is a number
        if (!int.TryParse(transactionID, out _))
        {
            await SendAsync(stream, "OUT\r\n");
            return;
        }

        // Get payload from the command (get after first \r\n)
        string payload = fullCommand.Contains("\r\n")
            ? fullCommand.Split(new[] { "\r\n" }, 2, StringSplitOptions.None)[1]
            : string.Empty;

        try
        {
            // Print the raw payload
            Console.WriteLine($"[UUX PAYLOAD RECEIVED]");
            Console.WriteLine(payload);

            // Parse XML payload if present (non-blocking)
            if (!string.IsNullOrEmpty(payload))
            {
                var parseTask = XmlHelper.ParseXmlAsync(payload);
                var formatTask = XmlHelper.FormatXmlAsync(payload);

                await Task.WhenAll(parseTask, formatTask);

                var doc = await parseTask;
                var formattedXml = await formatTask;

                if (doc != null)
                {
                    Console.WriteLine($"[UUX PARSED XML]\n{formattedXml}");
                    currentUser.CustomStatus = payload;

                    // Extract specific data if needed
                    var dataElement = doc.Root?.Element("Data");
                    if (dataElement != null)
                    {
                        Console.WriteLine($"[UUX DATA ELEMENT]\n{dataElement}");
                    }
                }
                else
                {
                    Console.WriteLine("[UUX] Payload is not valid XML, treating as plain text");
                    currentUser.CustomStatus = payload;
                }
            }

            int payloadLength = Encoding.UTF8.GetByteCount(payload);

            // Send acknowledgement
            await SendAsync(stream, $"UUX {transactionID} 0\r\n");

            // Get contacts in parallel
            var getContactsTask = Task.Run(() =>
                contacts.Where(c => c.UserId == currentUser.Id && c.List == "FL").ToList());

            // Process contacts in background
            _ = Task.Run(async () =>
            {
                var userContacts = await getContactsTask;
                Console.WriteLine($"[UUX] Broadcasting to {userContacts.Count} contacts");

                var notificationTasks = new List<Task>();

                foreach (var contact in userContacts)
                {
                    notificationTasks.Add(NotifyContactAsync(contact, currentUser, payload, payloadLength, activeUsers));
                }

                await Task.WhenAll(notificationTasks);
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UUX ERROR] {ex.Message}");
            await SendAsync(stream, $"911 {transactionID}\r\n");
        }
    }

    private static async Task NotifyContactAsync(
        Contact contact,
        User currentUser,
        string payload,
        int payloadLength,
        Dictionary<string, User> activeUsers)
    {
        try
        {
            var contactUser = GetUserById(contact.ContactId);
            if (contactUser != null && activeUsers.TryGetValue(contactUser.Email, out var onlineContact))
            {
                if (onlineContact.Version >= 11 && onlineContact.ActiveConnection?.Connected == true)
                {
                    var contactStream = onlineContact.ActiveConnection.GetStream();
                    Console.WriteLine($"[UUX] Notifying {contactUser.Email} with payload length {payloadLength}");
                    await SendAsync(contactStream, $"UBX {currentUser.Email} {payloadLength}\r\n{payload}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UUX NOTIFICATION ERROR] {contact.ContactId}: {ex.Message}");
        }
    }

    private static async Task HandleXfrCommand(NetworkStream stream, User currentUser, int version, string[] parts)
    {
        if (parts.Length < 3)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string transactionId = parts[1];
        string serverType = parts[2];

        switch (serverType)
        {
            case "NS":
                await HandleXfrNsCommand(stream, currentUser, version, transactionId);
                break;

            case "SB":
                await HandleXfrSbCommand(stream, currentUser, version, transactionId);
                break;

            default:
                await SendAsync(stream, $"911 {transactionId}\r\n");
                break;
        }
    }

    private static async Task HandleXfrNsCommand(NetworkStream stream, User currentUser, int version, string trid)
    {
        // For forced soft reset
        if (trid == "0")
        {
            await SendAsync(stream, "XFR 0 NS 0\r\n");
            return;
        }

        string serverAddress = "77.68.90.130:1863"; // Using localhost for testing

        string response;
        if (version < 3)
        {
            response = $"XFR {trid} NS {serverAddress}\r\n";
        }
        else if (version < 7)
        {
            response = $"XFR {trid} NS {serverAddress} 0\r\n";
        }
        else if (version < 13)
        {
            response = $"XFR {trid} NS {serverAddress} 0 {serverAddress}\r\n";
        }
        else
        {
            response = $"XFR {trid} NS {serverAddress} U D\r\n";
        }

        await SendAsync(stream, response);
    }

    private static async Task HandleXfrSbCommand(NetworkStream stream, User currentUser, int version, string trid)
    {
        if (currentUser == null)
        {
            await SendAsync(stream, $"911 {trid}\r\n");
            return;
        }

        // Generate a random cookie for the session
        string cookie = $"{DateTime.UtcNow.Ticks}.{new Random().Next(1000, 9999)}";
        string serverAddress = "77.68.90.130:1864"; // SB server address

        string response;
        if (version < 13)
        {
            response = $"XFR {trid} SB {serverAddress} CKI {cookie}\r\n";
        }
        else
        {
            response = $"XFR {trid} SB {serverAddress} CKI {cookie} U messenger.msn.com\r\n";
        }

        // Create a new switchboard session
        var session = new SwitchboardSession
        {
            SessionId = Guid.NewGuid().ToString(),
            Caller = currentUser.Email,
            Participants = new List<string> { currentUser.Email },
            AuthTicket = cookie
        };

        _sessions[cookie] = session;
        await SendAsync(stream, response);
    }

    private static async Task HandleGcfCommand(NetworkStream stream, string[] parts)
    {
        {
            string trid = parts[1];
            if (parts.Length >= 3)
            {
                string requestedFile = parts[2];
                if (requestedFile.Equals("Shields.xml", StringComparison.OrdinalIgnoreCase))
                {
                    string shields = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n" +
                                   "<config>\r\n" +
                                   "  <shield><cli maj=\"7\" min=\"0\" minbld=\"0\" maxbld=\"9999\" deny=\" \" /></shield>\r\n" +
                                   "  <block></block>\r\n" +
                                   "</config>";

                    byte[] shieldData = Encoding.UTF8.GetBytes(shields);
                    string header = $"GCF {trid} Shields.xml {shieldData.Length}\r\n";
                    await SendRawAsync(stream, header, shieldData);
                }
                else
                {
                    await SendAsync(stream, $"GCF {trid} 0\r\n");
                }
            }
        }
    }
    #endregion

    #region Switchboard Server (SB) Handlers
    private static async Task HandleSbClientAsync(TcpClient client)
    {
        using NetworkStream stream = client.GetStream();
        byte[] buffer = new byte[1024];
        SwitchboardSession session = null;
        User currentUser = null;
        StringBuilder incomingData = new StringBuilder();

        while (client.Connected)
        {
            int byteCount;
            try
            {
                byteCount = await stream.ReadAsync(buffer, 0, buffer.Length);
                if (byteCount == 0) break;
            }
            catch (IOException)
            {
                break; // Client disconnected
            }

            incomingData.Append(Encoding.UTF8.GetString(buffer, 0, byteCount));

            string data = incomingData.ToString();
            string[] lines = data.Split(new[] { "\r\n" }, StringSplitOptions.None);

            incomingData.Clear();
            if (!data.EndsWith("\r\n"))
            {
                incomingData.Append(lines[^1]);
                lines = lines[..^1];
            }

            foreach (string rawLine in lines)
            {
                string request = rawLine.Trim();
                if (string.IsNullOrEmpty(request)) continue;

                Console.WriteLine($"[SB>] {request}");

                string[] parts = request.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;

                string command = parts[0];
                string trid = parts.Length > 1 ? parts[1] : "0";

                switch (command)
                {
                    case "USR":
                        session = await HandleSbUsrCommand(stream, parts, session);
                        break;

                    case "ANS":
                        session = await HandleAnsCommand(stream, parts, session);
                        break;

                    case "CAL":
                        session = await HandleCalCommand(stream, parts, session);
                        break;

                    case "JOI":
                        session = await HandleJoiCommand(stream, parts, session);
                        break;

                    case "IRO":
                        session = await HandleIroCommand(stream, parts, session);
                        break;

                    case "MSG":
                        session = await HandleMsgCommand(stream, parts, session);
                        break;

                    case "BYE":
                        session = await HandleByeCommand(stream, parts, session);
                        break;

                    case "OUT":
                        await HandleSbOutCommand(stream, session);
                        return; // End the connection

                    default:
                        Console.WriteLine($"[SB] Unknown command: {command}");
                        break;
                }
            }
        }

        // Clean up on disconnect
        if (session != null)
        {
            await HandleSessionDisconnect(session);
        }
        Console.WriteLine("[*] SB Client disconnected");
    }


    private static async Task<SwitchboardSession> HandleSbUsrCommand(
        NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (parts.Length < 4)
        {
            await SendSbResponse(stream, "911", "Invalid USR command");
            return session;
        }

        string trid = parts[1];
        string email = parts[2].Replace("@hotmail.com", "@a.com");
        string cookie = parts[3];

        Console.WriteLine($"[SB USR] Email: {email}, Cookie: {cookie}");

        // Verify the cookie matches an existing session
        if (!_sessions.TryGetValue(cookie, out session))
        {
            Console.WriteLine($"[SB USR] Invalid cookie: {cookie}");
            // Don't send any response for invalid cookies (as per requirements)
            return null;
        }

        // Get user details
        var user = GetUserByEmail(email);
        if (user == null)
        {
            Console.WriteLine($"[SB USR] User not found: {email}");
            // Don't send any response for invalid users
            return null;
        }

        // Store display name
        session.DisplayNames[email] = user.FriendlyName ?? email.Split('@')[0];

        // Send success response
        Console.WriteLine($"[SB USR] Authenticated {email} with cookie {cookie}");
        await SendSbResponse(stream, "USR", trid, "OK", email, WebUtility.UrlEncode(user.FriendlyName ?? email.Split('@')[0]));

        return session;
    }

    private static async Task<SwitchboardSession> HandleCalCommand(
        NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (parts.Length < 3)
        {
            await SendSbResponse(stream, "911", "Invalid CAL command");
            return session;
        }

        string trid = parts[1];
        string emailToInvite = parts[2];
        var callerEmail = session?.Caller;
        var callerUser = callerEmail != null ? GetUserByEmail(callerEmail) : null;

        // Create new session if this is the initial call
        if (session == null)
        {
            string sessionId = Guid.NewGuid().ToString();
            string cookie = sessionId; // Use sessionId as cookie

            session = new SwitchboardSession
            {
                SessionId = sessionId,
                Caller = callerEmail,
                AuthTicket = cookie,
                Participants = new List<string> { callerEmail },
                DisplayNames = new Dictionary<string, string>(),
                CallerClient = stream
            };

            if (callerUser != null)
            {
                session.DisplayNames[callerEmail] = callerUser.FriendlyName ?? callerEmail.Split('@')[0];
            }

            // Store session with cookie as key
            _sessions[cookie] = session;
            Console.WriteLine($"[CAL] Created new session {sessionId} for caller {callerEmail}");
        }

        // Send RINGING response to caller
        await SendSbResponse(stream, "CAL", trid, "RINGING", session.SessionId);

        // Notify the invited user if they're online
        if (_activeUsers.TryGetValue(emailToInvite, out var invitedUser))
        {
            try
            {
                var invitedStream = invitedUser.ActiveStream;
                await SendAsync(invitedStream,
                    $"RNG {session.SessionId} 77.68.90.130:1864 CKI {session.AuthTicket} " +
                    $"{callerUser?.Email ?? "unknown"} {callerUser?.FriendlyName ?? "Unknown User"}\r\n");

                Console.WriteLine($"[CAL] Sent RNG to {emailToInvite} for session {session.SessionId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CAL] Error notifying {emailToInvite}: {ex.Message}");
            }
        }

        return session;
    }

    private static async Task<SwitchboardSession> HandleAnsCommand(
        NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (parts.Length < 5)
        {
            await SendSbResponse(stream, "911", "Invalid ANS command");
            return session;
        }

        string trid = parts[1];
        string email = parts[2];
        string cookie = parts[3];
        string sessionId = parts[4];

        Console.WriteLine($"[SB ANS] Email: {email}, Cookie: {cookie}, SessionId: {sessionId}");

        // Find session by cookie
        if (!_sessions.TryGetValue(cookie, out session))
        {
            Console.WriteLine($"[SB ANS] Session not found for cookie: {cookie}");
            await SendSbResponse(stream, "OUT");
            return null;
        }

        // Verify session ID matches
        if (session.SessionId != sessionId)
        {
            Console.WriteLine($"[SB ANS] Session ID mismatch (expected {session.SessionId}, got {sessionId})");
            await SendSbResponse(stream, "OUT");
            return null;
        }

        // Get user details
        var user = GetUserByEmail(email);
        if (user == null)
        {
            Console.WriteLine($"[SB ANS] User not found: {email}");
            await SendSbResponse(stream, "OUT");
            return null;
        }

        // Add user to session participants
        if (!session.Participants.Contains(email))
        {
            session.Participants.Add(email);
            session.DisplayNames[email] = user.FriendlyName ?? email.Split('@')[0];
        }

        // Set the participant's stream
        session.Client = stream;

        // Send IRO messages for existing participants (excluding self)
        await SendIroMessages(stream, session, email, parts);

        // Send success response
        await SendSbResponse(stream, "ANS", trid, "OK");
        Console.WriteLine($"[SB ANS] {email} successfully joined session {sessionId}");

        return session;
    }

    private static async Task SendIroMessages(NetworkStream stream, SwitchboardSession session,
        string joiningUser, string[] parts)
    {
        if (session == null || session.Participants.Count == 0)
            return;

        int totalParticipants = session.Participants.Count;
        int currentIndex = 1;
        string trid = parts[1];

        foreach (var participant in session.Participants)
        {
            string displayName = session.GetUserDisplayName(participant);
            await SendSbResponse(
                stream,
                "IRO",
                trid,  // Include the transaction ID
                currentIndex.ToString(),
                totalParticipants.ToString(),
                participant,
                WebUtility.UrlEncode(displayName));

            currentIndex++;
        }
    }

    // Helper methods
    private static string GenerateSessionId()
    {
        return $"{DateTime.UtcNow.Ticks}.{new Random().Next(1000, 9999)}";
    }

    private static async Task<SwitchboardSession> HandleJoiCommand(
        NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (session == null || parts.Length < 3)
        {
            await SendSbResponse(stream, "911", "Invalid JOI command");
            return session; // Return unchanged session
        }

        string email = parts[1];
        string displayName = parts[2];

        if (!session.Participants.Contains(email))
        {
            session.Participants.Add(email);
            session.DisplayNames[email] = displayName;
        }

        await BroadcastToSession(session, $"JOI {email} {displayName}");
        return session; // Return the modified session
    }

    private static async Task<SwitchboardSession> HandleIroCommand(
    NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (session == null || parts.Length < 5)
        {
            await SendSbResponse(stream, "911", "Invalid IRO command");
            return session;
        }

        string current = parts[1];
        string total = parts[2];
        string email = parts[3];
        string displayName = parts[4];

        await SendSbResponse(stream, "IRO", current, total, email, displayName);
        return session;
    }

    private static async Task<SwitchboardSession> HandleMsgCommand(
        NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (session == null || parts.Length < 4)
        {
            await SendSbResponse(stream, "911", "Invalid MSG command");
            return session;
        }

        string trid = parts[1];
        string senderEmail = parts[2];
        string lengthStr = parts[3];

        if (!int.TryParse(lengthStr, out int payloadLength) || payloadLength <= 0)
        {
            await SendSbResponse(stream, "911", "Invalid message length");
            return session;
        }

        // Read the full payload (headers + content)
        byte[] payloadBuffer = new byte[payloadLength];
        int bytesRead = 0;
        while (bytesRead < payloadLength)
        {
            int read = await stream.ReadAsync(payloadBuffer, bytesRead, payloadLength - bytesRead);
            if (read == 0) throw new IOException("Connection closed while reading message payload");
            bytesRead += read;
        }

        string payload = Encoding.UTF8.GetString(payloadBuffer);
        Console.WriteLine($"[SB MSG] Payload from {senderEmail}:\n{payload}");

        // Parse MIME headers and content
        var headers = new Dictionary<string, string>();
        string content = string.Empty;
        bool inHeaders = true;

        using (var reader = new StringReader(payload))
        {
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                if (inHeaders)
                {
                    if (string.IsNullOrEmpty(line))
                    {
                        inHeaders = false;
                        continue;
                    }

                    int colon = line.IndexOf(':');
                    if (colon > 0)
                    {
                        string key = line.Substring(0, colon).Trim();
                        string value = line.Substring(colon + 1).Trim();
                        headers[key] = value;
                    }
                }
                else
                {
                    content += line + "\r\n";
                }
            }
        }

        // Handle different message types
        if (headers.TryGetValue("Content-Type", out var contentType))
        {
            if (contentType.Contains("text/x-msmsgscontrol"))
            {
                // Typing notification
                if (headers.TryGetValue("TypingUser", out var typingUser))
                {
                    Console.WriteLine($"[TYPING] {typingUser} is typing");
                    await BroadcastTypingNotification(session, typingUser);
                }
            }
            else if (contentType.Contains("text/plain"))
            {
                // Regular chat message
                Console.WriteLine($"[MSG] Content: {content}");
                await BroadcastChatMessage(session, senderEmail, headers, content);
            }
        }

        // Send acknowledgement
        await SendSbResponse(stream, "MSG", trid, "OK");

        return session;
    }

    private static async Task BroadcastTypingNotification(
        SwitchboardSession session, string typingUser)
    {
        if (session == null) return;

        var typingNotification = new StringBuilder();
        typingNotification.AppendLine("MIME-Version: 1.0");
        typingNotification.AppendLine("Content-Type: text/x-msmsgscontrol");
        typingNotification.AppendLine($"TypingUser: {typingUser}");
        typingNotification.AppendLine(); // Empty line to end headers

        string payload = typingNotification.ToString();
        int length = Encoding.UTF8.GetByteCount(payload);

        foreach (var participant in session.Participants)
        {
            if (participant == typingUser) continue;

            if (_activeUsers.TryGetValue(participant, out var user) &&
                user.ActiveConnection?.Connected == true)
            {
                try
                {
                    var participantStream = user.ActiveStream;
                    await SendAsync(participantStream, $"MSG {typingUser} {length}\r\n");
                    await SendAsync(participantStream, payload);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[TYPING BROADCAST ERROR] {participant}: {ex.Message}");
                }
            }
        }
    }

    private static async Task BroadcastChatMessage(
        SwitchboardSession session,
        string senderEmail,
        Dictionary<string, string> headers,
        string content)
    {
        if (session == null) return;

        // Reconstruct the message with headers
        var message = new StringBuilder();
        foreach (var header in headers)
        {
            message.AppendLine($"{header.Key}: {header.Value}");
        }
        message.AppendLine(); // Empty line between headers and content
        message.Append(content);

        string fullMessage = message.ToString();
        int messageLength = Encoding.UTF8.GetByteCount(fullMessage);

        foreach (var participant in session.Participants)
        {
            if (participant == senderEmail) continue;

            if (_activeUsers.TryGetValue(participant, out var user) &&
                user.ActiveConnection?.Connected == true)
            {
                try
                {
                    var participantStream = user.ActiveStream;
                    await SendAsync(participantStream, $"MSG {senderEmail} {messageLength}\r\n");
                    await SendAsync(participantStream, fullMessage);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[MSG BROADCAST ERROR] {participant}: {ex.Message}");
                }
            }
        }
    }

    private static async Task<SwitchboardSession> HandleByeCommand(
        NetworkStream stream, string[] parts, SwitchboardSession session)
    {
        if (session == null)
        {
            await SendSbResponse(stream, "911", "No active session");
            return null;
        }

        string email = parts.Length > 1 ? parts[1] : string.Empty;

        if (!string.IsNullOrEmpty(email))
        {
            session.Participants.Remove(email);
            await BroadcastToSession(session, $"BYE {email}");

            if (session.Participants.Count == 0)
            {
                await HandleSessionDisconnect(session);
                return null; // Return null to indicate session should be cleared
            }
        }
        else
        {
            await HandleSessionDisconnect(session);
            return null; // Return null to indicate session should be cleared
        }

        await SendSbResponse(stream, "BYE", "OK");
        return session; // Return the (possibly modified) session
    }

    private static async Task HandleSbOutCommand(NetworkStream stream, SwitchboardSession session)
    {
        if (session != null)
        {
            await HandleSessionDisconnect(session);
        }
        await SendSbResponse(stream, "OUT");
    }

    private static async Task HandleSessionDisconnect(SwitchboardSession session)
    {
        await BroadcastToSession(session, "OUT");

        if (!string.IsNullOrEmpty(session.AuthTicket) && _sessions.ContainsKey(session.AuthTicket))
        {
            _sessions.Remove(session.AuthTicket);
        }

        try
        {
            if (session.Client != null)
            {
                session.Client.Dispose();
            }
        }
        catch { }

        try
        {
            if (session.CallerClient != null)
            {
                session.CallerClient.Dispose();
            }
        }
        catch { }

        Console.WriteLine($"[SB] Session {session.SessionId} ended");
    }
    #endregion

    #region Common Methods
    private static async Task SendAsync(NetworkStream stream, string message)
    {
        Console.WriteLine($"[NS<] {message.Trim()}");
        byte[] response = Encoding.UTF8.GetBytes(message);
        await stream.WriteAsync(response, 0, response.Length);
    }

    private static async Task SendRawAsync(NetworkStream stream, string header, byte[] body)
    {
        Console.WriteLine($"[NS<] {header.Trim()} (+{body.Length} bytes)");
        byte[] headerBytes = Encoding.UTF8.GetBytes(header);
        await stream.WriteAsync(headerBytes, 0, headerBytes.Length);
        await stream.WriteAsync(body, 0, body.Length);
    }

    private static async Task SendSbResponse(NetworkStream stream, params string[] parts)
    {
        string response = string.Join(" ", parts) + "\r\n";
        Console.WriteLine($"[SB<] {response.Trim()}");
        byte[] responseBytes = Encoding.UTF8.GetBytes(response);
        await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
    }

    private static async Task BroadcastToSession(SwitchboardSession session, string message)
    {
        if (session == null) return;

        Console.WriteLine($"[SB Broadcast] {message}");
        byte[] messageBytes = Encoding.UTF8.GetBytes(message + "\r\n");

        foreach (var participant in session.Participants)
        {
            try
            {
                if (session.Client != null)
                {
                    await session.Client.WriteAsync(messageBytes, 0, messageBytes.Length);
                }
                if (session.CallerClient != null)
                {
                    await session.CallerClient.WriteAsync(messageBytes, 0, messageBytes.Length);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SB Broadcast Error] {ex.Message}");
            }
        }
    }


    private static async Task BroadcastMessageToSession(
        SwitchboardSession session,
        string senderEmail,
        Dictionary<string, string> headers,
        string content)
    {
        if (session == null) return;

        // Reconstruct the full message with headers
        var messageBuilder = new StringBuilder();
        foreach (var header in headers)
        {
            messageBuilder.AppendLine($"{header.Key}: {header.Value}");
        }
        messageBuilder.AppendLine(); // Empty line between headers and content
        messageBuilder.Append(content);

        string fullMessage = messageBuilder.ToString();
        int messageLength = Encoding.UTF8.GetByteCount(fullMessage);

        foreach (var participant in session.Participants)
        {
            if (participant == senderEmail) continue;

            if (_activeUsers.TryGetValue(participant, out var user) &&
                user.ActiveConnection?.Connected == true)
            {
                try
                {
                    var participantStream = user.ActiveStream;
                    // Send MSG command line
                    await SendAsync(participantStream, $"MSG {senderEmail} {messageLength}\r\n");
                    // Send the full payload
                    await SendAsync(participantStream, fullMessage);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SB Broadcast Error] Failed to send to {participant}: {ex.Message}");
                }
            }
        }
    }

    private static async Task HandleOutCommand(NetworkStream stream, User user)
    {
        if (user != null)
        {
            Console.WriteLine($"[OUT] {user.Email} is logging out");
            await NotifyBuddiesOfPresence(user, "FLN");
            _activeUsers.Remove(user.Email);
            user.Status = "FLN";
            user.ActiveConnection = null;
        }

        await SendAsync(stream, "OUT\r\n");
    }

    public static async Task SendPendingNotifications(User user)
    {
        if (user.PendingNotifications.Count == 0) return;

        Console.WriteLine($"[STATUS DELIVERY] Sending {user.PendingNotifications.Count} " +
                         $"pending notifications to {user.Email}");

        foreach (var notification in user.PendingNotifications)
        {
            try
            {
                await NotifyBuddiesOfChanges(user, notification.Status,
                    notification.Capabilities, notification.MsnObject);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[STATUS DELIVERY ERROR] Failed to send pending " +
                                $"notification to {user.Email}: {ex.Message}");
            }
        }

        user.PendingNotifications.Clear();
    }

    private static async Task HandleChgCommand(NetworkStream stream, User currentUser, string[] parts, int version)
    {
        if (currentUser == null || parts.Length < 3)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string transactionId = parts[1];
        string newStatus = parts[2];
        string capabilities = parts.Length > 3 ? parts[3] : "0";
        string msnObject = parts.Length > 4 ? WebUtility.UrlDecode(parts[4]) : string.Empty;

        // Validate status
        string[] validStatuses = { "NLN", "BSY", "IDL", "BRB", "AWY", "PHN", "LUN", "HDN", "FLN" };
        if (!validStatuses.Contains(newStatus))
        {
            await SendAsync(stream, $"911 {transactionId}\r\n");
            return;
        }

        // Store previous state for comparison
        string oldStatus = currentUser.Status;
        string oldMsnObject = currentUser.MsnObjectPfp;

        // Update user state
        currentUser.Status = newStatus;
        currentUser.Capabilities = capabilities;
        currentUser.LastActivity = DateTime.UtcNow;

        // Process MSN Object if provided
        if (!string.IsNullOrEmpty(msnObject))
        {
            try
            {
                if (msnObject.StartsWith("<msnobj"))
                {
                    // Basic XML validation
                    var doc = XDocument.Parse(msnObject);
                    if (doc.Root?.Name == "msnobj")
                    {
                        currentUser.MsnObjectPfp = msnObject;
                        Console.WriteLine($"[MSNOBJ] Valid object for {currentUser.Email}");
                    }
                    else
                    {
                        Console.WriteLine($"[MSNOBJ] Invalid root element");
                        currentUser.MsnObjectPfp = string.Empty;
                    }
                }
                else
                {
                    Console.WriteLine($"[MSNOBJ] Doesn't start with <msnobj");
                    currentUser.MsnObjectPfp = string.Empty;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[MSNOBJ] Error parsing: {ex.Message}");
                currentUser.MsnObjectPfp = string.Empty;
            }
        }

        // Update presence tracking
        UpdateActiveUser(currentUser);

        // Send acknowledgement (format varies by protocol version)
        string ackResponse = version >= 10 ?
            $"CHG {transactionId} {newStatus}\r\n" :
            $"CHG {transactionId} {newStatus} {capabilities}\r\n";

        await SendAsync(stream, ackResponse);
        Console.WriteLine($"[CHG] {currentUser.Email} changed status from {oldStatus} to {newStatus}");

        // Notify contacts if status changed or MSN Object changed
        if (oldStatus != newStatus || oldMsnObject != currentUser.MsnObjectPfp)
        {
            // If new status is HDN, notify contacts as FLN (appear offline)
            string notificationStatus = newStatus == "HDN" ? "FLN" : newStatus;
            await NotifyBuddiesOfPresence(currentUser, notificationStatus);
        }

        // Debug output
        PrintPresenceStatus();
    }

    public static void PrintPresenceStatus()
    {
        lock (_userLock)
        {
            Console.WriteLine("=== CURRENT PRESENCE ===");
            Console.WriteLine($"Active users: {_activeUsers.Count}");
            foreach (var user in _activeUsers.Values)
            {
                Console.WriteLine($"{user.Email.PadRight(20)} | " +
                    $"Status: {user.Status.PadRight(4)} | " +
                    $"Active: {user.IsActive} | " +
                    $"Last: {(DateTime.UtcNow - user.LastActivity).TotalSeconds:F0}s ago");
            }
        }
    }

    private static async Task NotifyContactsOfStatusChange(User user, string oldStatus, string newStatus, string capabilities)
    {
        // Get all contacts that have this user in their AL list
        var alContacts = MsnServer.GetReverseContacts(user.Id, "AL");
        Console.WriteLine($"[NOTIFY] Preparing to notify {alContacts.Count} contacts about {user.Email}'s status change");

        foreach (var contact in alContacts)
        {
            var contactUser = MsnServer.GetUserById(contact.UserId);
            if (contactUser == null)
            {
                Console.WriteLine($"[NOTIFY] Contact user {contact.UserId} not found");
                continue;
            }

            NetworkStream buddyStream = null;
            int buddyVersion = 0;
            bool isOnline = false;

            // Check active users first
            lock (_userLock)
            {
                if (_activeUsers.TryGetValue(contactUser.Email, out var onlineContact))
                {
                    buddyVersion = onlineContact.Version;
                    if (onlineContact.ActiveConnection?.Connected == true)
                    {
                        try
                        {
                            buddyStream = onlineContact.ActiveStream ??
                                         onlineContact.ActiveConnection.GetStream();
                            isOnline = buddyStream != null;
                            Console.WriteLine($"[NOTIFY] Found {contactUser.Email} in active users");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[NOTIFY] Connection error for {contactUser.Email}: {ex.Message}");
                            _activeUsers.Remove(contactUser.Email);
                        }
                    }
                }
            }

            // If not found in active users but has an active connection
            if (!isOnline && contactUser.ActiveConnection?.Connected == true)
            {
                try
                {
                    buddyStream = contactUser.ActiveStream ??
                                 contactUser.ActiveConnection.GetStream();
                    if (buddyStream != null)
                    {
                        // Simple ping test
                        await SendAsync(buddyStream, "PNG 0\r\n");
                        isOnline = true;
                        buddyVersion = contactUser.Version;

                        // Add to active users
                        lock (_userLock)
                        {
                            _activeUsers[contactUser.Email] = contactUser;
                            Console.WriteLine($"[NOTIFY] Added {contactUser.Email} to active users via direct connection");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[NOTIFY] Direct connection failed for {contactUser.Email}: {ex.Message}");
                    contactUser.ActiveConnection?.Dispose();
                    lock (_userLock)
                    {
                        _activeUsers.Remove(contactUser.Email);
                    }
                }
            }

            if (isOnline && buddyStream != null)
            {
                try
                {
                    string notification;
                    if (newStatus == "HDN" || newStatus == "FLN")
                    {
                        notification = buddyVersion >= 14 ?
                            $"FLN {user.Email} 1\r\n" :
                            $"FLN {user.Email}\r\n";
                    }
                    else
                    {
                        if (buddyVersion >= 8) // MSNP8+
                        {
                            notification = $"NLN {newStatus} {user.Email} " +
                                         (buddyVersion >= 14 ? "1 " : "") +
                                         $"{user.FriendlyName} {capabilities}";

                            if (!string.IsNullOrEmpty(user.MsnObjectPfp) && buddyVersion >= 9)
                            {
                                notification += $" {user.MsnObjectPfp}";
                            }
                        }
                        else // MSNP7 and below
                        {
                            notification = $"NLN {newStatus} {user.Email} {user.FriendlyName}";
                        }

                        notification += "\r\n";
                    }

                    Console.WriteLine($"[NOTIFY] Sending to {contactUser.Email}: {notification.Trim()}");
                    await SendAsync(buddyStream, notification);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[NOTIFY ERROR] Failed to notify {contactUser.Email}: {ex.Message}");
                    lock (_userLock)
                    {
                        _activeUsers.Remove(contactUser.Email);
                    }
                }
            }
            else
            {
                Console.WriteLine($"[NOTIFY] {contactUser.Email} is offline (Active: {contactUser.ActiveConnection?.Connected ?? false})");
            }
        }
    }

    private static async Task SendInitialStatusToClient(NetworkStream stream, User currentUser, int version)
    {
        Console.WriteLine($"[CHG INIT] Starting initial status sync for {currentUser.Email}");
        var flContacts = GetContacts(currentUser.Id, "FL");
        Console.WriteLine($"[CHG INIT] Found {flContacts.Count} FL contacts");

        foreach (var contact in flContacts)
        {
            var contactUser = GetUserById(contact.ContactId);
            if (contactUser == null)
            {
                Console.WriteLine($"[CHG INIT] Contact user not found for ID {contact.ContactId}");
                continue;
            }

            // Check if the contact has us in their AL list
            var reverseContacts = GetContacts(contactUser.Id, "AL")
                .Where(c => c.ContactId == currentUser.Id)
                .ToList();

            if (reverseContacts.Count == 0)
            {
                Console.WriteLine($"[CHG INIT] No reverse AL contact for {contactUser.Email}");
                continue;
            }

            // Check if contact is online
            string status = "FLN";
            string capabilities = "0";
            string msnObject = "";

            lock (_userLock)
            {
                if (_activeUsers.TryGetValue(contactUser.Email, out var onlineContact))
                {
                    status = onlineContact.Status;
                    capabilities = onlineContact.Capabilities;
                    msnObject = onlineContact.MsnObjectPfp;
                }
            }

            if (status != "FLN")
            {
                Console.WriteLine($"[CHG INIT] Building status line for {contactUser.Email}");
                string statusLine;
                if (version >= 8)
                {
                    statusLine = $"ILN {status} {contactUser.Email} " +
                               $"{(version >= 14 ? "1 " : "")}" +
                               $"{contactUser.FriendlyName} {capabilities}" +
                               $"{(version >= 9 ? " " + msnObject : "")}";
                }
                else
                {
                    statusLine = $"ILN {status} {contactUser.Email} {contactUser.FriendlyName}";
                }

                Console.WriteLine($"[CHG INIT] Sending status: {statusLine}");
                await SendAsync(stream, statusLine + "\r\n");

                // Send custom status if available (MSNP11+)
                if (version >= 11 && !string.IsNullOrEmpty(contactUser.CustomStatus))
                {
                    Console.WriteLine($"[CHG INIT] Sending custom status (length: {contactUser.CustomStatus.Length})");
                    await SendAsync(stream, $"UBX {contactUser.Email} {contactUser.CustomStatus.Length}\r\n");
                    await SendAsync(stream, contactUser.CustomStatus);
                }
            }
            else
            {
                Console.WriteLine($"[CHG INIT] Contact {contactUser.Email} not online");
            }
        }
    }

    public static async Task NotifyBuddiesOfPresence(User user, string notificationStatus)
    {
        if (user == null) return;

        // Get contacts who have this user in their Allow list
        var alContacts = MsnServer.GetReverseContacts(user.Id, "AL");
        Console.WriteLine($"[NOTIFY] Preparing to notify {alContacts.Count} contacts about {user.Email}'s status ({notificationStatus})");

        var notificationTasks = new List<Task>();
        int notifiedCount = 0;
        int offlineCount = 0;

        foreach (var contact in alContacts)
        {
            var contactUser = MsnServer.GetUserById(contact.UserId);
            if (contactUser == null) continue;

            // Check if contact is online
            NetworkStream targetStream = null;
            int targetVersion = 0;
            bool isOnline = false;

            lock (_userLock)
            {
                if (_activeUsers.TryGetValue(contactUser.Email, out var onlineContact))
                {
                    if (onlineContact.ActiveConnection?.Connected == true &&
                        onlineContact.ActiveStream != null)
                    {
                        targetStream = onlineContact.ActiveStream;
                        targetVersion = onlineContact.Version;
                        isOnline = true;
                    }
                }
            }

            if (isOnline && targetStream != null)
            {
                try
                {
                    string notification;
                    if (notificationStatus == "FLN")
                    {
                        notification = targetVersion >= 14 ?
                            $"FLN {user.Email} 1\r\n" :
                            $"FLN {user.Email}\r\n";
                    }
                    else
                    {
                        if (targetVersion >= 8) // MSNP8+
                        {
                            notification = $"NLN {notificationStatus} {user.Email} " +
                                         (targetVersion >= 14 ? "1 " : "") +
                                         $"{user.FriendlyName} {user.Capabilities}";

                            if (!string.IsNullOrEmpty(user.MsnObjectPfp) && targetVersion >= 9)
                            {
                                notification += $" {user.MsnObjectPfp}";
                            }
                        }
                        else // MSNP7 and below
                        {
                            notification = $"NLN {notificationStatus} {user.Email} {user.FriendlyName}";
                        }

                        notification += "\r\n";
                    }

                    Console.WriteLine($"[NOTIFY] Sending to {contactUser.Email}: {notification.Trim()}");
                    await SendAsync(targetStream, notification);
                    notifiedCount++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[NOTIFY ERROR] Failed to notify {contactUser.Email}: {ex.Message}");
                    lock (_userLock)
                    {
                        _activeUsers.Remove(contactUser.Email);
                    }
                }
            }
            else
            {
                Console.WriteLine($"[NOTIFY] {contactUser.Email} is offline");
                offlineCount++;
            }
        }

        Console.WriteLine($"[NOTIFY] Completed: {notifiedCount} notified, {offlineCount} offline");
    }

    private static async Task NotifyBuddiesOfChanges(User user, string newStatus,
        string capabilities, string msnObject)
    {
        if (user == null) return;

        // Get contacts who have this user in their Allow list
        var alContacts = MsnServer.GetReverseContacts(user.Id, "AL");

        if (alContacts.Count == 0)
        {
            Console.WriteLine($"[STATUS] No contacts to notify for {user.Email}'s status change");
            return;
        }

        Console.WriteLine($"[STATUS DETAILS] User {user.Email} changing status to {newStatus}. " +
                         $"Checking {alContacts.Count} contacts in AL list...");

        var notificationTasks = new List<Task>();
        int notifiedCount = 0;
        int offlineCount = 0;
        int notInListCount = 0;
        int connectionFailedCount = 0;

        foreach (var contact in alContacts)
        {
            var contactUser = MsnServer.GetUserById(contact.UserId);
            if (contactUser == null) continue;

            // Check if contact is online
            if (_activeUsers.TryGetValue(contactUser.Email, out var onlineContact) &&
                onlineContact.ActiveConnection?.Connected == true)
            {
                // ... existing online notification code ...
            }
            else
            {
                // Store for delivery when contact comes online
                contactUser.PendingNotifications.Add(new StatusNotification
                {
                    Status = newStatus,
                    Capabilities = capabilities,
                    MsnObject = msnObject,
                    Timestamp = DateTime.UtcNow
                });
                Console.WriteLine($"[STATUS QUEUED] Notification queued for {contactUser.Email} " +
                                $"to receive when they come online");
            }
        }
    }

    private static async Task SendLegacyContactListWithStatus(NetworkStream stream, string list, int userId, int version, string trid, int syncId)
    {
        var contacts = MsnServer.GetContacts(userId, list);
        int total = contacts.Count;

        if (total == 0)
        {
            await SendAsync(stream, $"LST {trid} {list} {syncId} 0 0\r\n");
            return;
        }

        for (int i = 0; i < contacts.Count; i++)
        {
            var contact = contacts[i];
            var contactUser = MsnServer.GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            string status = "FLN";
            if (_activeUsers.ContainsKey(contactUser.Email))
            {
                status = _activeUsers[contactUser.Email].Status;
            }

            await SendAsync(stream,
                $"LST {trid} {list} {syncId} {i + 1} {total} {contactUser.Email} " +
                $"{contactUser.FriendlyName}" +
                $"{(version > 6 ? " 0" : "")}\r\n");

            if (status != "FLN")
            {
                await SendAsync(stream,
                    $"NLN {status} {contactUser.Email} {contactUser.FriendlyName}\r\n");
            }
        }
    }

    private static async Task SendLegacyReverseContactListWithStatus(NetworkStream stream, int userId, int version, string trid, int syncId)
    {
        var contacts = MsnServer.GetReverseContacts(userId);
        int total = contacts.Count;

        if (total == 0)
        {
            await SendAsync(stream, $"LST {trid} RL {syncId} 0 0\r\n");
            return;
        }

        for (int i = 0; i < contacts.Count; i++)
        {
            var contact = contacts[i];
            var contactUser = MsnServer.GetUserById(contact.UserId);
            if (contactUser == null) continue;

            string status = "FLN";
            if (_activeUsers.ContainsKey(contactUser.Email))
            {
                status = _activeUsers[contactUser.Email].Status;
            }

            await SendAsync(stream,
                $"LST {trid} RL {syncId} {i + 1} {total} {contactUser.Email} " +
                $"{contactUser.FriendlyName}" +
                $"{(version > 6 ? " 0" : "")}\r\n");

            if (status != "FLN")
            {
                await SendAsync(stream,
                    $"NLN {status} {contactUser.Email} {contactUser.FriendlyName}\r\n");
            }
        }
    }

    private static async Task HandleSynCommand(NetworkStream stream, User user, int version, string trid, string syncId)
    {
        if (user == null)
        {
            await SendAsync(stream, $"911 {trid}\r\n");
            return;
        }

        Console.WriteLine($"[SYN] {user.Email} requested contact list");

        if (version >= 10)
        {
            string GetFormattedTimestamp()
            {
                var date = DateTime.UtcNow;
                return date.ToString("yyyy-MM-ddTHH:mm:ss.fff-00:00");
            }

            var lists = new[] { "FL", "AL", "BL" };
            var contactResults = lists.Select(list => MsnServer.GetContacts(user.Id, list)).ToList();
            var reverseContacts = MsnServer.GetReverseContacts(user.Id);

            var allContacts = new HashSet<string>();
            foreach (var result in contactResults)
            {
                foreach (var contact in result)
                {
                    allContacts.Add(contact.ContactId.ToString());
                }
            }
            foreach (var contact in reverseContacts)
            {
                allContacts.Add(contact.UserId.ToString());
            }

            int totalContacts = allContacts.Count;
            string timestamp = GetFormattedTimestamp();
            int totalGroups = user.Groups?.Count ?? 0;

            await SendAsync(stream, $"SYN {trid} {timestamp} {timestamp} {totalContacts} {totalGroups}\r\n");
            await SendAsync(stream, $"GTC A\r\n");
            await SendAsync(stream, $"BLP AL\r\n");
            await SendAsync(stream, $"PRP MFN {user.FriendlyName}\r\n");

            // Send phone numbers if they exist
            if (user.Phone?.PHH != null) await SendAsync(stream, $"PRP PHH {user.Phone.PHH}\r\n");
            if (user.Phone?.PHM != null) await SendAsync(stream, $"PRP PHM {user.Phone.PHM}\r\n");
            if (user.Phone?.PHW != null) await SendAsync(stream, $"PRP PHW {user.Phone.PHW}\r\n");

            // Send groups
            foreach (var group in user.Groups ?? new List<Group>())
            {
                await SendAsync(stream, $"LSG {group.Name} {group.Id}\r\n");
            }

            // Send contact list with proper NLN/FLN status
            foreach (var list in lists)
            {
                await SendContactListWithStatus(stream, list, user.Id, version);
            }

            // Send reverse contacts
            await SendReverseContactListWithStatus(stream, user.Id, version);
        }
        else
        {
            // MSNP9 and below SYN handling
            int syncIdInt;
            if (!int.TryParse(syncId, out syncIdInt))
            {
                await SendAsync(stream, $"911 {trid}\r\n");
                return;
            }

            syncIdInt++;
            await SendAsync(stream, $"SYN {trid} {syncIdInt}\r\n");
            await SendAsync(stream, $"GTC {trid} {syncIdInt} A\r\n");
            await SendAsync(stream, $"BLP {trid} {syncIdInt} AL\r\n");

            if (version >= 7)
            {
                int totalGroups = (user.Groups?.Count ?? 0) + 1;
                int index = 2;
                await SendAsync(stream, $"LSG {trid} {syncIdInt} 1 {totalGroups} 0 Other%20Contacts 0\r\n");

                foreach (var group in user.Groups ?? new List<Group>())
                {
                    await SendAsync(stream, $"LSG {trid} {syncIdInt} {index} {totalGroups} {index - 1} {group.Name} 0\r\n");
                    index++;
                }
            }

            // Handle contacts for older versions with status
            var lists = new[] { "FL", "AL", "BL" };
            foreach (var list in lists)
            {
                await SendLegacyContactListWithStatus(stream, list, user.Id, version, trid, syncIdInt);
            }

            // Send reverse contacts with status
            await SendLegacyReverseContactListWithStatus(stream, user.Id, version, trid, syncIdInt);
        }
    }

    private static async Task SendContactListWithStatus(NetworkStream stream, string list, int userId, int version)
    {
        var contacts = MsnServer.GetContacts(userId, list);

        foreach (var contact in contacts)
        {
            var contactUser = MsnServer.GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            string status = "FLN";
            if (_activeUsers.ContainsKey(contactUser.Email))
            {
                status = _activeUsers[contactUser.Email].Status;
            }

            await SendAsync(stream,
                $"LST N={contactUser.Email} F={contactUser.FriendlyName} C={contactUser.UUID} {GetListNumber(list)}" +
                $"{(version >= 12 ? " 1" : "")} {string.Join(",", contact.Groups ?? new List<int>())}\r\n");

            if (status != "FLN")
            {
                await SendAsync(stream,
                    $"NLN {status} {contactUser.Email} {contactUser.FriendlyName}" +
                    $"{(version >= 8 ? " " + contactUser.Capabilities : "")}" +
                    $"{(version >= 9 ? " " + contactUser.MsnObjectPfp : "")}\r\n");
            }
        }
    }

    private static async Task SendReverseContactListWithStatus(NetworkStream stream, int userId, int version)
    {
        var reverseContacts = MsnServer.GetReverseContacts(userId);

        foreach (var contact in reverseContacts)
        {
            var contactUser = MsnServer.GetUserById(contact.UserId);
            if (contactUser == null) continue;

            string status = "FLN";
            if (_activeUsers.ContainsKey(contactUser.Email))
            {
                status = _activeUsers[contactUser.Email].Status;
            }

            await SendAsync(stream,
                $"LST N={contactUser.Email} F={contactUser.FriendlyName} C={contactUser.UUID} 8" + // 8 for RL list
                $"{(version >= 12 ? " 1" : "")}\r\n");

            if (status != "FLN")
            {
                await SendAsync(stream,
                    $"NLN {status} {contactUser.Email} {contactUser.FriendlyName}" +
                    $"{(version >= 8 ? " " + contactUser.Capabilities : "")}" +
                    $"{(version >= 9 ? " " + contactUser.MsnObjectPfp : "")}\r\n");
            }
        }
    }

    private static int GetListNumber(string list)
    {
        return list switch
        {
            "FL" => 1,
            "AL" => 2,
            "BL" => 4,
            "RL" => 8,
            _ => 0
        };
    }


    private static async Task HandleAdcCommand(NetworkStream stream, User currentUser, string[] parts)
    {
        if (currentUser == null || parts.Length < 4)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string transactionId = parts[1];
        string list = parts[2];
        string contactIdentifier = parts[3];

        // Validate transaction ID is a number
        if (!int.TryParse(transactionId, out _))
        {
            await SendAsync(stream, $"OUT\r\n");
            return;
        }

        // For MSNP10+, we don't support this command if it's not in the right format
        if (currentUser.Version >= 10 && !(contactIdentifier.StartsWith("N=") || contactIdentifier.StartsWith("C=")))
        {
            await SendAsync(stream, $"OUT\r\n");
            return;
        }

        try
        {
            if (contactIdentifier.StartsWith("C="))
            {
                // Handle adding to group
                await HandleAddToGroup(stream, currentUser, transactionId, list, contactIdentifier, parts);
                return;
            }

            string email = contactIdentifier.Replace("N=", "");
            string username = email.Split('@')[0];

            // Find the user being added
            var userToAdd = _users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
            if (userToAdd == null)
            {
                Console.WriteLine($"[ADC] {currentUser.Email} attempted to add non-existent user: {email}");
                await SendAsync(stream, $"205 {transactionId}\r\n");
                return;
            }

            // Check contact list size limit (150 for FL list)
            var currentContacts = _contacts.Count(c => c.UserId == currentUser.Id && c.List == "FL");
            if (currentContacts >= 150 && list == "FL")
            {
                Console.WriteLine($"[ADC] {currentUser.Email} has reached contact limit (150)");
                await SendAsync(stream, $"210 {transactionId}\r\n");
                return;
            }

            // Check if contact already exists in this list
            var existingContact = _contacts.FirstOrDefault(c =>
                c.UserId == currentUser.Id &&
                c.ContactId == userToAdd.Id &&
                c.List == list);

            if (existingContact != null)
            {
                Console.WriteLine($"[ADC] {currentUser.Email} already has {username} in {list} list");
                await SendAsync(stream, $"215 {transactionId}\r\n");
                return;
            }

            // Check if contact is blocked
            var blockedContact = _contacts.FirstOrDefault(c =>
                c.UserId == currentUser.Id &&
                c.ContactId == userToAdd.Id &&
                c.List == "BL");

            var allowedContact = _contacts.FirstOrDefault(c =>
                c.UserId == currentUser.Id &&
                c.ContactId == userToAdd.Id &&
                c.List == "AL");

            if (blockedContact != null && allowedContact != null)
            {
                Console.WriteLine($"[ADC] {currentUser.Email} tried to add blocked user: {username}");
                await SendAsync(stream, $"215 {parts[1]}\r\n");
                return;
            }

            // Add the new contact
            var newContact = new Contact
            {
                Id = _contacts.Count > 0 ? _contacts.Max(c => c.Id) + 1 : 1,
                UserId = currentUser.Id,
                ContactId = userToAdd.Id,
                List = list,
                Groups = new List<int>()
            };

            // Handle group addition if specified
            if (parts.Length > 4)
            {
                string groupIdStr = parts[4];
                if (int.TryParse(groupIdStr, out int groupId))
                {
                    newContact.Groups.Add(groupId);
                }
            }

            _contacts.Add(newContact);
            await SaveContacts();

            // Send appropriate response based on list type
            if (list == "FL")
            {
                // Also add to AL list if not already present
                var existingALContact = _contacts.FirstOrDefault(c =>
                    c.UserId == currentUser.Id &&
                    c.ContactId == userToAdd.Id &&
                    c.List == "AL");

                if (existingALContact == null)
                {
                    _contacts.Add(new Contact
                    {
                        Id = _contacts.Max(c => c.Id) + 1,
                        UserId = currentUser.Id,
                        ContactId = userToAdd.Id,
                        List = "AL"
                    });
                    await SaveContacts();
                }
            }
            else if (list == "AL" || list == "BL" || list == "RL")
            {
                await SendAsync(stream, $"ADC {transactionId} {list} N={userToAdd.Email}\r\n");
            }

            Console.WriteLine($"[ADC] {currentUser.Email} added {userToAdd.Email} to {list} list");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ADC ERROR] {ex.Message}");
            await SendAsync(stream, $"911 {transactionId}\r\n");
        }
    }

    private static async Task HandlePrpCommand(NetworkStream stream, User currentUser, string[] parts, int version)
    {
        if (currentUser == null)
        {
            await SendAsync(stream, "911\r\n");
            return;
        }

        try
        {
            if (version >= 11) // MSNP11 and above
            {
                if (parts.Length < 3)
                {
                    await SendAsync(stream, "911\r\n");
                    return;
                }

                string transactionId = parts[1];
                string type = parts[2];
                string newSetting = parts.Length > 3 ? parts[3] : string.Empty;

                // Validate transaction ID is a number
                if (!int.TryParse(transactionId, out _))
                {
                    await SendAsync(stream, "OUT\r\n");
                    return;
                }

                switch (type)
                {
                    case "MFN": // Friendly name
                        await HandleMfnProperty(stream, currentUser, transactionId, newSetting, version);
                        break;

                    case "PHH": // Home phone
                    case "PHW": // Work phone
                    case "PHM": // Mobile phone
                        await HandlePhoneProperty(stream, currentUser, transactionId, type, newSetting, version);
                        break;

                    default:
                        Console.WriteLine($"[PRP] Unknown property type: {type}");
                        await SendAsync(stream, $"200 {transactionId}\r\n");
                        break;
                }

                var reverseContacts = GetReverseContacts(currentUser.Id);

                foreach (var contact in reverseContacts)
                {
                    var contactUser = GetUserById(contact.UserId);
                    if (contactUser == null) continue;

                    string status = "FLN";
                    if (_activeUsers.ContainsKey(contactUser.Email))
                    {
                        status = _activeUsers[contactUser.Email].Status;
                    }

                    await SendAsync(stream,
                        $"LST N={contactUser.Email} F={contactUser.FriendlyName} C={contactUser.UUID} 8" + // 8 for RL list
                        $"{(version >= 12 ? " 1" : "")}\r\n");

                    if (status != "FLN")
                    {
                        await SendAsync(stream,
                            $"NLN {status} {contactUser.Email} {contactUser.FriendlyName}" +
                            $"{(version >= 8 ? " " + contactUser.Capabilities : "")}" +
                            $"{(version >= 9 ? " " + contactUser.MsnObjectPfp : "")}\r\n");
                    }
                }
                    }
                    else // MSNP8-10
            {
                if (parts.Length < 2)
                {
                    await SendAsync(stream, "911\r\n");
                    return;
                }

                string type = parts[1];
                string newSetting = parts.Length > 2 ? parts[2] : string.Empty;

                switch (type)
                {
                    case "MFN": // Friendly name
                        currentUser.FriendlyName = Uri.UnescapeDataString(newSetting);
                        Console.WriteLine($"[PRP] Updated friendly name to: {currentUser.FriendlyName}");
                        break;

                    case "WWE": // Web enabled
                                // These are flags that might be used in MSNP8-10
                        Console.WriteLine($"[PRP] Flag {type} set to {newSetting}");
                        break;

                    default:
                        Console.WriteLine($"[PRP] Unknown property type: {type}");
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PRP ERROR] {ex.Message}");
            await SendAsync(stream, "911\r\n");
        }
    }

    private static async Task HandleMfnProperty(NetworkStream stream, User currentUser, string transactionId, string newFriendlyName, int version)
    {
        // Update friendly name
        currentUser.FriendlyName = newFriendlyName;
        await SaveUserToDatabase(currentUser);

        // Send confirmation
        await SendAsync(stream, $"PRP {transactionId} MFN {newFriendlyName}\r\n");

        // Notify contacts
        var contacts = MsnServer.GetContacts(currentUser.Id, "FL");
        foreach (var contact in contacts)
        {
            var contactUser = MsnServer.GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            // Check if the contact has us in their FL list
            var reverseContacts = MsnServer.GetContacts(contactUser.Id, "FL")
                .Where(c => c.ContactId == currentUser.Id)
                .ToList();

            if (reverseContacts.Count == 0) continue;

            // Check if contact is online
            if (_activeUsers.TryGetValue(contactUser.Email, out var onlineContact))
            {
                if (onlineContact.ActiveConnection?.Connected == true)
                {
                    try
                    {
                        var contactStream = onlineContact.ActiveConnection.GetStream();
                        if (onlineContact.Version >= 8)
                        {
                            await SendAsync(contactStream,
                                $"NLN {currentUser.Status} {currentUser.Email} " +
                                $"{(onlineContact.Version >= 14 ? "1 " : "")}" +
                                $"{currentUser.FriendlyName} {currentUser.Capabilities}" +
                                $"{(onlineContact.Version >= 9 ? " " + currentUser.MsnObjectPfp : "")}\r\n");
                        }
                        else
                        {
                            await SendAsync(contactStream,
                                $"NLN {currentUser.Status} {currentUser.Email} {currentUser.FriendlyName}\r\n");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[PRP MFN Notify Error] {ex.Message}");
                    }
                }
            }
        }
    }

    private static async Task HandlePhoneProperty(NetworkStream stream, User currentUser, string transactionID, string phoneType, string newNumber, int version)
    {
        // Initialize phone object if null
        currentUser.Phone = currentUser.Phone ?? new Phone();

        // Update the appropriate phone number
        switch (phoneType)
        {
            case "PHH":
                currentUser.Phone.PHH = newNumber;
                break;
            case "PHW":
                currentUser.Phone.PHW = newNumber;
                break;
            case "PHM":
                currentUser.Phone.PHM = newNumber;
                break;
        }

        await SaveUserToDatabase(currentUser);

        // Send confirmation
        await SendAsync(stream, $"PRP {transactionID} {phoneType} {newNumber}\r\n");

        // Notify contacts
        var contacts = MsnServer.GetContacts(currentUser.Id, "FL");
        foreach (var contact in contacts)
        {
            var contactUser = MsnServer.GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            // Check if the contact has us in their FL list
            var reverseContacts = MsnServer.GetContacts(contactUser.Id, "FL")
                .Where(c => c.ContactId == currentUser.Id)
                .ToList();

            if (reverseContacts.Count == 0) continue;

            // Check if contact is online
            if (_activeUsers.TryGetValue(contactUser.Email, out var onlineContact))
            {
                if (onlineContact.ActiveConnection?.Connected == true)
                {
                    try
                    {
                        var contactStream = onlineContact.ActiveConnection.GetStream();
                        await SendAsync(contactStream, $"BPR {currentUser.Email} {phoneType} {newNumber}\r\n");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[PRP {phoneType} Notify Error] {ex.Message}");
                    }
                }
            }
        }
    }

    private static async Task HandleAddToGroup(NetworkStream stream, User currentUser, string transactionId, string list, string contactIdentifier, string[] parts)
    {
        if (list != "FL")
        {
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        string contactUUID = contactIdentifier.Replace("C=", "");
        var contact = _users.FirstOrDefault(u => u.UUID == contactUUID);

        if (contact == null)
        {
            Console.WriteLine($"[ADC] {currentUser.Email} attempted to add non-existent user: {contactUUID}");
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        if (parts.Length < 5)
        {
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        string groupIdStr = parts[4];
        if (!int.TryParse(groupIdStr, out int groupId))
        {
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        // Verify the group exists for this user
        var groupExists = currentUser.Groups?.Any(g => g.Id == groupId) ?? false;
        if (!groupExists)
        {
            Console.WriteLine($"[ADC] {currentUser.Email} attempted to add to non-existent group: {groupId}");
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        // Find the existing FL contact
        var existingContact = _contacts.FirstOrDefault(c =>
            c.UserId == currentUser.Id &&
            c.ContactId == contact.Id &&
            c.List == "FL");

        if (existingContact == null)
        {
            Console.WriteLine($"[ADC] {currentUser.Email} attempted to add to group without FL contact: {contact.Email}");
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        // Add to group if not already there
        if (!existingContact.Groups.Contains(groupId))
        {
            existingContact.Groups.Add(groupId);
            await SaveContacts();
        }

        await SendAsync(stream, $"ADC {transactionId} FL C={contactUUID} {groupId}\r\n");
        Console.WriteLine($"[ADC] {currentUser.Email} added {contact.Email} to group {groupId}");
    }

    private static async Task HandleAddCommand(NetworkStream stream, User currentUser, string[] parts)
    {
        if (parts.Length < 4)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string transactionId = parts[1];
        string list = parts[2];
        string email = parts[3];
        string username = email.Split('@')[0];

        // Validate transaction ID is a number
        if (!int.TryParse(transactionId, out _))
        {
            await SendAsync(stream, $"OUT\r\n");
            return;
        }

        // For MSNP10+, we don't support this command
        if (currentUser.Version >= 10)
        {
            await SendAsync(stream, $"OUT\r\n");
            return;
        }

        // Find the user being added
        var userToAdd = _users.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        if (userToAdd == null)
        {
            Console.WriteLine($"[ADD] {currentUser.Email} attempted to add non-existent user: {email}");
            await SendAsync(stream, $"205 {transactionId}\r\n");
            return;
        }

        // Check contact list size limit (150)
        var currentContacts = _contacts.Count(c => c.UserId == currentUser.Id && c.List == "FL");
        if (currentContacts >= 150)
        {
            Console.WriteLine($"[ADD] {currentUser.Email} has reached contact limit (150)");
            await SendAsync(stream, $"210 {transactionId}\r\n");
            return;
        }

        // Check if contact already exists in this list
        var existingContact = _contacts.FirstOrDefault(c =>
            c.UserId == currentUser.Id &&
            c.ContactId == userToAdd.Id &&
            c.List == list);

        if (existingContact != null)
        {
            Console.WriteLine($"[ADD] {currentUser.Email} already has {username} in {list} list");
            await SendAsync(stream, $"215 {transactionId}\r\n");
            return;
        }

        // Check if contact is blocked
        var blockedContact = _contacts.FirstOrDefault(c =>
            c.UserId == currentUser.Id &&
            c.ContactId == userToAdd.Id &&
            c.List == "BL");

        var allowedContact = _contacts.FirstOrDefault(c =>
            c.UserId == currentUser.Id &&
            c.ContactId == userToAdd.Id &&
            c.List == "AL");

        if (blockedContact != null && allowedContact != null)
        {
            Console.WriteLine($"[ADD] {currentUser.Email} tried to add blocked user: {username}");
            await SendAsync(stream, $"215 {transactionId}\r\n");
            return;
        }

        // Add the new contact
        var newContact = new Contact
        {
            Id = _contacts.Count > 0 ? _contacts.Max(c => c.Id) + 1 : 1,
            UserId = currentUser.Id,
            ContactId = userToAdd.Id,
            List = list
        };

        _contacts.Add(newContact);
        await SaveContacts();

        Console.WriteLine($"[ADD] {currentUser.Email} added {userToAdd.Email} to {list} list");
        await SendAsync(stream, $"ADD {transactionId} {list} 1 {userToAdd.Email} {userToAdd.FriendlyName ?? userToAdd.FriendlyName} 0\r\n");
    }

    private static async Task HandleReaCommand(NetworkStream stream, User currentUser, string[] parts, int version)
    {
        if (parts.Length < 4)
        {
            await SendAsync(stream, $"911 {parts[1]}\r\n");
            return;
        }

        string trid = parts[1];
        string email = parts[2];
        string newDisplayNameEncoded = parts[3];

        try
        {
            string newDisplayName = WebUtility.UrlDecode(newDisplayNameEncoded);
            if (Encoding.UTF8.GetByteCount(newDisplayNameEncoded) > 387)
            {
                await SendAsync(stream, $"209 {trid}\r\n");
                return;
            }

            // Update the display name
            currentUser.FriendlyName = newDisplayName;

            // Save to database
            await SaveUserToDatabase(currentUser);

            // Send success response
            await SendAsync(stream, $"REA {trid} 1 {email} {newDisplayNameEncoded}\r\n");
            Console.WriteLine($"[REA] Updated display name for {email} to {newDisplayName}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[REA ERROR] {ex.Message}");
            await SendAsync(stream, $"911 {trid}\r\n");
        }
    }

    internal static async Task SaveUserToDatabase(User user)
    {
        // Create a clean object without the ActiveConnection
        var userData = new
        {
            user.Id,
            user.Email,
            user.FriendlyName,
            user.PasswordHash,
            user.Status,
            user.Capabilities,
            user.MsnObjectPfp,
            user.UUID
        };

        // Find and update the user in the list
        var existingUser = _users.FirstOrDefault(u => u.Email.Equals(user.Email, StringComparison.OrdinalIgnoreCase));
        if (existingUser != null)
        {
            existingUser.FriendlyName = user.FriendlyName;
            existingUser.Status = user.Status;
            existingUser.Capabilities = user.Capabilities;
            existingUser.MsnObjectPfp = user.MsnObjectPfp;
        }

        // Serialize and save to JSON file
        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(_users.Select(u => new
        {
            u.Id,
            u.Email,
            u.FriendlyName,
            u.PasswordHash,
            u.Status,
            u.Capabilities,
            u.MsnObjectPfp,
            u.UUID
        }), options);

        await File.WriteAllTextAsync(UsersDbFile, json);
    }
}

// Model classes
class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string FriendlyName { get; set; } = "";
    public int Version { get; set; }
    public string PasswordHash { get; set; } = "";
    public Phone Phone { get; set; } = new Phone();
    public List<Group> Groups { get; set; } = new List<Group>();
    public string UUID { get; set; } = Guid.NewGuid().ToString();
    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    public string Status { get; set; } = "NLN";
    public string Capabilities { get; set; } = "0";
    public string MsnObjectPfp { get; set; } = "";
    public string CustomStatus { get; set; } = "";
    public bool InitialStatusSent { get; set; }
    public List<StatusNotification> PendingNotifications { get; set; } = new List<StatusNotification>();

    public TcpClient ActiveConnection { get; set; }
    public NetworkStream ActiveStream { get; set; }
    public DateTime LastActivity { get; set; }
    public bool IsActive => ActiveConnection?.Connected == true
                     && (DateTime.UtcNow - LastActivity) < TimeSpan.FromMinutes(5);
}
class Contact
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public int ContactId { get; set; }
    public string List { get; set; }
    public List<int> Groups { get; set; }
}

class Phone
{
    public string PHH { get; set; }  // Home phone
    public string PHM { get; set; }  // Mobile phone
    public string PHW { get; set; }  // Work phone
}

class Group
{
    public int Id { get; set; }
    public string Guid { get; set; }
    public string Name { get; set; }

    public Group()
    {
        Guid = System.Guid.NewGuid().ToString();
    }
}

class ContactData
{
    public string Email { get; set; }
    public string FriendlyName { get; set; }
    public string UUID { get; set; }
    public int ListsNumber { get; set; }
    public List<int> Groups { get; set; } = new List<int>();
    public Phone Phone { get; set; }
    public string Status { get; set; } = "FLN";
}

class StatusNotification
{
    public string Status { get; set; }
    public string Capabilities { get; set; }
    public string MsnObject { get; set; }
    public DateTime Timestamp { get; set; }
}

// Add this class to track connected clients
public class ConnectedClient
{
    public TcpClient TcpClient { get; set; }
    public NetworkStream Stream { get; set; }
    public string Email { get; set; }
    public int Version { get; set; }
    public DateTime LastActivity { get; set; }
}

class SwitchboardSession
{
    public string SessionId { get; set; }
    public string Caller { get; set; }  // The user who initiated the session
    public List<string> Participants { get; set; } = new List<string>();
    public NetworkStream Client { get; set; }  // For the answering participant
    public NetworkStream CallerClient { get; set; }  // For the original caller
    public string AuthTicket { get; set; }  // The cookie used for authentication
    public Dictionary<string, string> DisplayNames { get; set; } = new Dictionary<string, string>();

    public string GetUserDisplayName(string email)
    {
        return DisplayNames.TryGetValue(email, out var name) ? name : email.Split('@')[0];
    }
}
#endregion

class HttpSoapServer
{
    private const int Port = 80;
    private static readonly XNamespace SoapNs = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace AbNs = "http://www.msn.com/webservices/AddressBook";

    public static async Task Start()
    {
        try
        {
            HttpListener listener = new HttpListener();

            // Add both common URL variants
            listener.Prefixes.Add($"http://localhost:{Port}/");
            listener.Prefixes.Add($"http://*:{Port}/");
            listener.Prefixes.Add($"http://localhost:{Port}/messenger/");
            listener.Prefixes.Add($"http://*:{Port}/messenger/");

            Console.WriteLine($"[HTTP] Attempting to start on port {Port}...");
            listener.Start();
            Console.WriteLine($"[+] HTTP SOAP Server started on port {Port}");

            while (true)
            {
                try
                {
                    var context = await listener.GetContextAsync();
                    Console.WriteLine($"[HTTP] Incoming request from {context.Request.RemoteEndPoint}");
                    _ = ProcessRequestAsync(context); // Fire and forget
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[HTTP Request Error] {ex.Message}");
                }
            }
        }
        catch (HttpListenerException hlex)
        {
            Console.WriteLine($"[HTTP Startup Failed] {hlex.Message}");
            if (hlex.ErrorCode == 5) // Access denied
            {
                Console.WriteLine("You may need to run as administrator or grant URL ACL:");
                Console.WriteLine($"netsh http add urlacl url=http://*:{Port}/ user=Everyone");
                Console.WriteLine($"netsh http add urlacl url=http://*:{Port}/messenger/ user=Everyone");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HTTP Fatal Error] {ex.Message}");
        }
    }

    private static async Task ProcessRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        Console.WriteLine($"[HTTP] {request.HttpMethod} {request.Url.AbsolutePath}");

        try
        {
            // Handle CORS preflight (OPTIONS request)
            if (request.HttpMethod == "OPTIONS")
            {
                response.StatusCode = 200;
                response.AddHeader("Access-Control-Allow-Origin", "*");
                response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                response.AddHeader("Access-Control-Allow-Headers", "Content-Type, SOAPAction");
                response.Close();
                return;
            }

            // Special handling for MSN Messenger's legacy GET requests
            if (request.HttpMethod == "GET" &&
                (request.Url.AbsolutePath.EndsWith("/Config/MsgrConfig.asmx") ||
                 request.Url.AbsolutePath.EndsWith("/messenger/clientconfig.asmx")))
            {
                // Extract parameters from query string for logging
                var queryParams = System.Web.HttpUtility.ParseQueryString(request.Url.Query);
                Console.WriteLine($"[GET Config] Client version: {queryParams["ver"]}, Country: {queryParams["Country"]}");

                // Return the client configuration
                string responseXml = GenerateClientConfigResponse();
                await SendSoapResponse(response, responseXml);
                return;
            }

            // Only allow POST for other SOAP requests
            if (request.HttpMethod != "POST")
            {
                response.StatusCode = 405; // Method Not Allowed
                response.AddHeader("Allow", "GET, POST"); // Inform client of allowed methods
                response.Close();
                return;
            }

            // Process POST requests (standard SOAP handling)
            string requestBody;
            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
            {
                requestBody = await reader.ReadToEndAsync();
            }

            string soapAction = request.Headers["SOAPAction"];
            if (string.IsNullOrEmpty(soapAction))
            {
                response.StatusCode = 400; // Bad Request
                await SendSoapResponse(response, "SOAPAction header is required");
                return;
            }

            // Route to appropriate handler based on path
            if (request.Url.AbsolutePath.Equals("/abservice/abservice.asmx", StringComparison.OrdinalIgnoreCase))
            {
                await HandleABServiceRequest(soapAction, requestBody, response);
            }
            else if (request.Url.AbsolutePath.Equals("/abservice/SharingService.asmx", StringComparison.OrdinalIgnoreCase))
            {
                await HandleSharingServiceRequest(soapAction, requestBody, response);
            }
            else if (request.Url.AbsolutePath.Equals("/messenger/clientconfig.asmx", StringComparison.OrdinalIgnoreCase) ||
                     request.Url.AbsolutePath.Equals("/Config/MsgrConfig.asmx", StringComparison.OrdinalIgnoreCase))
            {
                await HandleClientConfigRequest(soapAction, requestBody, response);
            }
            else
            {
                response.StatusCode = 404; // Not Found
                await SendSoapResponse(response, "Endpoint not found");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[HTTP Error] {ex.Message}");
            response.StatusCode = 500; // Internal Server Error
            await SendSoapResponse(response, $"Internal server error: {ex.Message}");
        }
    }

    private static async Task HandleABServiceRequest(string soapAction, string requestBody, HttpListenerResponse response)
    {
        string action = soapAction.Split('/').Last().Replace("\"", "");
        string responseXml;

        switch (action)
        {
            case "ABFindAll":
                responseXml = await HandleABFindAll(requestBody);
                break;
            case "ABFindContactsPaged":
                responseXml = await HandleABFindContactsPaged(requestBody);
                break;
            default:
                Console.WriteLine($"[SOAP] No handler for ABService action: {action}");
                response.StatusCode = 404;
                response.Close();
                return;
        }

        await SendSoapResponse(response, responseXml);
    }

    private static async Task HandleSharingServiceRequest(string soapAction, string requestBody, HttpListenerResponse response)
    {
        string action = soapAction.Split('/').Last().Replace("\"", "");
        string responseXml;

        switch (action)
        {
            case "FindMembership":
                responseXml = await HandleFindMembership(requestBody);
                break;
            default:
                Console.WriteLine($"[SOAP] No handler for SharingService action: {action}");
                response.StatusCode = 404;
                response.Close();
                return;
        }

        await SendSoapResponse(response, responseXml);
    }


    private static XElement BuildServicesXml(List<Contact> allowContacts, List<Contact> blockContacts, List<Contact> reverseContacts, int userId)
    {
        var servicesElement = new XElement("Services",
            new XElement("Service",
                BuildMembershipsXml(allowContacts, blockContacts, reverseContacts, userId),
                new XElement("Info",
                    new XElement("Handle",
                        new XElement("Id", "1"),
                        new XElement("Type", "Messenger"),
                        new XElement("ForeignId", "")
                    ),
                    new XElement("InverseRequired", "false"),
                    new XElement("AuthorizationCriteria", "Everyone"),
                    new XElement("IsBot", "false")
                ),
                new XElement("Changes", ""),
                new XElement("LastChange", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                new XElement("Deleted", "false")
            )
        );

        return servicesElement;
    }

    private static XElement BuildGroupsXml(List<Group> groups)
    {
        var groupsElement = new XElement(AbNs + "groups");

        foreach (var group in groups)
        {
            groupsElement.Add(
                new XElement(AbNs + "Group",
                    new XElement(AbNs + "groupId", group.Id),
                    new XElement(AbNs + "groupInfo",
                        new XElement(AbNs + "annotations",
                            new XElement(AbNs + "Annotation",
                                new XElement(AbNs + "Name", "MSN.IM.Display"),
                                new XElement(AbNs + "Value", "1")
                            )
                        ),
                        new XElement(AbNs + "groupType", "c8529ce2-6ead-434d-881f-341e17db3ff8"),
                        new XElement(AbNs + "name", group.Name),
                        new XElement(AbNs + "IsNotMobileVisible", "false"),
                        new XElement(AbNs + "IsPrivate", "false"),
                        new XElement(AbNs + "IsFavorite", "false")
                    ),
                    new XElement(AbNs + "propertiesChanged", ""),
                    new XElement(AbNs + "fDeleted", "false"),
                    new XElement(AbNs + "lastChange", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
                )
            );
        }

        return groupsElement;
    }

    private static async Task<string> HandleABFindAll(string requestBody)
    {
        try
        {
            var doc = XDocument.Parse(requestBody);
            var abNs = XNamespace.Get("http://www.msn.com/webservices/AddressBook");
            var ticketToken = doc.Descendants(abNs + "TicketToken").FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(ticketToken))
                return CreateErrorResponse("Invalid ticket token");

            var email = ticketToken.Split('&').FirstOrDefault(p => p.StartsWith("p="))?.Substring(2);
            if (string.IsNullOrEmpty(email))
                return CreateErrorResponse("Invalid email in token");

            var user = MsnServer.GetUserByEmail(email);
            if (user == null)
                return CreateErrorResponse("User not found");

            // Initialize collections if null
            user.Groups = user.Groups ?? new List<Group>();
            var contacts = MsnServer.GetContacts(user.Id, "FL") ?? new List<Contact>();
            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var created = user.CreatedDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            // Build groups XML
            var groupsBuilder = new StringBuilder();
            foreach (var group in user.Groups.Where(g => g != null))
            {
                groupsBuilder.Append($@"
                <Group xmlns=""http://www.msn.com/webservices/AddressBook"">
                    <groupId>{group.Id}</groupId>
                    <groupInfo>
                        <annotations>
                            <Annotation>
                                <Name>MSN.IM.Display</Name>
                                <Value>1</Value>
                            </Annotation>
                        </annotations>
                        <groupType>c8529ce2-6ead-434d-881f-341e17db3ff8</groupType>
                        <name>{WebUtility.HtmlEncode(group.Name)}</name>
                        <IsNotMobileVisible>false</IsNotMobileVisible>
                        <IsPrivate>false</IsPrivate>
                        <IsFavorite>false</IsFavorite>
                    </groupInfo>
                    <propertiesChanged />
                    <fDeleted>false</fDeleted>
                    <lastChange>{now}</lastChange>
                </Group>");
            }

            // Build contacts XML
            var contactsBuilder = new StringBuilder();
            foreach (var contact in contacts.Where(c => c != null))
            {
                var contactUser = MsnServer.GetUserById(contact.ContactId);
                if (contactUser == null) continue;

                var groupsXml = contact.Groups?.Count > 0 ?
                    $"<groupIds>{string.Join("", contact.Groups.Select(g => $"<guid>{g}</guid>"))}</groupIds>" :
                    "";

                contactsBuilder.Append($@"
                <Contact xmlns=""http://www.msn.com/webservices/AddressBook"">
                    <contactId>{contactUser.UUID}</contactId>
                    <contactInfo>
                        <contactType>Regular</contactType>
                        <quickName>{WebUtility.HtmlEncode(contactUser.FriendlyName)}</quickName>
                        <passportName>{contactUser.Email}</passportName>
                        <IsPassportNameHidden>false</IsPassportNameHidden>
                        <displayName>{WebUtility.HtmlEncode(contactUser.FriendlyName)}</displayName>
                        <puid>0</puid>
                        {groupsXml}
                        <CID>{contactUser.Id}</CID>
                        <IsNotMobileVisible>false</IsNotMobileVisible>
                        <isMobileIMEnabled>false</isMobileIMEnabled>
                        <isMessengerUser>true</isMessengerUser>
                        <isFavorite>false</isFavorite>
                        <isSmtp>false</isSmtp>
                        <hasSpace>false</hasSpace>
                        <spotWatchState>NoDevice</spotWatchState>
                        <birthdate>0001-01-01T00:00:00</birthdate>
                        <primaryEmailType>ContactEmailPersonal</primaryEmailType>
                        <PrimaryLocation>ContactLocationPersonal</PrimaryLocation>
                        <PrimaryPhone>ContactPhonePersonal</PrimaryPhone>
                        <IsPrivate>false</IsPrivate>
                        <Gender>Unspecified</Gender>
                        <TimeZone>None</TimeZone>
                    </contactInfo>
                    <propertiesChanged />
                    <fDeleted>false</fDeleted>
                    <lastChange>{now}</lastChange>
                </Contact>");
            }

            // Add self contact
            contactsBuilder.Append($@"
            <Contact xmlns=""http://www.msn.com/webservices/AddressBook"">
                <contactId>{user.UUID}</contactId>
                <contactInfo>
                    <annotations>
                        <Annotation>
                            <Name>MSN.IM.MBEA</Name>
                            <Value>0</Value>
                        </Annotation>
                        <Annotation>
                            <Name>MSN.IM.GTC</Name>
                            <Value>0</Value>
                        </Annotation>
                        <Annotation>
                            <Name>MSN.IM.BLP</Name>
                            <Value>0</Value>
                        </Annotation>
                    </annotations>
                    <contactType>Me</contactType>
                    <quickName>{WebUtility.HtmlEncode(user.FriendlyName)}</quickName>
                    <passportName>{user.Email}</passportName>
                    <IsPassportNameHidden>false</IsPassportNameHidden>
                    <displayName>{WebUtility.HtmlEncode(user.FriendlyName)}</displayName>
                    <puid>0</puid>
                    <CID>{user.Id}</CID>
                    <IsNotMobileVisible>false</IsNotMobileVisible>
                    <isMobileIMEnabled>false</isMobileIMEnabled>
                    <isMessengerUser>false</isMessengerUser>
                    <isFavorite>false</isFavorite>
                    <isSmtp>false</isSmtp>
                    <hasSpace>false</hasSpace>
                    <spotWatchState>NoDevice</spotWatchState>
                    <birthdate>0001-01-01T00:00:00</birthdate>
                    <primaryEmailType>ContactEmailPersonal</primaryEmailType>
                    <PrimaryLocation>ContactLocationPersonal</PrimaryLocation>
                    <PrimaryPhone>ContactPhonePersonal</PrimaryPhone>
                    <IsPrivate>false</IsPrivate>
                    <Gender>Unspecified</Gender>
                    <TimeZone>None</TimeZone>
                </contactInfo>
                <propertiesChanged />
                <fDeleted>false</fDeleted>
                <lastChange>{now}</lastChange>
            </Contact>");

            // Build final response using template
            var response = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/AddressBook"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>12r1:{Guid.NewGuid()}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>contacts.msn.com</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <ABFindAllResponse xmlns=""http://www.msn.com/webservices/AddressBook"">
            <ABFindAllResult>
                <groups>
                    {groupsBuilder}
                </groups>
                <contacts>
                    {contactsBuilder}
                </contacts>
                <ab>
                    <abId>00000000-0000-0000-0000-000000000000</abId>
                    <abInfo>
                        <ownerPuid>0</ownerPuid>
                        <OwnerCID>{user.Id}</OwnerCID>
                        <ownerEmail>{user.Email}</ownerEmail>
                        <fDefault>true</fDefault>
                        <joinedNamespace>false</joinedNamespace>
                    </abInfo>
                    <lastChange>{now}</lastChange>
                    <DynamicItemLastChanged>0001-01-01T00:00:00</DynamicItemLastChanged>
                    <createDate>{created}</createDate>
                </ab>
            </ABFindAllResult>
        </ABFindAllResponse>
    </soap:Body>
</soap:Envelope>";

            return response;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ABFindAll Error] {ex}");
            return CreateErrorResponse("Internal server error");
        }
    }

    private static string FormatDecimalCID(string id)
    {
        id = "76321";
        return id; // Placeholder - replace with actual formatting
    }

    private static XElement BuildContactsXml(List<Contact> contacts, int userId)
    {
        var contactsElement = new XElement(AbNs + "contacts");

        foreach (var contact in contacts)
        {
            var contactUser = MsnServer.GetUserByEmail(contact.ContactId.ToString()); // Adjust this based on your contact structure
            if (contactUser == null) continue;

            var isSelf = contactUser.Id == userId;

            var contactElement = new XElement(AbNs + "Contact",
                new XElement(AbNs + "contactId", Guid.NewGuid().ToString()),
                new XElement(AbNs + "contactInfo",
                    new XElement(AbNs + "contactType", isSelf ? "Me" : "Regular"),
                    new XElement(AbNs + "quickName", contactUser.Email.Split('@')[0]),
                    new XElement(AbNs + "passportName", contactUser.Email),
                    new XElement(AbNs + "IsPassportNameHidden", "false"),
                    new XElement(AbNs + "displayName", contactUser.FriendlyName ?? contactUser.Email.Split('@')[0]),
                    new XElement(AbNs + "puid", "0"),
                    new XElement(AbNs + "groupIds",
                        contact.Groups?.Select(g => new XElement(AbNs + "guid", g)) ?? Enumerable.Empty<XElement>()
                    ),
                    new XElement(AbNs + "CID", "0"),
                    new XElement(AbNs + "IsNotMobileVisible", "false"),
                    new XElement(AbNs + "isMobileIMEnabled", "false"),
                    new XElement(AbNs + "isMessengerUser", "true"),
                    new XElement(AbNs + "isFavorite", "false"),
                    new XElement(AbNs + "isSmtp", "false"),
                    new XElement(AbNs + "hasSpace", "false"),
                    new XElement(AbNs + "spotWatchState", "NoDevice"),
                    new XElement(AbNs + "birthdate", "0001-01-01T00:00:00"),
                    new XElement(AbNs + "primaryEmailType", "ContactEmailPersonal"),
                    new XElement(AbNs + "PrimaryLocation", "ContactLocationPersonal"),
                    new XElement(AbNs + "PrimaryPhone", "ContactPhonePersonal"),
                    new XElement(AbNs + "IsPrivate", "false"),
                    new XElement(AbNs + "Gender", "Unspecified"),
                    new XElement(AbNs + "TimeZone", "None")
                ),
                new XElement(AbNs + "propertiesChanged", ""),
                new XElement(AbNs + "fDeleted", "false"),
                new XElement(AbNs + "lastChange", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
            );

            if (isSelf)
            {
                contactElement.Element(AbNs + "contactInfo").Add(
                    new XElement(AbNs + "annotations",
                        new XElement(AbNs + "Annotation",
                            new XElement(AbNs + "Name", "MSN.IM.MBEA"),
                            new XElement(AbNs + "Value", "0")
                        ),
                        new XElement(AbNs + "Annotation",
                            new XElement(AbNs + "Name", "MSN.IM.GTC"),
                            new XElement(AbNs + "Value", "1")
                        ),
                        new XElement(AbNs + "Annotation",
                            new XElement(AbNs + "Name", "MSN.IM.BLP"),
                            new XElement(AbNs + "Value", "1")
                        )
                    )
                );
            }

            contactsElement.Add(contactElement);
        }

        return contactsElement;
    }

    private static async Task<string> HandleABFindContactsPaged(string requestBody)
    {
        try
        {
            var doc = XDocument.Parse(requestBody);
            var abNs = XNamespace.Get("http://www.msn.com/webservices/AddressBook");
            var ticketToken = doc.Descendants(abNs + "TicketToken").FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(ticketToken))
                return CreateErrorResponse("Invalid ticket token");

            var email = ticketToken.Split('&').FirstOrDefault(p => p.StartsWith("p="))?.Substring(2);
            if (string.IsNullOrEmpty(email))
                return CreateErrorResponse("Invalid email in token");

            var user = MsnServer.GetUserByEmail(email);
            if (user == null)
                return CreateErrorResponse("User not found");

            // Initialize collections if null
            user.Groups = user.Groups ?? new List<Group>();
            var contacts = MsnServer.GetContacts(user.Id, "FL") ?? new List<Contact>();
            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var created = user.CreatedDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            // Build groups XML
            var groupsBuilder = new StringBuilder();
            foreach (var group in user.Groups.Where(g => g != null))
            {
                groupsBuilder.Append($@"
            <Group xmlns=""http://www.msn.com/webservices/AddressBook"">
                <groupId>{group.Id}</groupId>
                <groupInfo>
                    <annotations>
                        <Annotation>
                            <Name>MSN.IM.Display</Name>
                            <Value>1</Value>
                        </Annotation>
                    </annotations>
                    <groupType>c8529ce2-6ead-434d-881f-341e17db3ff8</groupType>
                    <name>{WebUtility.HtmlEncode(group.Name)}</name>
                    <IsNotMobileVisible>false</IsNotMobileVisible>
                    <IsPrivate>false</IsPrivate>
                    <IsFavorite>true</IsFavorite>
                </groupInfo>
                <propertiesChanged />
                <fDeleted>false</fDeleted>
                <lastChange>{now}</lastChange>
            </Group>");
            }

            // Build contacts XML
            var contactsBuilder = new StringBuilder();
            foreach (var contact in contacts.Where(c => c != null))
            {
                var contactUser = MsnServer.GetUserById(contact.ContactId);
                if (contactUser == null) continue;

                var groupsXml = contact.Groups?.Count > 0 ?
                    $"<groupIds>{string.Join("", contact.Groups.Select(g => $"<guid>{g}</guid>"))}</groupIds>" :
                    "";

                contactsBuilder.Append($@"
            <Contact xmlns=""http://www.msn.com/webservices/AddressBook"">
                <contactId>{contactUser.UUID}</contactId>
                <contactInfo>
                    <contactType>Regular</contactType>
                    <quickName>{WebUtility.HtmlEncode(contactUser.FriendlyName)}</quickName>
                    <passportName>{contactUser.Email}</passportName>
                    <IsPassportNameHidden>false</IsPassportNameHidden>
                    <displayName>{WebUtility.HtmlEncode(contactUser.FriendlyName)}</displayName>
                    <puid>0</puid>
                    {groupsXml}
                    <CID>{contactUser.Id}</CID>
                    <IsNotMobileVisible>false</IsNotMobileVisible>
                    <isMobileIMEnabled>false</isMobileIMEnabled>
                    <isMessengerUser>true</isMessengerUser>
                    <isFavorite>false</isFavorite>
                    <isSmtp>false</isSmtp>
                    <hasSpace>false</hasSpace>
                    <spotWatchState>NoDevice</spotWatchState>
                    <birthdate>0001-01-01T00:00:00</birthdate>
                    <primaryEmailType>ContactEmailPersonal</primaryEmailType>
                    <PrimaryLocation>ContactLocationPersonal</PrimaryLocation>
                    <PrimaryPhone>ContactPhonePersonal</PrimaryPhone>
                    <IsPrivate>false</IsPrivate>
                    <Gender>Unspecified</Gender>
                    <TimeZone>None</TimeZone>
                </contactInfo>
                <propertiesChanged />
                <fDeleted>false</fDeleted>
                <lastChange>{now}</lastChange>
            </Contact>");
            }

            // Add self contact
            contactsBuilder.Append($@"
        <Contact xmlns=""http://www.msn.com/webservices/AddressBook"">
            <contactId>{user.UUID}</contactId>
            <contactInfo>
                <annotations>
                    <Annotation>
                        <Name>MSN.IM.MBEA</Name>
                        <Value>0</Value>
                    </Annotation>
                    <Annotation>
                        <Name>MSN.IM.GTC</Name>
                        <Value>0</Value>
                    </Annotation>
                    <Annotation>
                        <Name>MSN.IM.BLP</Name>
                        <Value>0</Value>
                    </Annotation>
                </annotations>
                <contactType>Me</contactType>
                <quickName>{WebUtility.HtmlEncode(user.FriendlyName)}</quickName>
                <passportName>{user.Email}</passportName>
                <IsPassportNameHidden>false</IsPassportNameHidden>
                <displayName>{WebUtility.HtmlEncode(user.FriendlyName)}</displayName>
                <puid>0</puid>
                <CID>{user.Id}</CID>
                <IsNotMobileVisible>false</IsNotMobileVisible>
                <isMobileIMEnabled>false</isMobileIMEnabled>
                <isMessengerUser>false</isMessengerUser>
                <isFavorite>false</isFavorite>
                <isSmtp>false</isSmtp>
                <hasSpace>false</hasSpace>
                <spotWatchState>NoDevice</spotWatchState>
                <birthdate>0001-01-01T00:00:00</birthdate>
                <primaryEmailType>ContactEmailPersonal</primaryEmailType>
                <PrimaryLocation>ContactLocationPersonal</PrimaryLocation>
                <PrimaryPhone>ContactPhonePersonal</PrimaryPhone>
                <IsPrivate>false</IsPrivate>
                <Gender>Unspecified</Gender>
                <TimeZone>None</TimeZone>
            </contactInfo>
            <propertiesChanged />
            <fDeleted>false</fDeleted>
            <lastChange>{now}</lastChange>
        </Contact>");

            // Build final response
            return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/AddressBook"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>12r1:{Guid.NewGuid()}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>contacts.msn.com</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <ABFindContactsPagedResponse xmlns=""http://www.msn.com/webservices/AddressBook"">
            <ABFindContactsPagedResult>
                <groups>
                    {groupsBuilder}
                </groups>
                <contacts>
                    {contactsBuilder}
                </contacts>
                <CircleResult>
                    <CircleTicket>&lt;?xml version=""1.0"" encoding=""utf-16""?&gt;&lt;SignedTicket xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" ver=""1"" keyVer=""1""&gt;&lt;Data&gt;tokenig&lt;/Data&gt;&lt;Sig&gt;a&lt;/Sig&gt;&lt;/SignedTicket&gt;</CircleTicket>
                </CircleResult>
                <Ab>
                    <abId>00000000-0000-0000-0000-000000000000</abId>
                    <abInfo>
                        <ownerPuid>0</ownerPuid>
                        <OwnerCID>{user.Id}</OwnerCID>
                        <ownerEmail>{user.Email}</ownerEmail>
                        <fDefault>true</fDefault>
                        <joinedNamespace>false</joinedNamespace>
                    </abInfo>
                    <lastChange>{now}</lastChange>
                    <DynamicItemLastChanged>0001-01-01T00:00:00</DynamicItemLastChanged>
                    <createDate>{created}</createDate>
                </Ab>
            </ABFindContactsPagedResult>
        </ABFindContactsPagedResponse>
    </soap:Body>
</soap:Envelope>";
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ABFindAll Error] {ex}");
            return CreateErrorResponse("Internal server error");
        }
    }

    private static XElement BuildAddressBookXml(User user)
    {
        return new XElement(AbNs + "ab",
            new XElement(AbNs + "abId", "00000000-0000-0000-0000-000000000000"),
            new XElement(AbNs + "abInfo",
                new XElement(AbNs + "ownerPuid", "0"),
                new XElement(AbNs + "OwnerCID", "0"),
                new XElement(AbNs + "ownerEmail", user.Email),
                new XElement(AbNs + "fDefault", "true"),
                new XElement(AbNs + "joinedNamespace", "false"),
                new XElement(AbNs + "IsBot", "false"),
                new XElement(AbNs + "IsParentManaged", "false"),
                new XElement(AbNs + "SubscribeExternalPartner", "false"),
                new XElement(AbNs + "NotifyExternalPartner", "false"),
                new XElement(AbNs + "AddressBookType", "Individual")
            ),
            new XElement(AbNs + "lastChange", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
            new XElement(AbNs + "DynamicItemLastChanged", "0001-01-01T00:00:00"),
            new XElement(AbNs + "createDate", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
        );
    }

    private static XElement BuildMembersXml(List<Contact> contacts, int userId, bool includeDisplayName)
    {
        var membersElement = new XElement(AbNs + "Members");

        foreach (var contact in contacts)
        {
            var contactUser = MsnServer.GetUserByEmail(contact.ContactId.ToString()); // Adjust based on your contact structure
            if (contactUser == null) continue;

            var memberElement = new XElement(AbNs + "Member",
                new XAttribute(XNamespace.Get("http://www.w3.org/2001/XMLSchema-instance") + "type", "PassportMember"),
                new XElement(AbNs + "MembershipId", contact.Id),
                new XElement(AbNs + "Type", "Passport"),
                new XElement(AbNs + "State", "Accepted"),
                new XElement(AbNs + "Deleted", "false"),
                new XElement(AbNs + "LastChanged", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                new XElement(AbNs + "JoinedDate", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                new XElement(AbNs + "ExpirationDate", "0001-01-01T00:00:00"),
                new XElement(AbNs + "Changes", ""),
                new XElement(AbNs + "PassportName", contactUser.Email),
                new XElement(AbNs + "IsPassportNameHidden", "false"),
                new XElement(AbNs + "PassportId", "0"),
                new XElement(AbNs + "CID", "0"),
                new XElement(AbNs + "PassportChanges", ""),
                new XElement(AbNs + "LookedupByCID", "false")
            );

            if (includeDisplayName)
            {
                memberElement.Add(new XElement(AbNs + "DisplayName", contactUser.FriendlyName ?? contactUser.Email.Split('@')[0]));
            }

            membersElement.Add(memberElement);
        }

        return membersElement;
    }


    private static async Task HandleClientConfigRequest(string soapAction, string requestBody, HttpListenerResponse response)
    {
        string action = soapAction.Split('/').Last().Replace("\"", "");
        string responseXml;

        switch (action)
        {
            case "GetClientConfig":
                responseXml = GenerateClientConfigResponse();
                break;

            default:
                Console.WriteLine($"[ClientConfig] No handler for action: {action}");
                response.StatusCode = 404;
                response.Close();
                return;
        }

        await SendSoapResponse(response, responseXml);
    }

    private static string GenerateClientConfigResponse()
    {
        // Get the server's IP address
        string serverIp = "127.0.0.1"; // Default to localhost
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            serverIp = host.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)?.ToString() ?? serverIp;
        }
        catch { }

        string config = $@"<MsgrConfig>
    <Simple>
        <Config>
            <ExpiresInDays>0</ExpiresInDays>
        </Config>
        <DisablePhoneDialer>1</DisablePhoneDialer>
        <MinFlashPlayer BuildNumber=""60"" MajorVersion=""7"" MinorVersion=""0""></MinFlashPlayer>
        <Relay>
            <Enabled>0</Enabled>
        </Relay>
        <TrustedDomains>
            <domain name=""escargot.chat""/>
            <domain name=""mconf.escargot.nina.chat""/>
            <domain name=""apps.escargot.nina.chat""/>
            <domain name=""static.levelleap.com""/>
        </TrustedDomains>
        <ErrorResponseTable>
            <Feature type=""0"" name=""Login"">
                <Entry hr=""0x80072EE7"" action=""3""></Entry>
                <Entry hr=""0x81000306"" action=""3""></Entry>
                <Entry hr=""0x80072EFD"" action=""3""></Entry>
                <Entry hr=""0x81000362"" action=""3""></Entry>
                <Entry hr=""0x8100030E"" action=""3""></Entry>
                <Entry hr=""0x80072745"" action=""3""></Entry>
                <Entry hr=""0x800701F7"" action=""3""></Entry>
                <Entry hr=""0x80072EFF"" action=""3""></Entry>
                <Entry hr=""0x81000363"" action=""3""></Entry>
                <Entry hr=""0x81000395"" action=""3""></Entry>
                <Entry hr=""0x800B0001"" action=""3""></Entry>
                <Entry hr=""0x81000323"" action=""3""></Entry>
                <Entry hr=""0x80072F19"" action=""3""></Entry>
                <Entry hr=""0x800701F8"" action=""3""></Entry>
                <Entry hr=""0x80072746"" action=""3""></Entry>
                <Entry hr=""0x800701F6"" action=""3""></Entry>
                <Entry hr=""0x81000377"" action=""3""></Entry>
                <Entry hr=""0x81000314"" action=""3""></Entry>
                <Entry hr=""0x81000378"" action=""3""></Entry>
                <Entry hr=""0x80072EFF"" action=""3""></Entry>
                <Entry hr=""0x80070190"" action=""3""></Entry>
                <Entry hr=""0x80070197"" action=""3""></Entry>
                <Entry hr=""0x80048820"" action=""3""></Entry>
                <Entry hr=""0x80048829"" action=""3""></Entry>
                <Entry hr=""0x80048834"" action=""3""></Entry>
                <Entry hr=""0x80048852"" action=""3""></Entry>
                <Entry hr=""0x8004886a"" action=""3""></Entry>
                <Entry hr=""0x8004886b"" action=""3""></Entry>
            </Feature>
            <Feature type=""2"" name=""MapFile"">
                <Entry hr=""0x810003F0"" action=""3""></Entry>
                <Entry hr=""0x810003F1"" action=""3""></Entry>
                <Entry hr=""0x810003F2"" action=""3""></Entry>
                <Entry hr=""0x810003F3"" action=""3""></Entry>
                <Entry hr=""0x810003F4"" action=""3""></Entry>
                <Entry hr=""0x810003F5"" action=""3""></Entry>
                <Entry hr=""0x810003F6"" action=""3""></Entry>
                <Entry hr=""0x810003F7"" action=""3""></Entry>
            </Feature>
        </ErrorResponseTable>
    </Simple>
    <TabConfig>
        <msntabdata>
            <tab>
    <type>page</type>
    <contenturl>https://escargot.chat/forums/</contenturl>
    <hiturl>https://escargot.chat/forums/</hiturl>
    <image>http://storage.levelleap.com/nina/clients/msnp/tabicon/escargot.png</image>
    <name>Escargot Forums</name>
    <tooltip>Escargot Forums</tooltip>
    <siteid>0</siteid>
    <notificationid>0</notificationid>
</tab><tab>
    <type>page</type>
    <contenturl>http://m.facebook.com</contenturl>
    <hiturl>http://m.facebook.com</hiturl>
    <image>http://storage.levelleap.com/nina/clients/msnp/tabicon/facebook.png</image>
    <name>Facebook</name>
    <tooltip>Facebook</tooltip>
    <siteid>0</siteid>
    <notificationid>0</notificationid>
</tab><tab>
    <type>page</type>
    <contenturl>http://m.youtube.com</contenturl>
    <hiturl>http://m.youtube.com</hiturl>
    <image>http://storage.levelleap.com/nina/clients/msnp/tabicon/youtube.png</image>
    <name>YouTube</name>
    <tooltip>YouTube</tooltip>
    <siteid>0</siteid>
    <notificationid>0</notificationid>
</tab><tab>
    <type>page</type>
    <contenturl>http://legacy.nina.chat/weather/?small=true</contenturl>
    <hiturl>http://legacy.nina.chat/weather/</hiturl>
    <image>http://storage.levelleap.com/nina/clients/msnp/tabicon/msn-weather.png</image>
    <name>NINA Weather</name>
    <tooltip>NINA Weather</tooltip>
    <siteid>0</siteid>
    <notificationid>0</notificationid>
</tab>
        </msntabdata>
        <msntabsettings>
            <oemdisplaylimit>1</oemdisplaylimit>
            <oemtotallimit>1</oemtotallimit>
        </msntabsettings>
    </TabConfig>
    <AbchCfg>
        <abchconfig>
            <url>https://ds.escargot.nina.chat/abservice/abservice.asmx</url>
        </abchconfig>
    </AbchCfg>
    <SpacesDownload>http://spaces.live.com/downloadA</SpacesDownload>
    <LocalizedConfig Market=""en-US"">
        <SpacesDownload>http://spaces.live.com/downloadB</SpacesDownload>
        <DynamicContent>
            <premium>
                <winks2 visibleto=""7.0.729 and greater"">
                    <providersiteid>60971</providersiteid>
                    <providerurl>http://apps.escargot.nina.chat/content/winks/</providerurl>
                    <slots>
                        <URL id=""1"">http://apps.escargot.nina.chat/content/winks/?id=screen-punch</URL>
                        <URL id=""2"">http://apps.escargot.nina.chat/content/winks/?id=sup-dawg</URL>
                        <URL id=""3"">http://apps.escargot.nina.chat/content/winks/?id=flower-fart</URL>
                        <URL id=""4"">http://apps.escargot.nina.chat/content/winks/?id=sup-dawg</URL>
                        <URL id=""5"">http://apps.escargot.nina.chat/content/winks/?id=pc-explosion</URL>
                        <URL id=""6"">http://apps.escargot.nina.chat/content/winks/?id=smiley-faces</URL>
                        <URL id=""7"">http://apps.escargot.nina.chat/content/winks/?id=break-dancer</URL>
                        <URL id=""8"">http://apps.escargot.nina.chat/content/winks/?id=bugs-bunny</URL>
                    </slots>
                </winks2>
            </premium>
        </DynamicContent>
        <AdMainConfig>
            <TextAdRefresh>1</TextAdRefresh>
            <TextAdServer>http://mconf.escargot.nina.chat/ads/msn/text/</TextAdServer>
            <AdBanner20URL Refresh=""300"">http://mconf.escargot.nina.chat/ads/msn/banners/?id=$PUID$</AdBanner20URL>
        </AdMainConfig>
        <AppDirConfig>
            <AppDirPageURL>http://apps.escargot.nina.chat/activities/directory/?a=b</AppDirPageURL>
            <AppDirSeviceURL>http://apps.escargot.nina.chat/activities/service/</AppDirSeviceURL>
            <AppDirVersionURL>http://apps.escargot.nina.chat/activities/version/</AppDirVersionURL>
        </AppDirConfig>
        <MSNSearch>
            <DesktopInstallURL>https://www.google.com/search?q=$QUERY$&amp;source=hp</DesktopInstallURL>
            <ImagesURL>https://www.google.com/search?q=$QUERY$&amp;source=lnms&amp;tbm=isch</ImagesURL>
            <NearMeURL>https://www.google.com/search?q=$QUERY$&amp;source=hp</NearMeURL>
            <NewsURL>https://www.google.com/search?q=$QUERY$&amp;source=lmns&amp;tbm=vid</NewsURL>
            <SearchKidsURL>https://www.google.com/search?q=$QUERY$&amp;source=hp&amp;safe=active</SearchKidsURL>
            <SearchURL>https://www.google.com/search?q=$QUERY$&amp;source=hp</SearchURL>
            <SharedSearchURL>https://www.google.com/search?q=$QUERY$&amp;source=hp</SharedSearchURL>
            <SharedSearchURL2>https://www.google.com/search?q=$QUERY$&amp;source=hp</SharedSearchURL2>
        </MSNSearch>
        <MsnTodayConfig>
            <MsnTodayURL>https://escargot.chat/today/msn/</MsnTodayURL>
        </MsnTodayConfig>
        <MusicIntegration URL=""https://www.last.fm/search/tracks?q=$ARTIST$+$TITLE$""/>
        <RL>
            <ViewProfileURL>http://g.msn.com/5meen_us/106?%1&amp;Plcid=%2!hs!&amp;%3&amp;Country=%4!hs!&amp;BrandID=%5&amp;passport=%6</ViewProfileURL>
        </RL>
        <TermsOfUse>
            <TermsOfUseSID>956</TermsOfUseSID>
            <TermsOfUseURL>https://escargot.chat/legal/terms/</TermsOfUseURL>
        </TermsOfUse>
    </LocalizedConfig>
</MsgrConfig>>";

        return $@"<?xml version='1.0' encoding='utf-8'?>
<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xsd='http://www.w3.org/2001/XMLSchema'>
    <soap:Header>
        <ServiceHeader xmlns='http://www.msn.com/webservices/Messenger/Client'>
            <Version>15.01.1408.0000</Version>
            <CacheKey>12r1:{Guid.NewGuid()}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>messenger.msn.com</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <GetClientConfigResponse xmlns='http://www.msn.com/webservices/Messenger/Client'>
            <GetClientConfigResult>
                {config}
            </GetClientConfigResult>
        </GetClientConfigResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private static XElement BuildMembershipsXml(List<Contact> allowContacts, List<Contact> blockContacts, List<Contact> reverseContacts, int userId)
    {
        var membershipsElement = new XElement(AbNs + "Memberships");

        if (allowContacts.Any())
        {
            membershipsElement.Add(
                new XElement(AbNs + "Membership",
                    new XElement(AbNs + "MemberRole", "AL-"),
                    BuildMembersXml(allowContacts, userId, false),
                    new XElement(AbNs + "MembershipIsComplete", "true")
                )
            );
        }

        if (blockContacts.Any())
        {
            membershipsElement.Add(
                new XElement(AbNs + "Membership",
                    new XElement(AbNs + "MemberRole", "BL-"),
                    BuildMembersXml(blockContacts, userId, false),
                    new XElement(AbNs + "MembershipIsComplete", "true")
                )
            );
        }

        if (reverseContacts.Any())
        {
            membershipsElement.Add(
                new XElement(AbNs + "Membership",
                    new XElement(AbNs + "MemberRole", "RL-"),
                    BuildMembersXml(reverseContacts, userId, true),
                    new XElement(AbNs + "MembershipIsComplete", "true")
                )
            );
        }

        return membershipsElement;
    }

    private static async Task<string> HandleFindMembership(string requestBody)
    {
        try
        {
            var doc = XDocument.Parse(requestBody);
            var abNs = XNamespace.Get("http://www.msn.com/webservices/AddressBook");
            var ticketToken = doc.Descendants(abNs + "TicketToken").FirstOrDefault()?.Value;

            if (string.IsNullOrEmpty(ticketToken))
            {
                return CreateErrorResponse("Invalid ticket token");
            }

            var email = ticketToken.Split(new[] { "p=" }, StringSplitOptions.None).Last();
            var user = MsnServer.GetUserByEmail(email);
            if (user == null)
            {
                return CreateErrorResponse("User not found");
            }

            // Get contacts from database
            var allowContacts = MsnServer.GetContacts(user.Id, "AL");
            var blockContacts = MsnServer.GetContacts(user.Id, "BL");
            var reverseContacts = MsnServer.GetReverseContacts(user.Id);

            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var cacheKey = $"12r1:{Guid.NewGuid()}";

            // Build members XML
            var allowMembersBuilder = new StringBuilder();
            foreach (var contact in allowContacts)
            {
                var contactUser = MsnServer.GetUserById(contact.ContactId);
                if (contactUser == null) continue;

                allowMembersBuilder.Append($@"
                <Member xmlns=""http://www.msn.com/webservices/AddressBook"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""PassportMember"">
                    <MembershipId>AL-{contactUser.UUID}</MembershipId>
                    <Type>Passport</Type>
                    <State>Accepted</State>
                    <Deleted>false</Deleted>
                    <LastChanged>{now}</LastChanged>
                    <JoinedDate>{now}</JoinedDate>
                    <ExpirationDate>0001-01-01T00:00:00</ExpirationDate>
                    <Changes />
                    <PassportName>{contactUser.Email}</PassportName>
                    <IsPassportNameHidden>false</IsPassportNameHidden>
                    <PassportId>0</PassportId>
                    <CID>{contactUser.Id}</CID>
                    <PassportChanges />
                    <LookedupByCID>false</LookedupByCID>
                </Member>");
            }

            var blockMembersBuilder = new StringBuilder();
            foreach (var contact in blockContacts)
            {
                var contactUser = MsnServer.GetUserById(contact.ContactId);
                if (contactUser == null) continue;

                blockMembersBuilder.Append($@"
                <Member xmlns=""http://www.msn.com/webservices/AddressBook"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""PassportMember"">
                    <MembershipId>BL-{contactUser.UUID}</MembershipId>
                    <Type>Passport</Type>
                    <State>Accepted</State>
                    <Deleted>false</Deleted>
                    <LastChanged>{now}</LastChanged>
                    <JoinedDate>{now}</JoinedDate>
                    <ExpirationDate>0001-01-01T00:00:00</ExpirationDate>
                    <Changes />
                    <PassportName>{contactUser.Email}</PassportName>
                    <IsPassportNameHidden>false</IsPassportNameHidden>
                    <PassportId>0</PassportId>
                    <CID>{contactUser.Id}</CID>
                    <PassportChanges />
                    <LookedupByCID>false</LookedupByCID>
                </Member>");
            }

            var reverseMembersBuilder = new StringBuilder();
            foreach (var contact in reverseContacts)
            {
                var contactUser = MsnServer.GetUserById(contact.UserId);
                if (contactUser == null) continue;

                reverseMembersBuilder.Append($@"
                <Member xmlns=""http://www.msn.com/webservices/AddressBook"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xsi:type=""PassportMember"">
                    <MembershipId>RL-{contactUser.UUID}</MembershipId>
                    <Type>Passport</Type>
                    <State>Accepted</State>
                    <Deleted>false</Deleted>
                    <LastChanged>{now}</LastChanged>
                    <JoinedDate>{now}</JoinedDate>
                    <ExpirationDate>0001-01-01T00:00:00</ExpirationDate>
                    <Changes />
                    <PassportName>{contactUser.Email}</PassportName>
                    <IsPassportNameHidden>false</IsPassportNameHidden>
                    <PassportId>0</PassportId>
                    <CID>{contactUser.Id}</CID>
                    <PassportChanges />
                    <LookedupByCID>false</LookedupByCID>
                    <DisplayName>{WebUtility.HtmlEncode(contactUser.FriendlyName)}</DisplayName>
                </Member>");
            }

            // Build response using template
            var response = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/AddressBook"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>contacts.msn.com</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <FindMembershipResponse xmlns=""http://www.msn.com/webservices/AddressBook"">
            <FindMembershipResult>
                <Services>
                    <Service>
                        <Memberships>
                            <Membership>
                                <MemberRole>Allow</MemberRole>
                                <Members>
                                    {allowMembersBuilder}
                                </Members>
                                <MembershipIsComplete>true</MembershipIsComplete>
                            </Membership>
                            <Membership>
                                <MemberRole>Block</MemberRole>
                                <Members>
                                    {blockMembersBuilder}
                                </Members>
                                <MembershipIsComplete>true</MembershipIsComplete>
                            </Membership>
                            <Membership>
                                <MemberRole>Reverse</MemberRole>
                                <Members>
                                    {reverseMembersBuilder}
                                </Members>
                                <MembershipIsComplete>true</MembershipIsComplete>
                            </Membership>
                            <Membership>
                                <MemberRole>Pending</MemberRole>
                                <Members/>
                                <MembershipIsComplete>true</MembershipIsComplete>
                            </Membership>
                        </Memberships>
                    </Service>
                </Services>
                <PartnerScenario>Initial</PartnerScenario>
                <CacheKey>{cacheKey}</CacheKey>
                <LastChanged>{now}</LastChanged>
            </FindMembershipResult>
        </FindMembershipResponse>
    </soap:Body>
</soap:Envelope>";

            return response;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FindMembership Error] {ex.Message}");
            return CreateErrorResponse("Internal server error");
        }
    }




    private static XElement BuildMembership(string role, List<Contact> contacts, User user, XNamespace abNs, XNamespace xsi)
    {
        if (contacts.Count == 0)
        {
            return null;
        }

        var members = new XElement(abNs + "Members");
        foreach (var contact in contacts)
        {
            var contactUser = MsnServer.GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            members.Add(new XElement(abNs + "Member",
                new XAttribute(xsi + "type", "PassportMember"),
                new XElement(abNs + "MembershipId", $"{role}-{contactUser.UUID}"),
                new XElement(abNs + "Type", "Passport"),
                new XElement(abNs + "State", "Accepted"),
                new XElement(abNs + "Deleted", "false"),
                new XElement(abNs + "LastChanged", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")),
                new XElement(abNs + "JoinedDate", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")),
                new XElement(abNs + "ExpirationDate", "0001-01-01T00:00:00"),
                new XElement(abNs + "Changes", ""),
                new XElement(abNs + "PassportName", contactUser.Email),
                new XElement(abNs + "IsPassportNameHidden", "false"),
                new XElement(abNs + "PassportId", "0"),
                new XElement(abNs + "CID", contactUser.Id.ToString()),
                new XElement(abNs + "PassportChanges", ""),
                new XElement(abNs + "LookedupByCID", "false"),
                role == "Reverse" ? new XElement(abNs + "DisplayName", contactUser.FriendlyName) : null
            ));
        }

        return new XElement(abNs + "Membership",
            new XElement(abNs + "MemberRole", role),
            members,
            new XElement(abNs + "MembershipIsComplete", "true")
        );
    }

    private static XElement BuildOwnerNamespaceXml(User user)
    {
        return new XElement(AbNs + "OwnerNamespace",
            new XElement(AbNs + "Info",
                new XElement(AbNs + "Handle",
                    new XElement(AbNs + "Id", "00000000-0000-0000-0000-000000000000"),
                    new XElement(AbNs + "IsPassportNameHidden", "false"),
                    new XElement(AbNs + "CID", "0")
                ),
                new XElement(AbNs + "CreatorPuid", "0"),
                new XElement(AbNs + "CreatorCID", "0"),
                new XElement(AbNs + "CreatorPassportName", user.Email)
            ),
            new XElement(AbNs + "Changes", ""),
            new XElement(AbNs + "CreateDate", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
            new XElement(AbNs + "LastChange", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))
        );
    }
    private static async Task SendSoapResponse(HttpListenerResponse response, string responseXml)
    {
        try
        {
            byte[] buffer = Encoding.UTF8.GetBytes(responseXml);
            response.ContentType = "text/xml; charset=utf-8";
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            response.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SendSoapResponse Error] {ex.Message}");
        }
    }

    private static string CreateErrorResponse(string message)
    {
        return $@"<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
            <soap:Body>
                <soap:Fault>
                    <faultcode>soap:Server</faultcode>
                    <faultstring>{message}</faultstring>
                </soap:Fault>
            </soap:Body>
        </soap:Envelope>";
    }
}

public class StorageService
{
    private readonly string _storageHost;
    private readonly string _storagePath;

    public StorageService(string storageHost = "storage.msn.com", string baseStoragePath = "Storage")
    {
        _storageHost = storageHost;
        _storagePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, baseStoragePath);
        Directory.CreateDirectory(_storagePath);
    }

    public async Task<string> HandleRequest(string action, string requestBody, string ticketToken)
    {
        try
        {
            // Common authentication and setup
            var (email, user) = await AuthenticateUser(ticketToken);
            if (user == null) return CreateErrorResponse("Authentication failed");

            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var cacheKey = $"12r1:{Guid.NewGuid()}";
            var cid = FormatCid(user.UUID);

            switch (action)
            {
                case "GetProfile":
                    return await HandleGetProfile(user, cid, now, cacheKey);

                case "FindDocuments":
                    return await HandleFindDocuments(user, cid, now, cacheKey);

                case "UpdateProfile":
                    return await HandleUpdateProfile(requestBody, user, cid, now, cacheKey);

                case "DeleteRelationships":
                    return await HandleDeleteRelationships(requestBody, user, cid, now, cacheKey);

                case "CreateDocument":
                    return await HandleCreateDocument(requestBody, user, cid, now, cacheKey);

                case "CreateRelationships":
                    return await HandleCreateRelationships(requestBody, user, cid, now, cacheKey);

                case "ShareItem":
                    return await HandleShareItem(requestBody, user, cid, now, cacheKey);

                default:
                    return CreateErrorResponse("Unsupported action", expected: true);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[StorageService Error] {ex}");
            return CreateErrorResponse("Internal server error");
        }
    }

    private async Task<(string, User)> AuthenticateUser(string ticketToken)
    {
        if (string.IsNullOrEmpty(ticketToken))
            return (null, null);

        var email = ticketToken.Split('&').FirstOrDefault(p => p.StartsWith("p="))?.Substring(2);
        if (string.IsNullOrEmpty(email))
            return (null, null);

        var user = MsnServer.GetUserByEmail(email);
        return (email, user);
    }

    private string FormatCid(string uuid)
    {
        return $"U{uuid.Replace("-", "").ToUpper()}";
    }

    #region Action Handlers

    private async Task<string> HandleGetProfile(User user, string cid, string timestamp, string cacheKey)
    {
        return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/StorageService"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>{_storageHost}</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <GetProfileResponse xmlns=""http://www.msn.com/webservices/StorageService"">
            <GetProfileResult>
                <Profile>
                    <CID>{cid}</CID>
                    <PassportName>{user.Email}</PassportName>
                    <DisplayName>{SecurityElement.Escape(user.FriendlyName)}</DisplayName>
                    <LastChange>{timestamp}</LastChange>
                    <PropertiesChanged />
                    </Picture>
                </Profile>
            </GetProfileResult>
        </GetProfileResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private async Task<string> HandleFindDocuments(User user, string cid, string timestamp, string cacheKey)
    {
        // Implement document search logic here
        return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/StorageService"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>{_storageHost}</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <FindDocumentsResponse xmlns=""http://www.msn.com/webservices/StorageService"">
            <FindDocumentsResult>
                <Documents />
                <TotalAvailable>0</TotalAvailable>
            </FindDocumentsResult>
        </FindDocumentsResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private async Task<string> HandleUpdateProfile(string requestBody, User user, string cid, string timestamp, string cacheKey)
    {
        // Parse and apply profile updates
        var doc = XDocument.Parse(requestBody);
        var ns = XNamespace.Get("http://www.msn.com/webservices/StorageService");

        var displayName = doc.Descendants(ns + "DisplayName").FirstOrDefault()?.Value;
        if (!string.IsNullOrEmpty(displayName))
        {
            user.FriendlyName = displayName;
            await MsnServer.SaveUserToDatabase(user);
        }

        return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/StorageService"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>{_storageHost}</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <UpdateProfileResponse xmlns=""http://www.msn.com/webservices/StorageService"">
            <UpdateProfileResult>
                <Profile>
                    <CID>{cid}</CID>
                    <PassportName>{user.Email}</PassportName>
                    <DisplayName>{SecurityElement.Escape(user.FriendlyName)}</DisplayName>
                    <LastChange>{timestamp}</LastChange>
                    <PropertiesChanged />
                </Profile>
            </UpdateProfileResult>
        </UpdateProfileResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private async Task<string> HandleDeleteRelationships(string requestBody, User user, string cid, string timestamp, string cacheKey)
    {
        // Implement relationship deletion logic
        return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/StorageService"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>{_storageHost}</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <DeleteRelationshipsResponse xmlns=""http://www.msn.com/webservices/StorageService"">
            <DeleteRelationshipsResult>
                <DeletedCount>0</DeletedCount>
            </DeleteRelationshipsResult>
        </DeleteRelationshipsResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private async Task<string> HandleCreateDocument(string requestBody, User user, string cid, string timestamp, string cacheKey)
    {
        var doc = XDocument.Parse(requestBody);
        var ns = XNamespace.Get("http://www.msn.com/webservices/StorageService");

        var name = doc.Descendants(ns + "Name").FirstOrDefault()?.Value;
        var streamType = doc.Descendants(ns + "DocumentStreamType").FirstOrDefault()?.Value;
        var mimeType = doc.Descendants(ns + "MimeType").FirstOrDefault()?.Value;
        var data = doc.Descendants(ns + "Data").FirstOrDefault()?.Value;

        return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/StorageService"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>{_storageHost}</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <CreateDocumentResponse xmlns=""http://www.msn.com/webservices/StorageService"">
            <CreateDocumentResult>
                <Document>
                    <Name>{SecurityElement.Escape(name)}</Name>
                    <DocumentStreamType>{streamType}</DocumentStreamType>
                    <LastChange>{timestamp}</LastChange>
                    </Url>
                </Document>
            </CreateDocumentResult>
        </CreateDocumentResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private async Task<string> HandleCreateRelationships(string requestBody, User user, string cid, string timestamp, string cacheKey)
    {
        // Implement relationship creation logic
        return $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
    <soap:Header>
        <ServiceHeader xmlns=""http://www.msn.com/webservices/StorageService"">
            <Version>15.01.1408.0000</Version>
            <CacheKey>{cacheKey}</CacheKey>
            <CacheKeyChanged>true</CacheKeyChanged>
            <PreferredHostName>{_storageHost}</PreferredHostName>
            <SessionId>{Guid.NewGuid()}</SessionId>
        </ServiceHeader>
    </soap:Header>
    <soap:Body>
        <CreateRelationshipsResponse xmlns=""http://www.msn.com/webservices/StorageService"">
            <CreateRelationshipsResult>
                <CreatedCount>0</CreatedCount>
            </CreateRelationshipsResult>
        </CreateRelationshipsResponse>
    </soap:Body>
</soap:Envelope>";
    }

    private async Task<string> HandleShareItem(string requestBody, User user, string cid, string timestamp, string cacheKey)
    {
        // Implement item sharing logic
        return CreateErrorResponse("ShareItem not implemented", expected: true);
    }

    #endregion

    private string CreateErrorResponse(string message, bool expected = false)
    {
        return $@"<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
            <soap:Body>
                <soap:Fault>
                    <faultcode>soap:{(expected ? "Client" : "Server")}</faultcode>
                    <faultstring>{SecurityElement.Escape(message)}</faultstring>
                </soap:Fault>
            </soap:Body>
        </soap:Envelope>";
    }
}
