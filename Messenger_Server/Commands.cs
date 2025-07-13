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
using System.Text.Unicode;
using System.Threading.Tasks;
using System.Transactions;
using System.Xml;
using System.Xml.Linq;
using static System.Net.Mime.MediaTypeNames;
using static ModelClasses;
using static Functions;
using static Global;

class Commands {

    public static string ExtractCommandFromXml(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        Console.WriteLine($"[RAW INPUT] {input}");

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
                lastClosingBracketPos = i;
            }
        }

        if (extractedXml.Length > 0)
        {
            string xmlContent = extractedXml.ToString();
            Console.WriteLine($"[EXTRACTED XML CONTENT]\n{FormatXml(xmlContent)}");
        }

        if (lastClosingBracketPos >= 0 && lastClosingBracketPos < input.Length - 1)
        {
            string remainingText = input.Substring(lastClosingBracketPos + 1).Trim();
            if (!string.IsNullOrEmpty(remainingText))
            {
                Console.WriteLine($"[CLEAN COMMAND] {remainingText}");
                return remainingText;
            }
        }

        return extractedXml.Length > 0 ? extractedXml.ToString() : input;
    }

    public static async Task HandleNsClientAsync(TcpClient client)
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

    public static async Task HandleRegCommand(NetworkStream stream, User currentUser, string[] parts, int version)
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
            await SaveUserToDatabase(currentUser);

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

    public static async Task HandleAdgCommand(NetworkStream stream, User currentUser, string[] parts, int version)
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
            await SaveUserToDatabase(currentUser);

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

    public static async Task<int> HandleVerCommand(NetworkStream stream, string[] parts, int currentVersion)
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

    public static async Task<int> HandleURLCommand(NetworkStream stream, string[] parts, int currentVersion)
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

    public static async Task<int> HandleBlpCommand(NetworkStream stream, string[] parts)
    {
        string response = string.Join(" ", parts) + "\r\n";
        await SendAsync(stream, response);
        return 0;
    }

    public static async Task<int> HandleAdlCommand(NetworkStream stream, string[] parts)
    {
        string trid = parts[1];
        string response = $"ADL {trid} OK\r\n";
        await SendAsync(stream, response);
        return 0;
    }

    public static async Task<(User updatedUser, int updatedVersion)> HandleUsrCommand(
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

    public static async Task HandleUuxCommand(
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

    public static async Task HandleXfrCommand(NetworkStream stream, User currentUser, int version, string[] parts)
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

    public static async Task HandleXfrNsCommand(NetworkStream stream, User currentUser, int version, string trid)
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

    public static async Task HandleXfrSbCommand(NetworkStream stream, User currentUser, int version, string trid)
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

    public static async Task HandleGcfCommand(NetworkStream stream, string[] parts)
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

    public static async Task HandleSbClientAsync(TcpClient client)
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


    public static async Task<SwitchboardSession> HandleSbUsrCommand(
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

    public static async Task<SwitchboardSession> HandleCalCommand(
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

    public static async Task<SwitchboardSession> HandleAnsCommand(
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

    public static async Task<SwitchboardSession> HandleIroCommand(
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

    public static async Task<SwitchboardSession> HandleMsgCommand(
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

    public static async Task<SwitchboardSession> HandleByeCommand(
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

    public static async Task HandleSbOutCommand(NetworkStream stream, SwitchboardSession session)
    {
        if (session != null)
        {
            await HandleSessionDisconnect(session);
        }
        await SendSbResponse(stream, "OUT");
    }

    public static async Task HandleOutCommand(NetworkStream stream, User user)
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

    public static async Task HandleChgCommand(NetworkStream stream, User currentUser, string[] parts, int version)
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

    public static async Task HandleSynCommand(NetworkStream stream, User user, int version, string trid, string syncId)
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
            var contactResults = lists.Select(list => GetContacts(user.Id, list)).ToList();
            var reverseContacts = GetReverseContacts(user.Id);

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

    public static async Task HandleAdcCommand(NetworkStream stream, User currentUser, string[] parts)
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

    public static async Task HandlePrpCommand(NetworkStream stream, User currentUser, string[] parts, int version)
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

    public static async Task HandleAddCommand(NetworkStream stream, User currentUser, string[] parts)
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

    public static async Task HandleReaCommand(NetworkStream stream, User currentUser, string[] parts, int version)
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

}
