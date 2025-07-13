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
using static Global;
using static ModelClasses;

class Functions {
    public static async Task BroadcastChatMessage(
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

    public static User GetUserByEmail(string email)
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

    public static User GetUserById(int id)
    {
        return _users.FirstOrDefault(u => u.Id == id);
    }

    public static List<Contact> GetContacts(int userId, string list = null)
    {
        return _contacts.Where(c =>
            c.UserId == userId &&
            (list == null || c.List.Equals(list, StringComparison.OrdinalIgnoreCase))
        ).ToList();
    }

    public static async Task NotifyBuddiesOfChanges(User user, string newStatus,
        string capabilities, string msnObject)
    {
        if (user == null) return;

        // Get contacts who have this user in their Allow list
        var alContacts = GetReverseContacts(user.Id, "AL");

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
            var contactUser = GetUserById(contact.UserId);
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

    public static async Task SendLegacyContactListWithStatus(NetworkStream stream, string list, int userId, int version, string trid, int syncId)
    {
        var contacts = GetContacts(userId, list);
        int total = contacts.Count;

        if (total == 0)
        {
            await SendAsync(stream, $"LST {trid} {list} {syncId} 0 0\r\n");
            return;
        }

        for (int i = 0; i < contacts.Count; i++)
        {
            var contact = contacts[i];
            var contactUser = GetUserById(contact.ContactId);
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

    public static async Task SendLegacyReverseContactListWithStatus(NetworkStream stream, int userId, int version, string trid, int syncId)
    {
        var contacts = GetReverseContacts(userId);
        int total = contacts.Count;

        if (total == 0)
        {
            await SendAsync(stream, $"LST {trid} RL {syncId} 0 0\r\n");
            return;
        }

        for (int i = 0; i < contacts.Count; i++)
        {
            var contact = contacts[i];
            var contactUser = GetUserById(contact.UserId);
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

    public static async Task SendContactListWithStatus(NetworkStream stream, string list, int userId, int version)
    {
        var contacts = GetContacts(userId, list);

        foreach (var contact in contacts)
        {
            var contactUser = GetUserById(contact.ContactId);
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

    public static async Task SendReverseContactListWithStatus(NetworkStream stream, int userId, int version)
    {
        var reverseContacts = GetReverseContacts(userId);

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

    public static int GetListNumber(string list)
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

    public static async Task HandleMfnProperty(NetworkStream stream, User currentUser, string transactionId, string newFriendlyName, int version)
    {
        // Update friendly name
        currentUser.FriendlyName = newFriendlyName;
        await SaveUserToDatabase(currentUser);

        // Send confirmation
        await SendAsync(stream, $"PRP {transactionId} MFN {newFriendlyName}\r\n");

        // Notify contacts
        var contacts = GetContacts(currentUser.Id, "FL");
        foreach (var contact in contacts)
        {
            var contactUser = GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            // Check if the contact has us in their FL list
            var reverseContacts = GetContacts(contactUser.Id, "FL")
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

    public static async Task NotifyBuddiesOfPresence(User user, string notificationStatus)
    {
        if (user == null) return;

        // Get contacts who have this user in their Allow list
        var alContacts = GetReverseContacts(user.Id, "AL");
        Console.WriteLine($"[NOTIFY] Preparing to notify {alContacts.Count} contacts about {user.Email}'s status ({notificationStatus})");

        var notificationTasks = new List<Task>();
        int notifiedCount = 0;
        int offlineCount = 0;

        foreach (var contact in alContacts)
        {
            var contactUser = GetUserById(contact.UserId);
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

    public static string FormatXml(string xml)
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

    public static async Task MonitorConnections()
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromMinutes(1));
            CleanupInactiveConnections();
        }
    }

    public static void CleanupInactiveConnections()
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

    public static (long high, long low) UuidToHighLow(string uuidString)
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

    public static async Task ForceLogoutExistingUser(User existingUser, string email)
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

    public static string GenerateMbiKey()
    {
        byte[] randomBytes = new byte[48];
        new Random().NextBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    public static async Task SendShieldsPolicy(NetworkStream stream)
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

    public static async Task SendAuthenticationResponse(
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

    public static string BuildProfileMessage(User user, int version, string token,
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

    public static async Task NotifyContactAsync(
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

    public static async Task SendIroMessages(NetworkStream stream, SwitchboardSession session,
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
    public static string GenerateSessionId()
    {
        return $"{DateTime.UtcNow.Ticks}.{new Random().Next(1000, 9999)}";
    }

    public static async Task<SwitchboardSession> HandleJoiCommand(
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

    public static async Task BroadcastTypingNotification(
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

    public static async Task NotifyContactsOfStatusChange(User user, string oldStatus, string newStatus, string capabilities)
    {
        // Get all contacts that have this user in their AL list
        var alContacts = GetReverseContacts(user.Id, "AL");
        Console.WriteLine($"[NOTIFY] Preparing to notify {alContacts.Count} contacts about {user.Email}'s status change");

        foreach (var contact in alContacts)
        {
            var contactUser = GetUserById(contact.UserId);
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

    public static async Task SendInitialStatusToClient(NetworkStream stream, User currentUser, int version)
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

    public static async Task SaveUserToDatabase(User user)
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

    public static async Task SaveContacts()
    {
        var json = JsonSerializer.Serialize(_contacts, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(ContactsDbFile, json);
    }

    public static async Task HandlePhoneProperty(NetworkStream stream, User currentUser, string transactionID, string phoneType, string newNumber, int version)
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
        var contacts = GetContacts(currentUser.Id, "FL");
        foreach (var contact in contacts)
        {
            var contactUser = GetUserById(contact.ContactId);
            if (contactUser == null) continue;

            // Check if the contact has us in their FL list
            var reverseContacts = GetContacts(contactUser.Id, "FL")
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

    public static async Task HandleAddToGroup(NetworkStream stream, User currentUser, string transactionId, string list, string contactIdentifier, string[] parts)
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

    public static List<Contact> GetReverseContacts(int contactId, string list = "FL")
    {
        return _contacts.Where(c =>
            c.ContactId == contactId &&
            c.List.Equals(list, StringComparison.OrdinalIgnoreCase)
        ).ToList();
    }

    public static async Task HandleSessionDisconnect(SwitchboardSession session)
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

    public static async Task SendAsync(NetworkStream stream, string message)
    {
        Console.WriteLine($"[NS<] {message.Trim()}");
        byte[] response = Encoding.UTF8.GetBytes(message);
        await stream.WriteAsync(response, 0, response.Length);
    }

    public static async Task SendRawAsync(NetworkStream stream, string header, byte[] body)
    {
        Console.WriteLine($"[NS<] {header.Trim()} (+{body.Length} bytes)");
        byte[] headerBytes = Encoding.UTF8.GetBytes(header);
        await stream.WriteAsync(headerBytes, 0, headerBytes.Length);
        await stream.WriteAsync(body, 0, body.Length);
    }

    public static async Task SendSbResponse(NetworkStream stream, params string[] parts)
    {
        string response = string.Join(" ", parts) + "\r\n";
        Console.WriteLine($"[SB<] {response.Trim()}");
        byte[] responseBytes = Encoding.UTF8.GetBytes(response);
        await stream.WriteAsync(responseBytes, 0, responseBytes.Length);
    }

    public static async Task BroadcastToSession(SwitchboardSession session, string message)
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


    public static async Task BroadcastMessageToSession(
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
}
