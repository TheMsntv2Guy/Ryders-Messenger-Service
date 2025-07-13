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
using static Commands;
using static ModelClasses;
using static Functions;
using static Global;

public static class XmlHelper
{
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

    #endregion

    #region Notification Server (NS) Handlers

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
}

#endregion

class HttpSoapServer
{
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

    private static XElement BuildGroupsXml(List<ModelClasses.Group> groups)
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

            var user = GetUserByEmail(email);
            if (user == null)
                return CreateErrorResponse("User not found");

            // Initialize collections if null
            user.Groups = user.Groups ?? new List<ModelClasses.Group>();
            var contacts = GetContacts(user.Id, "FL") ?? new List<Contact>();
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
                var contactUser = GetUserById(contact.ContactId);
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
            var contactUser = GetUserByEmail(contact.ContactId.ToString()); // Adjust this based on your contact structure
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

            var user = GetUserByEmail(email);
            if (user == null)
                return CreateErrorResponse("User not found");

            // Initialize collections if null
            user.Groups = user.Groups ?? new List<ModelClasses.Group>();
            var contacts = GetContacts(user.Id, "FL") ?? new List<Contact>();
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
                var contactUser = GetUserById(contact.ContactId);
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
            var contactUser = GetUserByEmail(contact.ContactId.ToString()); // Adjust based on your contact structure
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
            var user = GetUserByEmail(email);
            if (user == null)
            {
                return CreateErrorResponse("User not found");
            }

            // Get contacts from database
            var allowContacts = GetContacts(user.Id, "AL");
            var blockContacts = GetContacts(user.Id, "BL");
            var reverseContacts = GetReverseContacts(user.Id);

            var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var cacheKey = $"12r1:{Guid.NewGuid()}";

            // Build members XML
            var allowMembersBuilder = new StringBuilder();
            foreach (var contact in allowContacts)
            {
                var contactUser = GetUserById(contact.ContactId);
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
                var contactUser = GetUserById(contact.ContactId);
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
                var contactUser = GetUserById(contact.UserId);
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
            var contactUser = GetUserById(contact.ContactId);
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

        var user = GetUserByEmail(email);
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
            await SaveUserToDatabase(user);
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
