using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
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
                return xml;
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
        await LoadDatabases();

        var nsTask = Task.Run(() => StartNotificationServer());
        Console.WriteLine("[+] Starting Notification Server...");

        var sbTask = Task.Run(() => StartSwitchboardServer());
        Console.WriteLine("[+] Starting Switchboard Server...");

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

    class HttpSoapServer
    {
        public static async Task Start()
        {
            try
            {
                HttpListener listener = new HttpListener();

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
                        _ = ProcessRequestAsync(context);
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
                if (hlex.ErrorCode == 5)
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

        private static string GetContentType(string path)
        {
            var extension = Path.GetExtension(path).ToLowerInvariant();
            return extension switch
            {
                ".htm" or ".html" => "text/html",
                ".css" => "text/css",
                ".asp" or ".aspx" => "text/html",
                ".asmx" => "text/xml",
                ".srf" => "text/html",
                ".js" => "application/javascript",
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".gif" => "image/gif",
                ".ico" => "image/x-icon",
                ".xml" => "text/xml",
                ".json" => "application/json",
                _ => "application/octet-stream",
            };
        }

        private static async Task HandleStaticFileRequest(HttpListenerContext context, string wwwroot = "wwwroot")
        {
            var request = context.Request;
            var response = context.Response;

            try
            {
                var path = request.Url.AbsolutePath.TrimStart('/');
                var fullPath = Path.GetFullPath(Path.Combine(wwwroot, path.Replace("/", "\\")));
                var rootPath = Path.GetFullPath(wwwroot);

                if (!fullPath.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase))
                {
                    response.StatusCode = 403;
                    await SendSoapResponse(response, "Access denied");
                    return;
                }

                if (Directory.Exists(fullPath))
                {
                    var indexFile = Path.Combine(fullPath, "index.html");
                    if (File.Exists(indexFile))
                    {
                        await ServeFile(response, indexFile);
                        return;
                    }
                    response.StatusCode = 404;
                    await SendSoapResponse(response, "File not found");
                    return;
                }

                if (File.Exists(fullPath))
                {
                    await ServeFile(response, fullPath);
                    return;
                }

                response.StatusCode = 404;
                await SendSoapResponse(response, "File not found");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Static File Error] {ex.Message}");
                response.StatusCode = 500;
                await SendSoapResponse(response, "Internal server error");
            }
            finally
            {
                response.Close();
            }
        }

        private static async Task ServeFile(HttpListenerResponse response, string filePath)
        {
            var contentType = GetContentType(filePath);
            response.ContentType = contentType;

            using (var fileStream = File.OpenRead(filePath))
            {
                response.ContentLength64 = fileStream.Length;
                await fileStream.CopyToAsync(response.OutputStream);
            }
        }

        private static async Task ProcessRequestAsync(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;

            Console.WriteLine($"[HTTP] {request.HttpMethod} {request.Url.AbsolutePath}");

            try
            {
                if (request.HttpMethod == "OPTIONS")
                {
                    response.StatusCode = 200;
                    response.AddHeader("Access-Control-Allow-Origin", "*");
                    response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                    response.AddHeader("Access-Control-Allow-Headers", "Content-Type, SOAPAction");
                    response.Close();
                    return;
                }

                if (request.HttpMethod == "GET")
                {
                    await HandleStaticFileRequest(context);
                    return;
                }

                if (request.HttpMethod != "POST")
                {
                    response.StatusCode = 405;
                    response.AddHeader("Allow", "GET, POST");
                    response.Close();
                    return;
                }

                string requestBody;
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    requestBody = await reader.ReadToEndAsync();
                }

                string soapAction = request.Headers["SOAPAction"];
                if (string.IsNullOrEmpty(soapAction))
                {
                    response.StatusCode = 400;
                    await SendSoapResponse(response, "SOAPAction header is required");
                    return;
                }

                if (request.Url.AbsolutePath.Equals("/abservice/abservice.asmx", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleABServiceRequest(soapAction, requestBody, response);
                }
                else if (request.Url.AbsolutePath.Equals("/abservice/SharingService.asmx", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleSharingServiceRequest(soapAction, requestBody, response);
                }
                else
                {
                    response.StatusCode = 404;
                    await SendSoapResponse(response, "Endpoint not found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HTTP Error] {ex.Message}");
                response.StatusCode = 500;
                await SendSoapResponse(response, $"Internal server error: {ex.Message}");
            }
        }

        public static class TemplateHelper
        {
            private static readonly string TemplateFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "templates");

            public static async Task<string> LoadTemplateAsync(string templateName, Dictionary<string, string> replacements)
            {
                try
                {
                    string templatePath = Path.Combine(TemplateFolder, templateName);
                    if (!File.Exists(templatePath))
                    {
                        Console.WriteLine($"[Template] File not found: {templatePath}");
                        return null;
                    }

                    string templateContent = await File.ReadAllTextAsync(templatePath);

                    foreach (var replacement in replacements)
                    {
                        templateContent = templateContent.Replace($"{{{replacement.Key}}}", replacement.Value);
                    }

                    return templateContent;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Template Error] {ex.Message}");
                    return null;
                }
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
                    <lastChange>{DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}</lastChange>
                </Group>");
                }

                var contactsBuilder = new StringBuilder();
                foreach (var contact in GetContacts(user.Id, "FL").Where(c => c != null))
                {
                    var contactUser = GetUserById(contact.ContactId);
                    if (contactUser == null) continue;

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
                    <lastChange>{DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")}</lastChange>
                </Contact>");
                }

                var replacements = new Dictionary<string, string>
            {
                { "cacheKey", Guid.NewGuid().ToString() },
                { "sessionId", Guid.NewGuid().ToString() },
                { "userId", user.Id.ToString() },
                { "email", user.Email },
                { "timestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") },
                { "createdDate", user.CreatedDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") },
                { "groups", groupsBuilder.ToString() },
                { "contacts", contactsBuilder.ToString() }
            };

                return await TemplateHelper.LoadTemplateAsync("ABFindAllResponse.xml", replacements)
                       ?? CreateErrorResponse("Template loading failed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ABFindAll Error] {ex}");
                return CreateErrorResponse("Internal server error");
            }
        }

        private static async Task<string> HandleABFindContactsPaged(string requestBody)
        {
            try
            {
                var doc = XDocument.Parse(requestBody);
                var abNs = XNamespace.Get("http://www.msn.com/webservices/AddressBook");

                var ticketToken = doc.Descendants(abNs + "TicketToken").FirstOrDefault()?.Value;
                var pageSize = int.Parse(doc.Descendants(abNs + "PageSize").FirstOrDefault()?.Value ?? "100");
                var lastSeen = doc.Descendants(abNs + "LastSeen").FirstOrDefault()?.Value;

                if (string.IsNullOrEmpty(ticketToken))
                    return CreateErrorResponse("Invalid ticket token");

                var email = ticketToken.Split('&').FirstOrDefault(p => p.StartsWith("p="))?.Substring(2);
                if (string.IsNullOrEmpty(email))
                    return CreateErrorResponse("Invalid email in token");

                var user = GetUserByEmail(email);
                if (user == null)
                    return CreateErrorResponse("User not found");

                user.Groups = user.Groups ?? new List<ModelClasses.Group>();
                var contacts = GetContacts(user.Id, "FL") ?? new List<Contact>();
                var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var created = user.CreatedDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

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

                var paginatedContacts = contacts
                    .Where(c => lastSeen == null || string.Compare(c.UUID, lastSeen) > 0)
                    .Take(pageSize)
                    .ToList();

                var contactsBuilder = new StringBuilder();
                foreach (var contact in paginatedContacts)
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
                var replacements = new Dictionary<string, string>
        {
            { "cacheKey", Guid.NewGuid().ToString() },
            { "sessionId", Guid.NewGuid().ToString() },
            { "userId", user.Id.ToString() },
            { "email", user.Email },
            { "timestamp", now },
            { "createdDate", created },
            { "groups", groupsBuilder.ToString() },
            { "contacts", contactsBuilder.ToString() }
        };

                return await TemplateHelper.LoadTemplateAsync("ABFindContactsPagedResponse.xml", replacements)
                       ?? CreateErrorResponse("Template loading failed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ABFindContactsPaged Error] {ex}");
                return CreateErrorResponse("Internal server error");
            }
        }

        private static async Task<string> HandleFindMembership(string requestBody)
        {
            try
            {
                var doc = XDocument.Parse(requestBody);
                var abNs = XNamespace.Get("http://www.msn.com/webservices/AddressBook");
                var ticketToken = doc.Descendants(abNs + "TicketToken").FirstOrDefault()?.Value;

                if (string.IsNullOrEmpty(ticketToken))
                    return CreateErrorResponse("Invalid ticket token");

                var email = ticketToken.Split('&').FirstOrDefault(p => p.StartsWith("p="))?.Substring(2);
                var user = GetUserByEmail(email);
                if (user == null)
                    return CreateErrorResponse("User not found");

                var now = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                var cacheKey = $"12r1:{Guid.NewGuid()}";

                var allowMembersBuilder = new StringBuilder();
                foreach (var contact in GetContacts(user.Id, "AL"))
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

                var replacements = new Dictionary<string, string>
            {
                { "cacheKey", cacheKey },
                { "sessionId", Guid.NewGuid().ToString() },
                { "timestamp", now },
                { "allowMembers", allowMembersBuilder.ToString() },
                { "blockMembers", "" },
                { "reverseMembers", "" }
            };

                return await TemplateHelper.LoadTemplateAsync("FindMembershipResponse.xml", replacements)
                       ?? CreateErrorResponse("Template loading failed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FindMembership Error] {ex.Message}");
                return CreateErrorResponse("Internal server error");
            }
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
}
