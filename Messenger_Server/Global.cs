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

class Global {
    public const int NsPort = 1863;
    public const string UsersDbFile = "users.json";
    public const string ContactsDbFile = "contacts.json";

    public const int Port = 80;
    public static readonly XNamespace SoapNs = "http://schemas.xmlsoap.org/soap/envelope/";
    public static readonly XNamespace AbNs = "http://www.msn.com/webservices/AddressBook";

    public const int SbPort = 1864;

    public static List<User> _users = new List<User>();
    public static readonly object _userLock = new object();
    public static List<Contact> _contacts = new List<Contact>();
    public static Dictionary<string, User> _activeUsers = new Dictionary<string, User>();
    public static Dictionary<string, SwitchboardSession> _sessions = new Dictionary<string, SwitchboardSession>();

    public static readonly XmlWriterSettings WriterSettings = new XmlWriterSettings
    {
        Indent = true,
        IndentChars = "  ",
        NewLineChars = "\n",
        NewLineHandling = NewLineHandling.Replace
    };
}
