using System.Net.Sockets;


class ModelClasses {
    public class User
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

    public class Contact
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public int ContactId { get; set; }
        public string List { get; set; }
        public List<int> Groups { get; set; }
        public string UUID { get; set; } = Guid.NewGuid().ToString();
    }

    public class Phone
    {
        public string PHH { get; set; }
        public string PHM { get; set; }
        public string PHW { get; set; }
    }

    public class Group
    {
        public int Id { get; set; }
        public string Guid { get; set; }
        public string Name { get; set; }

        public Group()
        {
            Guid = System.Guid.NewGuid().ToString();
        }
    }

    public class ContactData
    {
        public string Email { get; set; }
        public string FriendlyName { get; set; }
        public string UUID { get; set; }
        public int ListsNumber { get; set; }
        public List<int> Groups { get; set; } = new List<int>();
        public Phone Phone { get; set; }
        public string Status { get; set; } = "FLN";
    }

    public class StatusNotification
    {
        public string Status { get; set; }
        public string Capabilities { get; set; }
        public string MsnObject { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ConnectedClient
    {
        public TcpClient TcpClient { get; set; }
        public NetworkStream Stream { get; set; }
        public string Email { get; set; }
        public int Version { get; set; }
        public DateTime LastActivity { get; set; }
    }

    public class SwitchboardSession
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
}
