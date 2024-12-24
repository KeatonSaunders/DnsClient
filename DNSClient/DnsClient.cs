using DNSClient.Models;
using DNSClient.Reader;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DNSClient
{
    public class DnsClient
    {
        private Random random = new();
        private int BUFFER_SIZE = 4096;

        private readonly string[] ROOT_SERVERS =
        {
            "198.41.0.4",        // a.root-servers.net (Verisign)
            "199.9.14.201",      // b.root-servers.net (USC-ISI)
            "192.33.4.12",       // c.root-servers.net (Cogent)
            "199.7.91.13",       // d.root-servers.net (University of Maryland)
            "192.203.230.10",    // e.root-servers.net (NASA)
            "192.5.5.241",       // f.root-servers.net (Internet Systems Consortium)
            "192.112.36.4",      // g.root-servers.net (US Department of Defense)
            "198.97.190.53",     // h.root-servers.net (US Army Research Lab)
            "192.36.148.17",     // i.root-servers.net (Netnod)
            "192.58.128.30",     // j.root-servers.net (Verisign)
            "193.0.14.129",      // k.root-servers.net (RIPE NCC)
            "199.7.83.42",       // l.root-servers.net (ICANN)
            "202.12.27.33"       // m.root-servers.net (WIDE Project)
        };

        private (byte[], ushort) CreateDnsQuery(string domain, RecordType recordType)
        {
            ushort id = (ushort)random.Next(0, 65536);
            List<byte> query =
            [
                // Transaction ID
                .. BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)id)),
                // Flags
                .. BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0x0100)),  // Recursion Desired
                // Counts
                .. BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)1)),       // Questions
                .. BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0)),       // Answer RRs
                .. BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0)),       // Authority RRs
                .. BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)0)),       // Additional RRs
            ];

            if (recordType == RecordType.PTR)
                domain = ConvertIPToReverseLookupFormat(domain);

            // Question
            foreach (string label in domain.Split('.'))
            {
                query.Add((byte)label.Length);
                query.AddRange(Encoding.ASCII.GetBytes(label));
            }
            query.Add(0);// Null terminator

            // QTYPE and QCLASS
            query.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)recordType)));
            query.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)1)));

            return (query.ToArray(), id);
        }

        private string ConvertIPToReverseLookupFormat(string ipAddress)
        {
            if (!IPAddress.TryParse(ipAddress, out IPAddress? ip))
                throw new ArgumentException("Invalid IP address format");

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                string[] octets = ipAddress.Split('.');
                Array.Reverse(octets);
                return string.Join(".", octets) + ".in-addr.arpa";
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                string expandedAddress = ip.ToString();
                expandedAddress = expandedAddress.Replace(":", "");
                return string.Join(".", expandedAddress.ToCharArray().Reverse()) + ".ip6.arpa";
            }

            throw new ArgumentException("Unsupported IP address format");
        }

        public async Task<DnsPacket> QueryDomain(string domain = "www.wikipedia.org", RecordType recordType = RecordType.A)
        {
            var (queryBytes, queryID) = CreateDnsQuery(domain, recordType);

            using Socket udpClient = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            // This is of course not a connection in the TCP sense but rather associates the socket
            // with a remote endpoint, i.e. filters packets and allows for simpler send / receive syntax.
            await udpClient.ConnectAsync("8.8.8.8", 53);
            await udpClient.SendAsync(queryBytes);

            byte[] response = new byte[BUFFER_SIZE];
            int bytesReceived = await udpClient.ReceiveAsync(response);

            if (bytesReceived == 0)
                throw new Exception("No response received from DNS server");

            var reader = new DnsPacketReader(response[..bytesReceived]);
            return reader.ParsePacket();
        }

        public async Task TraceQueryDomain(string domain, RecordType recordType = RecordType.A)
        {
            string currentNameserver = ROOT_SERVERS[0];
            HashSet<string> visitedNameservers = new();
            int maxReferrals = 10;

            Console.WriteLine($"\nTracing DNS resolution for {domain} ({recordType})...");

            while (maxReferrals > 0)
            {
                if (!visitedNameservers.Add(currentNameserver))
                    throw new Exception("Circular reference detected");

                Console.WriteLine($"Querying nameserver: {currentNameserver}");

                var (queryBytes, queryID) = CreateDnsQuery(domain, recordType);
                using Socket udpClient = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                await udpClient.ConnectAsync(currentNameserver, 53);
                await udpClient.SendAsync(queryBytes);

                byte[] response = new byte[BUFFER_SIZE];
                int bytesReceived = await udpClient.ReceiveAsync(response);

                if (bytesReceived == 0)
                    throw new Exception("No response received from nameserver");

                var packet = new DnsPacketReader(response[..bytesReceived]).ParsePacket();

                // Check if we have an answer
                if (packet.Answers.Any())
                {
                    Console.WriteLine("\nFound authoritative answer!");
                    foreach (var answer in packet.Answers)
                    {
                        Console.WriteLine($"Answer: {answer.Name} {answer.Type} {answer.Data.TextValue}");
                    }
                    break;
                }

                // Get next nameserver to query
                var nextNameserver = GetNextNameserver(packet);
                if (nextNameserver == null)
                {
                    throw new Exception("No valid nameserver found to continue resolution");
                }

                currentNameserver = nextNameserver;
                maxReferrals--;
            }

            if (maxReferrals == 0)
                throw new Exception("Maximum referral limit reached");
        }

        private string? GetNextNameserver(DnsPacket packet)
        {
            // First try to find a nameserver with a glue record
            foreach (var auth in packet.Authorities.Where(a => a.Type == RecordType.NS))
            {
                var glueRecord = packet.AdditionalRecords.FirstOrDefault(r => r.Type == RecordType.A && r.Name == auth.Data.TextValue);

                if (glueRecord != null)
                {
                    Console.WriteLine($"Using glue record for {auth.Data.TextValue}: {glueRecord.Data.TextValue}");
                    return glueRecord.Data.TextValue;
                }
            }

            // If no glue record found, resolve the first nameserver
            var firstNS = packet.Authorities.FirstOrDefault(a => a.Type == RecordType.NS)?.Data.TextValue;

            if (firstNS != null)
            {
                try
                {
                    Console.WriteLine($"Resolving nameserver: {firstNS}");
                    return ResolveDomainToIp(firstNS).Result;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to resolve nameserver {firstNS}: {ex.Message}");
                    throw;
                }
            }

            return null;
        }

        private async Task<string> ResolveDomainToIp(string domain)
        {
            var response = await QueryDomain(domain, RecordType.A);
            var address = response.Answers.FirstOrDefault(a => a.Type == RecordType.A)?.Data.TextValue;

            if (string.IsNullOrEmpty(address))
                throw new Exception($"Failed to resolve IP for {domain}");

            return address;
        }
    }
}