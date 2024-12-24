namespace DNSClient.Models
{
    public class DnsPacket
    {
        public DnsHeader Header { get; set; } = new();
        public List<DnsQuestion> Questions { get; set; } = new();
        public List<DnsResourceRecord> Answers { get; set; } = new();
        public List<DnsResourceRecord> Authorities { get; set; } = new();
        public List<DnsResourceRecord> AdditionalRecords { get; set; } = new();

        public void PrintPacket()
        {
            Console.WriteLine($"Transaction ID: {Header.TransactionId}");
            Console.WriteLine($"Flags: {Header.Flags:X4}");
            Console.WriteLine($"Questions: {Header.Questions}");
            Console.WriteLine($"Answer RRs: {Header.AnswerRRs}");
            Console.WriteLine($"Authority RRs: {Header.AuthorityRRs}");
            Console.WriteLine($"Additional RRs: {Header.AdditionalRRs}");

            foreach (var question in Questions)
            {
                Console.WriteLine($"\nQuestion:");
                Console.WriteLine($"  Name: {question.Name}");
                Console.WriteLine($"  Type: {question.Type}");
                Console.WriteLine($"  Class: {question.Class}");
            }

            PrintResourceRecords("Answer", Answers);
            PrintResourceRecords("Authority", Authorities);
            PrintResourceRecords("Additional", AdditionalRecords);
        }

        private void PrintResourceRecords(string section, List<DnsResourceRecord> records)
        {
            foreach (var record in records)
            {
                Console.WriteLine($"\n{section}:");
                Console.WriteLine($"  Name: {record.Name}");
                Console.WriteLine($"  Type: {record.Type}");
                Console.WriteLine($"  Class: {record.Class}");
                Console.WriteLine($"  TTL: {record.TTL}");

                switch (record.Type)
                {
                    case RecordType.MX:
                        Console.WriteLine($"  Preference: {record.Data.Preference}");
                        Console.WriteLine($"  Exchange: {record.Data.TextValue}");
                        break;

                    case RecordType.SOA:
                        var soa = record.Data.SoaData!;
                        Console.WriteLine($"  Primary NS: {soa.PrimaryNameServer}");
                        Console.WriteLine($"  Mailbox: {soa.ResponsibleMailbox}");
                        Console.WriteLine($"  Serial: {soa.SerialNumber}");
                        Console.WriteLine($"  Refresh: {soa.RefreshInterval}");
                        Console.WriteLine($"  Retry: {soa.RetryInterval}");
                        Console.WriteLine($"  Expire: {soa.ExpirationLimit}");
                        Console.WriteLine($"  Minimum TTL: {soa.MinimumTTL}");
                        break;

                    default:
                        if (record.Data.TextValue != null)
                            Console.WriteLine($"  Data: {record.Data.TextValue}");
                        else if (record.Data.RawData != null)
                            Console.WriteLine($"  Data: {BitConverter.ToString(record.Data.RawData).Replace("-", "")}");
                        break;
                }
            }
        }
    }

    public class DnsHeader
    {
        public ushort TransactionId { get; set; }
        public ushort Flags { get; set; }
        public ushort Questions { get; set; }
        public ushort AnswerRRs { get; set; }
        public ushort AuthorityRRs { get; set; }
        public ushort AdditionalRRs { get; set; }
        public bool IsAuthoritative => (Flags & 0x0400) != 0;
    }

    public class DnsQuestion
    {
        public string Name { get; set; } = string.Empty;
        public RecordType Type { get; set; }
        public ushort Class { get; set; }
    }

    public class DnsResourceRecord
    {
        public string Name { get; set; } = string.Empty;
        public RecordType Type { get; set; }
        public ushort Class { get; set; }
        public uint TTL { get; set; }
        public ushort DataLength { get; set; }
        public RecordData Data { get; set; } = new();
    }

    public class RecordData
    {
        public string? TextValue { get; set; }
        public byte[]? RawData { get; set; }
        public ushort? Preference { get; set; }  // For MX records
        public SoaData? SoaData { get; set; }
    }

    public class SoaData
    {
        public string PrimaryNameServer { get; set; } = string.Empty;
        public string ResponsibleMailbox { get; set; } = string.Empty;
        public uint SerialNumber { get; set; }
        public int RefreshInterval { get; set; }
        public int RetryInterval { get; set; }
        public int ExpirationLimit { get; set; }
        public uint MinimumTTL { get; set; }
    }

    public enum RecordType : ushort
    {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28
    }
}
