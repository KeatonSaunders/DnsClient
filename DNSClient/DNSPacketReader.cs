using DNSClient.Models;
using System.Net;
using System.Text;

namespace DNSClient.Reader
{
    public class DnsPacketReader
    {
        private readonly byte[] packet;
        private int offset;
        private readonly HashSet<int> visitedOffsets = new();
        private const int MAX_POINTER_JUMPS = 10;

        public DnsPacketReader(byte[] packet)
        {
            this.packet = packet;
            offset = 0;
        }

        public ushort ReadUInt16()
        {
            var result = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(packet, offset));
            offset += 2;
            return result;
        }

        public uint ReadUInt32()
        {
            var result = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(packet, offset));
            offset += 4;
            return result;
        }

        public string ReadDomainName(int pointerJumps = 0, HashSet<int>? seenPointers = null)
        {
            List<string> parts = new();
            seenPointers ??= new HashSet<int>();

            if (pointerJumps >= MAX_POINTER_JUMPS)
            {
                throw new Exception("Too many pointer jumps - possible compression loop attack");
            }

            while (true)
            {
                if (offset >= packet.Length)
                    throw new Exception("Malformed DNS packet - unexpected end of data");

                byte length = packet[offset++];
                if (length == 0)
                    break;

                if ((length & 0xC0) == 0xC0)
                {
                    int pointer = ((length & 0x3F) << 8) | packet[offset++];
                    if (!seenPointers.Add(pointer))
                        throw new Exception("Circular reference detected in DNS name compression");

                    int originalOffset = offset;
                    offset = pointer;
                    parts.AddRange(ReadDomainName(pointerJumps + 1, seenPointers).Split('.'));
                    offset = originalOffset;
                    break;
                }

                if (length > 63)
                    throw new Exception($"Malformed DNS packet - invalid label length: {length}");

                parts.Add(Encoding.ASCII.GetString(packet, offset, length));
                offset += length;
            }

            return string.Join(".", parts);
        }

        public DnsPacket ParsePacket()
        {
            var packet = new DnsPacket
            {
                Header = ParseHeader()
            };

            // Parse questions
            for (int i = 0; i < packet.Header.Questions; i++)
                packet.Questions.Add(ParseQuestion());

            // Parse resource records
            packet.Answers = ParseResourceRecords(packet.Header.AnswerRRs);
            packet.Authorities = ParseResourceRecords(packet.Header.AuthorityRRs);
            packet.AdditionalRecords = ParseResourceRecords(packet.Header.AdditionalRRs);

            return packet;
        }

        private DnsHeader ParseHeader()
        {
            return new DnsHeader
            {
                TransactionId = ReadUInt16(),
                Flags = ReadUInt16(),
                Questions = ReadUInt16(),
                AnswerRRs = ReadUInt16(),
                AuthorityRRs = ReadUInt16(),
                AdditionalRRs = ReadUInt16()
            };
        }

        private DnsQuestion ParseQuestion()
        {
            return new DnsQuestion
            {
                Name = ReadDomainName(),
                Type = (RecordType)ReadUInt16(),
                Class = ReadUInt16()
            };
        }

        private List<DnsResourceRecord> ParseResourceRecords(int count)
        {
            var records = new List<DnsResourceRecord>();
            for (int i = 0; i < count; i++)
                records.Add(ParseResourceRecord());
            return records;
        }

        private DnsResourceRecord ParseResourceRecord()
        {
            var record = new DnsResourceRecord
            {
                Name = ReadDomainName(),
                Type = (RecordType)ReadUInt16(),
                Class = ReadUInt16(),
                TTL = ReadUInt32(),
                DataLength = ReadUInt16()
            };

            record.Data = ParseRecordData(record.Type, record.DataLength);
            return record;
        }

        private RecordData ParseRecordData(RecordType type, ushort length)
        {
            var data = new RecordData();
            int startOffset = offset;

            switch (type)
            {
                case RecordType.A:
                    data.TextValue = string.Join(".", packet.Skip(offset).Take(length));
                    break;

                case RecordType.AAAA:
                    byte[] ipv6Bytes = new byte[16];
                    Array.Copy(packet, offset, ipv6Bytes, 0, 16);
                    data.TextValue = new IPAddress(ipv6Bytes).ToString();
                    break;

                case RecordType.NS:
                case RecordType.CNAME:
                case RecordType.PTR:
                    data.TextValue = ReadDomainName();
                    break;

                case RecordType.MX:
                    data.Preference = ReadUInt16();
                    data.TextValue = ReadDomainName();
                    break;

                case RecordType.SOA:
                    data.SoaData = ParseSoaData();
                    break;

                default:
                    data.RawData = new byte[length];
                    Array.Copy(packet, offset, data.RawData, 0, length);
                    break;
            }

            // Ensure we advance the offset correctly
            offset = startOffset + length;
            return data;
        }

        private SoaData ParseSoaData()
        {
            return new SoaData
            {
                PrimaryNameServer = ReadDomainName(),
                ResponsibleMailbox = ReadDomainName(),
                SerialNumber = ReadUInt32(),
                RefreshInterval = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(packet, offset)),
                RetryInterval = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(packet, offset + 4)),
                ExpirationLimit = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(packet, offset + 8)),
                MinimumTTL = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(packet, offset + 12))
            };
        }
    }
}
