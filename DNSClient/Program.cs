using DNSClient;
using DNSClient.Models;

var client = new DnsClient();

// Query different record types

// IPv4 address
var ipv4Packet = await client.QueryDomain("google.com", RecordType.A);           
ipv4Packet.PrintPacket();

// IPv6 address
var ipv6Packet = await client.QueryDomain("google.com", RecordType.AAAA);
ipv6Packet.PrintPacket();

// Mail servers
var mailServerPacket = await client.QueryDomain("google.com", RecordType.MX);
mailServerPacket.PrintPacket();

// Text records
var textPacket = await client.QueryDomain("gmail.com", RecordType.TXT);
textPacket.PrintPacket();

// Canonical name
var canonicalPacket = await client.QueryDomain("www.github.com", RecordType.CNAME);
canonicalPacket.PrintPacket();

// Reverse lookup
var reversePacket = await client.QueryDomain("8.8.8.8", RecordType.PTR);
reversePacket.PrintPacket();

// Trace:
await client.TraceQueryDomain("www.example.com", RecordType.A);