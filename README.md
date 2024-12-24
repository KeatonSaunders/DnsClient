# DNS Client

A simple DNS client implementation written as a solution in the CSPrimer Computer Networking module.

## Features

- Supports common DNS record types (A, AAAA, CNAME, MX, TXT, PTR)
- Implements DNS packet creation and parsing
- Handles DNS name compression
- Includes iterative resolution tracing that shows step-by-step DNS resolution from root servers to authoritative nameservers

## Limitations

- Does not implement DNS caching
- No DNSSEC support
- Only supports UDP (no TCP fallback for large responses)
- Basic error handling
- No support for EDNS or other DNS extensions

## Usage

```csharp
var client = new DnsClient();

// Query A record
var ipv4Packet = await client.QueryDomain("google.com", RecordType.A);
ipv4Packet.PrintPacket();

// Trace DNS resolution
await client.TraceQueryDomain("www.example.com", RecordType.A);
```

## Educational Purpose

This repository is purely for educational purposes and is not intended for production use of any kind.

## Notes and Documentation

I've included a few files mainly for my own education and documentation:

- `PacketStructure.txt`: Breakdown of DNS packet formats and header structures
- `RecordTypes.txt`: Guide to DNS record types and their use cases
- `Servers.txt`: Information about DNS hierarchy and common DNS providers
