# pcap

[libpcap](https://www.tcpdump.org/) packet capture bindings for [Praia](https://praia.sh). Capture live traffic, read/write pcap files, and apply BPF filters.

Requires root or `CAP_NET_RAW` for live capture.

## Installation

```sh
sand install github.com/viggou/praia-pcap
```

Requires `libpcap` on the system (`libpcap-dev` on Debian/Ubuntu, ships with macOS).

## Usage

### Live capture

```praia
use "pcap"

let cap = pcap.openLive("en0")
pcap.setFilter(cap, "tcp port 80")

for (i in 0..10) {
    let pkt = pcap.next(cap)
    if (pkt) {
        print("got", pkt.caplen, "bytes at", pkt.timestamp)
    }
}
pcap.close(cap)
```

### Read a pcap file

```praia
use "pcap"

let cap = pcap.openFile("capture.pcap")
let pkt = pcap.next(cap)
while (pkt) {
    print(pkt.timestamp, pkt.len, "bytes")
    pkt = pcap.next(cap)
}
pcap.close(cap)
```

### Write packets to file

```praia
use "pcap"

let cap = pcap.openLive("en0")
pcap.dumpOpen(cap, "out.pcap")

for (i in 0..100) {
    let pkt = pcap.next(cap)
    if (pkt) { pcap.dump(cap, pkt.data, pkt.timestamp) }
}

pcap.dumpClose(cap)
pcap.close(cap)
```

### Combine with l2 for frame parsing

```praia
use "pcap"
use "l2"

let cap = pcap.openLive("en0")
pcap.setFilter(cap, "arp")

let pkt = pcap.next(cap)
if (pkt) {
    let frame = l2.parseFrame(pkt.data)
    if (frame && frame.etherType == 0x0806) {
        let arp = l2.parseArp(frame.payload)
        print(arp.senderIp, "is at", arp.senderMac)
    }
}
pcap.close(cap)
```

## API

### Capture

| Function | Description |
|----------|-------------|
| `openLive(iface, snaplen?, promisc?, timeoutMs?)` | Open live capture. Defaults: snaplen=65535, promisc=true, timeout=1000ms |
| `openFile(path)` | Open a pcap file for reading |
| `setFilter(handle, filter)` | Apply a BPF filter (e.g. `"tcp port 80"`, `"arp"`, `"host 10.0.0.1"`) |
| `next(handle)` | Read next packet. Returns `{data, timestamp, caplen, len}` or nil on timeout/EOF |
| `breakLoop(handle)` | Break out of a capture loop |
| `close(handle)` | Close the capture handle and any attached dump file |

### Writing

| Function | Description |
|----------|-------------|
| `dumpOpen(handle, path)` | Open a pcap dump file for writing (attached to capture handle) |
| `dump(handle, data, timestamp?)` | Write a packet to the dump file. Timestamp defaults to now |
| `dumpClose(handle)` | Close the dump file |

### Info

| Function | Description |
|----------|-------------|
| `stats(handle)` | Capture stats: `{recv, drop, ifdrop}` |
| `datalink(handle)` | Datalink type (e.g. `pcap.DLT_EN10MB` for Ethernet) |
| `devices()` | List capture devices: `[{name, description}]` |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DLT_EN10MB` | 1 | Ethernet datalink type |

## Building from source

```sh
make
```

Requires `libpcap` and Praia's development headers (`praia --include-path`).

## Platform notes

- **macOS**: libpcap ships with the system. Requires root for live capture.
- **Linux**: Install `libpcap-dev`. Requires root or `CAP_NET_RAW` for live capture.
