#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _XOPEN_SOURCE 700

#include "praia_plugin.h"
#include "signal_state.h"

#include <chrono>
#include <csignal>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <pcap/pcap.h>

struct PcapHandle {
    pcap_t* handle = nullptr;
    pcap_dumper_t* dumper = nullptr;
    int timeoutMs = 1000;
    bool isLive = false;
};

static std::unordered_map<int64_t, PcapHandle> handles;
static int64_t nextId = 1;

extern "C" void praia_register(PraiaMap* module) {
    // pcap.openLive(iface, snaplen?, promisc?, timeoutMs?) -> handle
    module->entries["openLive"] = Value(makeNative("pcap.openLive", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.empty() || !args[0].isString())
                throw RuntimeError("pcap.openLive() requires interface name", 0);

            const auto& iface = args[0].asString();
            int snaplen = (args.size() > 1 && args[1].isInt()) ? static_cast<int>(args[1].asInt()) : 65535;
            int promisc = (args.size() > 2 && args[2].isBool()) ? (args[2].asBool() ? 1 : 0) : 1;
            int timeoutMs = (args.size() > 3 && args[3].isInt()) ? static_cast<int>(args[3].asInt()) : 1000;

            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* p = pcap_open_live(iface.c_str(), snaplen, promisc, timeoutMs, errbuf);
            if (!p)
                throw RuntimeError("pcap.openLive(): " + std::string(errbuf), 0);

            // Set non-blocking so pcap_next_ex returns immediately.
            // We manage timeouts ourselves to stay responsive to Ctrl+C.
            // The pcap timeout still controls TPACKET_V3 block retirement.
            if (pcap_setnonblock(p, 1, errbuf) < 0) {
                pcap_close(p);
                throw RuntimeError("pcap.openLive(): " + std::string(errbuf), 0);
            }

            int64_t id = nextId++;
            handles[id] = {p, nullptr, timeoutMs, true};
            return Value(id);
        }));

    // pcap.openFile(path) -> handle
    module->entries["openFile"] = Value(makeNative("pcap.openFile", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isString())
                throw RuntimeError("pcap.openFile() requires file path", 0);

            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* p = pcap_open_offline(args[0].asString().c_str(), errbuf);
            if (!p)
                throw RuntimeError("pcap.openFile(): " + std::string(errbuf), 0);

            int64_t id = nextId++;
            handles[id] = {p, nullptr};
            return Value(id);
        }));

    // pcap.setFilter(handle, filter) -> nil
    module->entries["setFilter"] = Value(makeNative("pcap.setFilter", 2,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.setFilter() requires handle", 0);
            if (!args[1].isString())
                throw RuntimeError("pcap.setFilter() requires filter string", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.setFilter(): invalid handle", 0);

            struct bpf_program fp;
            if (pcap_compile(it->second.handle, &fp, args[1].asString().c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
                throw RuntimeError("pcap.setFilter(): " + std::string(pcap_geterr(it->second.handle)), 0);

            if (pcap_setfilter(it->second.handle, &fp) < 0) {
                pcap_freecode(&fp);
                throw RuntimeError("pcap.setFilter(): " + std::string(pcap_geterr(it->second.handle)), 0);
            }
            pcap_freecode(&fp);
            return Value();
        }));

    // pcap.next(handle) -> {data, timestamp, caplen, len} or nil
    // Live handles are non-blocking: pcap_next_ex returns immediately.
    // We loop with short sleeps (10ms) until a packet arrives, the timeout
    // expires, or Ctrl+C is detected. Offline handles call pcap_next_ex once.
    module->entries["next"] = Value(makeNative("pcap.next", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.next() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.next(): invalid handle", 0);

            auto& ph = it->second;

            // Offline: single blocking call
            if (!ph.isLive) {
                struct pcap_pkthdr* hdr;
                const u_char* pkt;
                int rc = pcap_next_ex(ph.handle, &hdr, &pkt);
                if (rc <= 0) return Value();
                auto result = gcNew<PraiaMap>();
                result->entries["data"] = Value(std::string(reinterpret_cast<const char*>(pkt), hdr->caplen));
                result->entries["timestamp"] = Value(static_cast<double>(hdr->ts.tv_sec) + static_cast<double>(hdr->ts.tv_usec) / 1000000.0);
                result->entries["caplen"] = Value(static_cast<int64_t>(hdr->caplen));
                result->entries["len"] = Value(static_cast<int64_t>(hdr->len));
                return Value(result);
            }

            // Live: non-blocking loop with signal checks
            auto start = std::chrono::steady_clock::now();

            while (true) {
                if (g_pendingSignals.load(std::memory_order_relaxed) & (1u << SIGINT))
                    throw RuntimeError("Interrupted", 0);

                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= ph.timeoutMs) return Value();

                struct pcap_pkthdr* hdr;
                const u_char* pkt;
                int rc = pcap_next_ex(ph.handle, &hdr, &pkt);

                if (rc > 0) {
                    auto result = gcNew<PraiaMap>();
                    result->entries["data"] = Value(std::string(reinterpret_cast<const char*>(pkt), hdr->caplen));
                    result->entries["timestamp"] = Value(static_cast<double>(hdr->ts.tv_sec) + static_cast<double>(hdr->ts.tv_usec) / 1000000.0);
                    result->entries["caplen"] = Value(static_cast<int64_t>(hdr->caplen));
                    result->entries["len"] = Value(static_cast<int64_t>(hdr->len));
                    return Value(result);
                }
                if (rc == PCAP_ERROR_BREAK) return Value();
                if (rc < 0)
                    throw RuntimeError("pcap.next(): " + std::string(pcap_geterr(ph.handle)), 0);

                // No packet yet — sleep 10ms to avoid busy-spinning
                usleep(10000);
            }
        }));

    // pcap.breakLoop(handle) -> nil
    module->entries["breakLoop"] = Value(makeNative("pcap.breakLoop", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.breakLoop() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.breakLoop(): invalid handle", 0);

            pcap_breakloop(it->second.handle);
            return Value();
        }));

    // pcap.stats(handle) -> {recv, drop, ifdrop}
    module->entries["stats"] = Value(makeNative("pcap.stats", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.stats() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.stats(): invalid handle", 0);

            struct pcap_stat ps;
            if (pcap_stats(it->second.handle, &ps) < 0)
                throw RuntimeError("pcap.stats(): " + std::string(pcap_geterr(it->second.handle)), 0);

            auto result = gcNew<PraiaMap>();
            result->entries["recv"] = Value(static_cast<int64_t>(ps.ps_recv));
            result->entries["drop"] = Value(static_cast<int64_t>(ps.ps_drop));
            result->entries["ifdrop"] = Value(static_cast<int64_t>(ps.ps_ifdrop));
            return Value(result);
        }));

    // pcap.datalink(handle) -> int
    module->entries["datalink"] = Value(makeNative("pcap.datalink", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.datalink() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.datalink(): invalid handle", 0);

            return Value(static_cast<int64_t>(pcap_datalink(it->second.handle)));
        }));

    // pcap.dumpOpen(handle, path) -> nil (attaches dumper to handle)
    module->entries["dumpOpen"] = Value(makeNative("pcap.dumpOpen", 2,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.dumpOpen() requires handle", 0);
            if (!args[1].isString())
                throw RuntimeError("pcap.dumpOpen() requires file path", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.dumpOpen(): invalid handle", 0);

            if (it->second.dumper) {
                pcap_dump_close(it->second.dumper);
                it->second.dumper = nullptr;
            }

            pcap_dumper_t* d = pcap_dump_open(it->second.handle, args[1].asString().c_str());
            if (!d)
                throw RuntimeError("pcap.dumpOpen(): " + std::string(pcap_geterr(it->second.handle)), 0);

            it->second.dumper = d;
            return Value();
        }));

    // pcap.dump(handle, data, timestamp?) -> nil
    module->entries["dump"] = Value(makeNative("pcap.dump", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.size() < 2 || !args[0].isInt() || !args[1].isString())
                throw RuntimeError("pcap.dump() requires handle and packet data", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.dump(): invalid handle", 0);
            if (!it->second.dumper)
                throw RuntimeError("pcap.dump(): no dump file open (call dumpOpen first)", 0);

            const auto& data = args[1].asString();

            struct pcap_pkthdr hdr;
            if (args.size() > 2 && args[2].isNumber()) {
                double ts = args[2].asNumber();
                hdr.ts.tv_sec = static_cast<time_t>(ts);
                hdr.ts.tv_usec = static_cast<suseconds_t>((ts - hdr.ts.tv_sec) * 1000000);
            } else {
                gettimeofday(&hdr.ts, nullptr);
            }
            hdr.caplen = static_cast<bpf_u_int32>(data.size());
            hdr.len = hdr.caplen;

            pcap_dump(reinterpret_cast<u_char*>(it->second.dumper),
                      &hdr, reinterpret_cast<const u_char*>(data.data()));
            return Value();
        }));

    // pcap.dumpFlush(handle) -> nil
    module->entries["dumpFlush"] = Value(makeNative("pcap.dumpFlush", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.dumpFlush() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end())
                throw RuntimeError("pcap.dumpFlush(): invalid handle", 0);
            if (!it->second.dumper)
                throw RuntimeError("pcap.dumpFlush(): no dump file open", 0);

            if (pcap_dump_flush(it->second.dumper) < 0)
                throw RuntimeError("pcap.dumpFlush(): flush failed", 0);
            return Value();
        }));

    // pcap.dumpClose(handle) -> nil
    module->entries["dumpClose"] = Value(makeNative("pcap.dumpClose", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.dumpClose() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end()) return Value();

            if (it->second.dumper) {
                pcap_dump_close(it->second.dumper);
                it->second.dumper = nullptr;
            }
            return Value();
        }));

    // pcap.close(handle) -> nil
    module->entries["close"] = Value(makeNative("pcap.close", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("pcap.close() requires handle", 0);

            auto it = handles.find(args[0].asInt());
            if (it == handles.end()) return Value();

            if (it->second.dumper)
                pcap_dump_close(it->second.dumper);
            if (it->second.handle)
                pcap_close(it->second.handle);
            handles.erase(it);
            return Value();
        }));

    // pcap.devices() -> [{name, description}]
    module->entries["devices"] = Value(makeNative("pcap.devices", 0,
        [](const std::vector<Value>& args) -> Value {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_if_t* devs;
            if (pcap_findalldevs(&devs, errbuf) < 0)
                throw RuntimeError("pcap.devices(): " + std::string(errbuf), 0);

            auto arr = gcNew<PraiaArray>();
            for (auto* d = devs; d; d = d->next) {
                auto entry = gcNew<PraiaMap>();
                entry->entries["name"] = Value(std::string(d->name));
                entry->entries["description"] = d->description
                    ? Value(std::string(d->description))
                    : Value();
                arr->elements.push_back(Value(entry));
            }
            pcap_freealldevs(devs);
            return Value(arr);
        }));

    // pcap.DLT_EN10MB constant (Ethernet)
    module->entries["DLT_EN10MB"] = Value(static_cast<int64_t>(DLT_EN10MB));
}
