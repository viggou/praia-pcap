#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _XOPEN_SOURCE 700

#include "praia_plugin.h"
#include "signal_state.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <limits>
#include <cstring>
#include <mutex>
#include <sys/time.h>
#include <unordered_set>
#include <vector>
#include <pcap/pcap.h>

PRAIA_DECLARE_ABI();
PRAIA_PLUGIN_METADATA("pcap", "1.1.1",
                     "libpcap bindings for Praia");

// A capture handle. Async tasks can share one, so:
//   opMu serializes libpcap calls on it (held through a blocking next()),
//   stateMu guards the pointers and the dump file, held only for a moment.
//   breakLoop takes only stateMu, so it can interrupt a next() blocked in
//   another task, and close() takes both, so neither ever sees a freed
//   handle. closing is set first thing in close(): no new read starts
//   after it, even one that would have consumed the break.
// pcap_breakloop wakes a blocked read at once on Linux (libpcap 1.10+);
// with BPF (macOS) the read only returns when the capture timeout ends,
// which is why openLive requires one and caps it
struct PcapHandle {
    std::timed_mutex opMu;
    std::mutex stateMu;
    std::atomic<bool> closing{false};
    pcap_t* handle = nullptr;
    pcap_dumper_t* dumper = nullptr;
};
static const char* kHandleType = "pcap.handle";

// Live handles, for the exit hook. Leaked on purpose: deleters can run
// during process teardown, after statics are destroyed
static std::mutex g_regMu;
static auto* g_handles = new std::unordered_set<PcapHandle*>();

// Flushes and closes the dump file. Call with stateMu held
static void closeDumper(PcapHandle* h) {
    if (h->dumper) {
        pcap_dump_flush(h->dumper);
        pcap_dump_close(h->dumper);
        h->dumper = nullptr;
    }
}

// Asks a read blocked on h to return, and stops new ones starting
static void stopReads(PcapHandle* h) {
    h->closing = true;
    std::lock_guard<std::mutex> state(h->stateMu);
    if (h->handle) pcap_breakloop(h->handle);
}

// Closes the dumper, then the handle (the documented libpcap order).
// Call with opMu held; takes stateMu itself
static void closeHandle(PcapHandle* h) {
    std::lock_guard<std::mutex> state(h->stateMu);
    closeDumper(h);
    if (h->handle) {
        pcap_close(h->handle);
        h->handle = nullptr;
    }
}

// The handle's deleter. Nothing else can be using it (whoever did held a
// reference), so the locks are uncontended
static void freeHandle(PcapHandle* h) {
    {
        std::lock_guard<std::mutex> reg(g_regMu);
        g_handles->erase(h);
    }
    {
        std::lock_guard<std::timed_mutex> op(h->opMu);
        closeHandle(h);
    }
    delete h;
}

// Process-exit hook — flush + close any open pcap handles so capture
// files aren't truncated on script crashes or sys.exit(). An unawaited
// task may still be in next(). The dump file only needs stateMu, so it's
// always flushed and closed; the capture itself is closed if its read
// returns soon, and otherwise left to the process exit
extern "C" void praia_at_exit(void) {
    std::lock_guard<std::mutex> reg(g_regMu);
    for (auto* h : *g_handles) {
        stopReads(h);
        {
            std::lock_guard<std::mutex> state(h->stateMu);
            closeDumper(h);
        }
        if (h->opMu.try_lock_for(std::chrono::milliseconds(250))) {
            closeHandle(h);
            h->opMu.unlock();
        }
    }
}

// ── Argument helpers ──

static PcapHandle* argHandle(const std::vector<Value>& args, size_t i, const std::string& fn) {
    if (i >= args.size() || !args[i].isExternal())
        praia::error(fn + "() argument " + std::to_string(i + 1) + " must be a pcap handle");
    return praia::getExternal<PcapHandle>(args[i], kHandleType);
}

// The handle's pcap_t, with opMu held by the caller
static pcap_t* openPcap(PcapHandle* h, const std::string& fn) {
    if (h->closing || !h->handle) praia::error(fn + "(): the handle is closed");
    return h->handle;
}

// An optional int argument: missing or nil gives the default
static int optInt(const std::vector<Value>& args, size_t i, int def, int lo, int hi,
                  const std::string& fn, const char* what) {
    if (i >= args.size() || args[i].isNil()) return def;
    int64_t v = praia::requireInt(args, i, fn);
    if (v < lo || v > hi)
        praia::error(fn + "(): " + what + " must be between " + std::to_string(lo) +
                     " and " + std::to_string(hi));
    return static_cast<int>(v);
}

static Value wrapHandle(pcap_t* p) {
    auto* h = new PcapHandle();
    h->handle = p;
    {
        std::lock_guard<std::mutex> reg(g_regMu);
        g_handles->insert(h);
    }
    return praia::makeExternal<PcapHandle>(h, kHandleType, freeHandle);
}

static bool interrupted() {
    return g_pendingSignals.load(std::memory_order_relaxed) & (1u << SIGINT);
}

static bool cancelled() {
    auto c = praia::shouldCancel();
    return c && *c;
}

extern "C" void praia_register(PraiaMap* module) {
    // pcap.openLive(iface, snaplen?, promisc?, timeoutMs?) -> handle
    module->entries["openLive"] = Value(makeNative("pcap.openLive", -1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.openLive";
            praia::requireArityRange(args, 1, 4, fn);
            const auto& iface = praia::requireString(args, 0, fn);
            int snaplen = optInt(args, 1, 65535, 1, 262144, fn, "snaplen");
            int promisc = 1;
            if (args.size() > 2 && !args[2].isNil())
                promisc = praia::requireBool(args, 2, fn) ? 1 : 0;
            // 0 would mean "wait forever" on Linux, which nothing could
            // interrupt; next() returns nil on each timeout instead
            // At most a minute: on macOS it's also how long close() and
            // breakLoop() can wait for a blocked next()
            int timeoutMs = optInt(args, 3, 1000, 1, 60000, fn, "timeoutMs");

            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* p = pcap_open_live(iface.c_str(), snaplen, promisc, timeoutMs, errbuf);
            if (!p)
                praia::error(fn + "(): " + std::string(errbuf));
            return wrapHandle(p);
        }));

    // pcap.openFile(path) -> handle
    module->entries["openFile"] = Value(makeNative("pcap.openFile", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.openFile";
            const auto& path = praia::requireString(args, 0, fn);
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* p = pcap_open_offline(path.c_str(), errbuf);
            if (!p)
                praia::error(fn + "(): " + std::string(errbuf));
            return wrapHandle(p);
        }));

    // pcap.setFilter(handle, filter) -> nil
    module->entries["setFilter"] = Value(makeNative("pcap.setFilter", 2,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.setFilter";
            auto* h = argHandle(args, 0, fn);
            const auto& filter = praia::requireString(args, 1, fn);
            std::lock_guard<std::timed_mutex> op(h->opMu);
            pcap_t* p = openPcap(h, fn);

            struct bpf_program fp;
            if (pcap_compile(p, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
                praia::error(fn + "(): " + std::string(pcap_geterr(p)));
            if (pcap_setfilter(p, &fp) < 0) {
                pcap_freecode(&fp);
                praia::error(fn + "(): " + std::string(pcap_geterr(p)));
            }
            pcap_freecode(&fp);
            return Value();
        }));

    // pcap.next(handle) -> {data, timestamp, caplen, len} or nil
    module->entries["next"] = Value(makeNative("pcap.next", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.next";
            auto* h = argHandle(args, 0, fn);

            // Ctrl+C and cooperative cancellation are checked before
            // reading, so a packet already read is always returned. Inside
            // a withCancel scope a cancelled token reads as a timeout: the
            // user's loop checks tok.cancelled() and cleans up
            if (interrupted()) praia::error("Interrupted");
            if (cancelled()) return Value();
            if (h->closing) praia::error(fn + "(): the handle is closed");

            std::lock_guard<std::timed_mutex> op(h->opMu);
            pcap_t* p = openPcap(h, fn);
            struct pcap_pkthdr* hdr;
            const u_char* pkt;
            int rc = pcap_next_ex(p, &hdr, &pkt);

            if (rc == 1) {
                auto result = gcNew<PraiaMap>();
                result->entries["data"] = Value(std::string(reinterpret_cast<const char*>(pkt), hdr->caplen));
                result->entries["timestamp"] = Value(static_cast<double>(hdr->ts.tv_sec) + static_cast<double>(hdr->ts.tv_usec) / 1000000.0);
                result->entries["caplen"] = Value(static_cast<int64_t>(hdr->caplen));
                result->entries["len"] = Value(static_cast<int64_t>(hdr->len));
                return Value(result);
            }
            // Ctrl+C pressed while waiting
            if (interrupted()) praia::error("Interrupted");
            if (rc == 0) return Value();                 // timeout
            if (rc == PCAP_ERROR_BREAK) return Value();  // EOF or breakLoop
            praia::error(fn + "(): " + std::string(pcap_geterr(p)));
        }));

    // pcap.breakLoop(handle) -> nil
    // Safe from another task while one is blocked in next(): it takes only
    // the state lock, and that next() returns nil
    module->entries["breakLoop"] = Value(makeNative("pcap.breakLoop", 1,
        [](const std::vector<Value>& args) -> Value {
            auto* h = argHandle(args, 0, "pcap.breakLoop");
            std::lock_guard<std::mutex> state(h->stateMu);
            if (h->handle) pcap_breakloop(h->handle);
            return Value();
        }));

    // pcap.stats(handle) -> {recv, drop, ifdrop}
    module->entries["stats"] = Value(makeNative("pcap.stats", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.stats";
            auto* h = argHandle(args, 0, fn);
            std::lock_guard<std::timed_mutex> op(h->opMu);
            pcap_t* p = openPcap(h, fn);

            struct pcap_stat ps;
            if (pcap_stats(p, &ps) < 0)
                praia::error(fn + "(): " + std::string(pcap_geterr(p)));

            auto result = gcNew<PraiaMap>();
            result->entries["recv"] = Value(static_cast<int64_t>(ps.ps_recv));
            result->entries["drop"] = Value(static_cast<int64_t>(ps.ps_drop));
            result->entries["ifdrop"] = Value(static_cast<int64_t>(ps.ps_ifdrop));
            return Value(result);
        }));

    // pcap.datalink(handle) -> int
    module->entries["datalink"] = Value(makeNative("pcap.datalink", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.datalink";
            auto* h = argHandle(args, 0, fn);
            std::lock_guard<std::timed_mutex> op(h->opMu);
            return Value(static_cast<int64_t>(pcap_datalink(openPcap(h, fn))));
        }));

    // pcap.dumpOpen(handle, path) -> nil (attaches dumper to handle)
    module->entries["dumpOpen"] = Value(makeNative("pcap.dumpOpen", 2,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.dumpOpen";
            auto* h = argHandle(args, 0, fn);
            const auto& path = praia::requireString(args, 1, fn);
            std::lock_guard<std::timed_mutex> op(h->opMu);
            pcap_t* p = openPcap(h, fn);
            std::lock_guard<std::mutex> state(h->stateMu);
            // The old file is closed first: pcap_dump_open truncates its
            // path, and if that's the same file (by any name), the old
            // dumper's buffered packets would otherwise land in it later
            closeDumper(h);
            pcap_dumper_t* d = pcap_dump_open(p, path.c_str());
            if (!d)
                praia::error(fn + "(): " + std::string(pcap_geterr(p)));
            h->dumper = d;
            return Value();
        }));

    // pcap.dump(handle, data, timestamp?) -> nil
    module->entries["dump"] = Value(makeNative("pcap.dump", -1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.dump";
            praia::requireArityRange(args, 2, 3, fn);
            auto* h = argHandle(args, 0, fn);
            const auto& data = praia::requireString(args, 1, fn);
            if (data.size() > 0xFFFFFFFFull)
                praia::error(fn + "(): packet too large");

            struct pcap_pkthdr hdr;
            if (args.size() > 2 && !args[2].isNil()) {
                double ts = praia::requireNumber(args, 2, fn);
                if (!std::isfinite(ts))
                    praia::error(fn + "(): timestamp must be a finite number");
                // floor, so a time before 1970 keeps tv_usec in [0, 1e6)
                double sec = std::floor(ts);
                if (sec < static_cast<double>(std::numeric_limits<time_t>::min()) ||
                    sec >= static_cast<double>(std::numeric_limits<time_t>::max()))
                    praia::error(fn + "(): timestamp out of range");
                hdr.ts.tv_sec = static_cast<time_t>(sec);
                hdr.ts.tv_usec = static_cast<suseconds_t>(
                    std::min(999999.0, std::round((ts - sec) * 1000000)));
            } else {
                gettimeofday(&hdr.ts, nullptr);
            }
            hdr.caplen = static_cast<bpf_u_int32>(data.size());
            hdr.len = hdr.caplen;

            std::lock_guard<std::timed_mutex> op(h->opMu);
            openPcap(h, fn);
            std::lock_guard<std::mutex> state(h->stateMu);
            if (!h->dumper)
                praia::error(fn + "(): no dump file open (call dumpOpen first)");
            pcap_dump(reinterpret_cast<u_char*>(h->dumper),
                      &hdr, reinterpret_cast<const u_char*>(data.data()));
            return Value();
        }));

    // pcap.dumpFlush(handle) -> nil
    module->entries["dumpFlush"] = Value(makeNative("pcap.dumpFlush", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "pcap.dumpFlush";
            auto* h = argHandle(args, 0, fn);
            std::lock_guard<std::timed_mutex> op(h->opMu);
            openPcap(h, fn);
            std::lock_guard<std::mutex> state(h->stateMu);
            if (!h->dumper)
                praia::error(fn + "(): no dump file open");
            if (pcap_dump_flush(h->dumper) < 0)
                praia::error(fn + "(): flush failed");
            return Value();
        }));

    // pcap.dumpClose(handle) -> nil
    module->entries["dumpClose"] = Value(makeNative("pcap.dumpClose", 1,
        [](const std::vector<Value>& args) -> Value {
            auto* h = argHandle(args, 0, "pcap.dumpClose");
            std::lock_guard<std::timed_mutex> op(h->opMu);
            std::lock_guard<std::mutex> state(h->stateMu);
            closeDumper(h);
            return Value();
        }));

    // pcap.close(handle) -> nil. Closing twice is fine
    module->entries["close"] = Value(makeNative("pcap.close", 1,
        [](const std::vector<Value>& args) -> Value {
            auto* h = argHandle(args, 0, "pcap.close");
            // A read blocked in another task returns nil (at once on Linux,
            // within its timeout on macOS) instead of holding this up
            stopReads(h);
            std::lock_guard<std::timed_mutex> op(h->opMu);
            closeHandle(h);
            return Value();
        }));

    // pcap.devices() -> [{name, description}]
    module->entries["devices"] = Value(makeNative("pcap.devices", 0,
        [](const std::vector<Value>&) -> Value {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_if_t* devs;
            if (pcap_findalldevs(&devs, errbuf) < 0)
                praia::error("pcap.devices(): " + std::string(errbuf));

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

    // Datalink types, to compare with pcap.datalink()
    module->entries["DLT_EN10MB"] = Value(static_cast<int64_t>(DLT_EN10MB));                     // Ethernet
    module->entries["DLT_IEEE802_11_RADIO"] = Value(static_cast<int64_t>(DLT_IEEE802_11_RADIO)); // 802.11 + radiotap
}
