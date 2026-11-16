PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT = plugins/pcap.dylib
  LDFLAGS = -undefined dynamic_lookup
  # pcap.cpp self-defines _XOPEN_SOURCE / _DARWIN_C_SOURCE before including
  # praia's fiber.h (which uses swapcontext(3) on macOS).
  EXTRA_FLAGS = -Wno-deprecated-declarations
else
  OUT = plugins/pcap-linux-$(shell uname -m).so
  LDFLAGS =
  EXTRA_FLAGS =
endif

# After the source: linkers using --as-needed (Ubuntu's default) drop a
# library named before the code that uses it, and the plugin won't load
LDLIBS = -lpcap

all:
	g++ -std=c++17 -shared -fPIC $(EXTRA_FLAGS) -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) plugins/pcap.cpp $(LDLIBS)

# Only this platform's build: the other prebuilt plugins are committed
clean:
	rm -f $(OUT)

.PHONY: all clean
