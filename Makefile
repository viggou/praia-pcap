PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT = plugins/pcap.dylib
  LDFLAGS = -undefined dynamic_lookup -lpcap
  # pcap.cpp self-defines _XOPEN_SOURCE / _DARWIN_C_SOURCE before including
  # praia's fiber.h (which uses swapcontext(3) on macOS).
  EXTRA_FLAGS = -Wno-deprecated-declarations
else
  OUT = plugins/pcap-linux-$(shell uname -m).so
  LDFLAGS = -lpcap
  EXTRA_FLAGS =
endif

all:
	g++ -std=c++17 -shared -fPIC $(EXTRA_FLAGS) -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) plugins/pcap.cpp

clean:
	rm -f plugins/pcap.dylib plugins/pcap-linux-*.so

.PHONY: all clean
