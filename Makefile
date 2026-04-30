PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT = plugins/pcap.dylib
  LDFLAGS = -undefined dynamic_lookup -lpcap
else
  OUT = plugins/pcap-linux-$(shell uname -m).so
  LDFLAGS = -lpcap
endif

all:
	g++ -std=c++17 -shared -fPIC -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) plugins/pcap.cpp

clean:
	rm -f plugins/pcap.dylib plugins/pcap-linux-*.so

.PHONY: all clean
