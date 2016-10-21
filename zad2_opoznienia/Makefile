CXXFLAGS = -std=c++11 -Wall -c -I/usr/local/include
LDFLAGS = -Wall -lboost_system -pthread

OBJECTS = main.o \
		TELNETServer.o \
		SDServerClient.o \
		LatencyDatabase.o \
		bitops.o \
		DNSPacket.o \
		dns_format.o \
		ICMPEchoPacket.o \
		ICMPService.o \
		TCPService.o \
		UDPService.o \

all : opoznienia

%.o : %.cc
	$(CXX) $(CXXFLAGS) $<

opoznienia : $(OBJECTS)
	$(CXX) -o opoznienia $(OBJECTS) $(LDFLAGS)

clean :
	rm -f $(OBJECTS) $(ALL)
