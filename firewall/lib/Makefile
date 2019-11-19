C = gcc
LIB = libfire.a
OBJS = arp.o ether.o ip.o pkt.o tcp.o udp.o utils.o firewall.o

ifeq ($(DEBUG), 1)
DBG_FLAGS = -DDEBUG
endif

$(LIB): $(OBJS)
	$(AR) rv $@ $(OBJS)

%.o: %.c
	$(C) $(DBG_FLAGS) -c -I../include $< -o $@

clean:
	rm -f $(OBJS) $(LIB)