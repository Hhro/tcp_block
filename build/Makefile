EXEC = tcp_block
CPP = g++

$(EXEC): main.o
	$(CPP) -o $(EXEC) main.o -L ../lib -lxpkt -lpthread -lpcap

%.o: %.cpp
	$(CPP) -c $< -o $@ -I../include

clean:
	rm main.o tcp_block
