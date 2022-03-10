TARGET = test
CFLAGS = -O3
LDFLAGS = -lcrypto -lssl -lm

$(TARGET): test.o libdpf.a
	gcc $^ -o $@ $(LDFLAGS)

test.o: test.c ../include/dpf.h
	gcc $(CFLAGS) -c $< -o $@ $(LDFLAGS)

libdpf.a: dpf.o vdpf.o mmo.o common.o sha256.o
	ar rcs $@ $^

dpf.o: dpf.c ../include/dpf.h
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

mmo.o: mmo.c ../include/mmo.h 
	gcc $(CFLAGS) -c -o $@ $< $(LDFLAGS)

clean:
	rm -f *.o *.a $(TARGET)