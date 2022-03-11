.POSIX:

mvebu64boot: mvebu64boot.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -pthread -ltinfo -o $@ $<

clean:
	rm -f mvebu64boot
