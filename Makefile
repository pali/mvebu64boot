.POSIX:

mvebu64boot: mvebu64boot.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -pthread -o $@ $< -ltinfo

clean:
	rm -f mvebu64boot
