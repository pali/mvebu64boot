// (c) 2022 Pali Rohár <pali@kernel.org>, GPLv3

#define _BSD_SOURCE
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <termios.h>

#include <term.h>

#include <pthread.h>

#ifndef CRTSCTS
#define CRTSCTS 0
#endif

#ifdef __GNUC__
#define __packed __attribute__((packed))
#define __unused __attribute__((unused))
#else
#define __packed
#define __unused
#endif

#define MAIN_HDR_MAGIC		0xB105B002

struct main_header {
	uint32_t	magic;			/* 0x00-0x03 */
	uint32_t	prolog_size;		/* 0x04-0x07 */
	uint32_t	prolog_checksum;	/* 0x08-0x0b */
	uint32_t	bl_image_size;		/* 0x0c-0x0f */
	uint32_t	bl_image_checksum;	/* 0x10-0x13 */
	uint32_t	reserved1;		/* 0x14-0x17 */
	uint32_t	load_addr;		/* 0x18-0x1b */
	uint32_t	exec_addr;		/* 0x1c-0x1f */
	uint8_t		uart_cfg;		/* 0x20      */
	uint8_t		baudrate;		/* 0x21      */
	uint8_t		ext_cnt;		/* 0x22      */
	uint8_t		aux_flags;		/* 0x23      */
	uint8_t		nand_block_size;	/* 0x24      */
	uint8_t		nand_cell_type;		/* 0x25      */
	uint8_t		reserved2[26];		/* 0x26-0x3f */
} __packed;
static char static_assert_main_header[sizeof(struct main_header) == 64 ? 1 : -1] __unused;

#define EXT_TYPE_SECURITY	0x1
#define EXT_TYPE_BINARY		0x2
#define EXT_TYPE_REGISTER	0x3

struct ext_header {
	uint8_t		type;
	uint8_t		offset;
	uint16_t	reserved;
	uint32_t	size;
	uint8_t		data[];
} __packed;
static char static_assert_ext_header[sizeof(struct ext_header) == 8 ? 1 : -1] __unused;

#define SOH	0x01
#define EOT	0x04
#define ACK	0x06
#define NAK	0x15

#define XMODEM_BLOCK_SIZE	128

struct xmodem_block {
	uint8_t soh;
	uint8_t seq;
	uint8_t cseq;
	uint8_t data[XMODEM_BLOCK_SIZE];
	uint8_t csum;
} __packed;
static char static_assert_xmodem_block[sizeof(struct xmodem_block) == 132 ? 1 : -1] __unused;

static inline bool read_byte(int fd, uint8_t *byte, unsigned int timeout)
{
	struct timeval tv;
	fd_set rfds;
	int ret;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout * 1000) % 1000000;

	do {
		ret = select(fd + 1, &rfds, NULL, NULL, &tv);
	} while (ret < 0 && errno == EINTR);
	if (ret == 0)
		errno = ETIMEDOUT;
	if (ret <= 0)
		return false;

	do {
		ret = read(fd, byte, 1);
	} while (ret < 0 && errno == EINTR);
	if (ret == 0)
		errno = ETIMEDOUT;
	if (ret <= 0)
		return false;

	return true;
}

static bool write_buf(int fd, const uint8_t *buf, size_t size)
{
	while (size > 0) {
		ssize_t ret = write(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return false;
		buf += ret;
		size -= ret;
	}

	return true;
}

static inline bool write_byte(int fd, uint8_t byte)
{
	return write_buf(fd, &byte, 1);
}

static inline void print_progress(unsigned int cur, unsigned int max)
{
	char buf[20];
	int len = snprintf(buf, sizeof(buf), "%u", max);
	printf("%*u/%s", len, cur, buf);
}

static inline void xmodem_print_status(unsigned int cur_block, unsigned int tot_blocks, unsigned int retries, unsigned int cur_attempt, unsigned int tot_attempts)
{
	printf("\r%3u%% done (", 100 * cur_block / tot_blocks);
	if (retries != (unsigned int)-1) {
		print_progress(cur_block * XMODEM_BLOCK_SIZE, tot_blocks * XMODEM_BLOCK_SIZE);
		printf(" bytes, ");
		print_progress(cur_block, tot_blocks);
		printf(" blocks, %2u retries, ", retries);
	}
	print_progress(cur_attempt, tot_attempts);
	printf(" attempts)");
	fflush(stdout);
}

static bool xmodem_process_block(int fd, const struct xmodem_block *block, unsigned int cur_block, unsigned int tot_blocks, unsigned int *retries, bool allow_output)
{
	const int max_i = 16;
	bool output = false;
	uint8_t byte = 0;

	for (int i = 0; i < max_i; i++) {
		if (!allow_output || i == 0)
			xmodem_print_status(cur_block, tot_blocks, *retries, i+1, max_i);
		if (i >= 7)
			usleep(2000 * 1000);
		if (!write_buf(fd, (const uint8_t *)block, sizeof(*block))) {
			printf("\n");
			fprintf(stderr, "Error: Failed to send xmodem block: %s\n", strerror(errno));
			return false;
		}
		if (allow_output && i == 0) {
			xmodem_print_status(cur_block+1, tot_blocks, *retries, i+1, max_i);
			printf("\n");
			printf("Waiting for BootROM...\n");
			output = false;
		}
retry:
		if (!read_byte(fd, &byte, allow_output ? 10000 : 2000)) {
			if (errno != ETIMEDOUT) {
				if (output || !allow_output)
					printf("\n");
				fprintf(stderr, "Error: Failed to read byte: %s\n", strerror(errno));
				return false;
			}
			byte = NAK;
		}
		if (byte == ACK) {
			if (!allow_output)
				xmodem_print_status(cur_block+1, tot_blocks, *retries, cur_block+1 == tot_blocks ? (i+1) : 0, max_i);
			if (output || (!allow_output && cur_block+1 == tot_blocks))
				printf("\n");
			return true;
		}
		if (allow_output && byte != NAK) {
			if (!output) {
				printf("\n");
				output = true;
			}
			putchar(byte);
			fflush(stdout);
			goto retry;
		}
		(*retries)++;
	}

	if (output || !allow_output)
		printf("\n");
	if (allow_output)
		fprintf(stderr, "Error: %s\n", byte == NAK ? "BootROM rejected image" : "BootROM did not respond");
	else
		fprintf(stderr, "Error: Failed to transfer xmodem block: %s\n", byte == NAK ? "BootROM rejected it" : "BootROM did not respond");
	return false;
}

static bool xmodem_transfer(int fd, uint8_t *seq, const uint8_t *data, size_t size, bool allow_output_last_ack)
{
	struct xmodem_block block;
	const unsigned int tot_blocks = (size + sizeof(block.data) - 1) / sizeof(block.data);
	unsigned int cur_block = 0;
	unsigned int retries = 0;

	while (size > 0) {
		const size_t n = size < sizeof(block.data) ? size : sizeof(block.data);
		const bool allow_output = (allow_output_last_ack && size <= sizeof(block.data));

		block.soh = SOH;
		block.seq = *seq;
		block.cseq = ~block.seq;

		memcpy(&block.data[0], data, n);
		memset(&block.data[n], 0, sizeof(block.data) - n);

		block.csum = 0;
		for (size_t i = 0; i < n; i++)
			block.csum += block.data[i];

		if (!xmodem_process_block(fd, &block, cur_block, tot_blocks, &retries, allow_output))
			return false;

		size -= n;
		data += n;
		(*seq)++;
		cur_block++;
	}

	return true;
}

static bool xmodem_finish(int fd)
{
	const int max_i = 16;
	uint8_t byte = 0;

	for (int i = 0; i < max_i; i++) {
		xmodem_print_status(0, 1, -1, i+1, max_i);
		if (i >= 7)
			usleep(2000 * 1000);
		if (!write_byte(fd, EOT)) {
			printf("\n");
			fprintf(stderr, "Error: Failed to send EOT byte: %s\n", strerror(errno));
			return false;
		}
		if (!read_byte(fd, &byte, 2000)) {
			if (errno != ETIMEDOUT) {
				printf("\n");
				fprintf(stderr, "Error: Failed to read byte: %s\n", strerror(errno));
				return false;
			}
			byte = NAK;
		}
		if (byte == ACK) {
			xmodem_print_status(1, 1, -1, i+1, max_i);
			printf("\n");
			return true;
		}
	}

	printf("\n");
	fprintf(stderr, "Error: Failed to finish transfer: %s\n", byte == NAK ? "BootROM rejected it" : "BootROM did not respond");
	return false;
}

static inline uint32_t le32_to_cpu(const void *ptr)
{
	const uint8_t *buffer = ptr;
	return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24);
}

static inline void cpu_to_le32(void *ptr, uint32_t number)
{
	uint8_t *buffer = ptr;
	buffer[0] = number;
	buffer[1] = number >> 8;
	buffer[2] = number >> 16;
	buffer[3] = number >> 24;
}

static uint32_t checksum32(const uint8_t *buffer, size_t size)
{
	uint32_t checksum = 0;
	while (size >= 4) {
		checksum += le32_to_cpu(buffer);
		buffer += 4;
		size -= 4;
	}
	return checksum;
}

static bool transfer_image_file(int fd, const uint8_t *image)
{
	const struct main_header *hdr = (const struct main_header *)image;
	uint8_t seq = 1;

	printf("Sending image prolog... (%u bytes)\n", (unsigned int)le32_to_cpu(&hdr->prolog_size));
	if (!xmodem_transfer(fd, &seq, image, le32_to_cpu(&hdr->prolog_size), true))
		return false;

	printf("Sending image bootloader... (%u bytes)\n", (unsigned int)le32_to_cpu(&hdr->bl_image_size));
	if (!xmodem_transfer(fd, &seq, image + le32_to_cpu(&hdr->prolog_size), le32_to_cpu(&hdr->bl_image_size), false))
		return false;

	printf("Finishing...\n");
	if (!xmodem_finish(fd))
		return false;

	printf("Transfer of image file is complete\n");
	return true;
}

static bool patch_image_file(uint8_t *image)
{
	struct main_header *hdr = (struct main_header *)image;
	uint32_t prolog_size = le32_to_cpu(&hdr->prolog_size);
	uint32_t bootloader_size = le32_to_cpu(&hdr->bl_image_size);
	uint32_t prolog_align = prolog_size % XMODEM_BLOCK_SIZE;

	if (prolog_align > 0) {
		printf("Aligning prolog size to xmodem block size\n");
		memmove(image + prolog_size + XMODEM_BLOCK_SIZE - prolog_align, image + prolog_size, bootloader_size);
		memset(image + prolog_size, 0, XMODEM_BLOCK_SIZE - prolog_align);
		prolog_size += XMODEM_BLOCK_SIZE - prolog_align;
		cpu_to_le32(&hdr->prolog_size, prolog_size);
		printf("Updating prolog checksum\n");
		cpu_to_le32(&hdr->prolog_checksum, checksum32(image, prolog_size) - le32_to_cpu(&hdr->prolog_checksum));
	}

	return true;
}

static bool validate_image_file(const uint8_t *image, size_t size)
{
	const struct main_header *hdr = (const struct main_header *)image;
	const struct ext_header *ext;

	printf("Validating image file\n");

	if (size < sizeof(*hdr)) {
		fprintf(stderr, "Error: Image file is too small\n");
		return false;
	}

	if (le32_to_cpu(&hdr->magic) != MAIN_HDR_MAGIC) {
		fprintf(stderr, "Error: Image file has invalid header magic\n");
		return false;
	}

	if (le32_to_cpu(&hdr->prolog_size) < sizeof(*hdr)) {
		fprintf(stderr, "Error: Image file has too small prolog\n");
		return false;
	}

	if (le32_to_cpu(&hdr->prolog_size) > size) {
		fprintf(stderr, "Error: Image file has larger prolog than image size\n");
		return false;
	}

	if (le32_to_cpu(&hdr->prolog_size) > 384*1024) {
		fprintf(stderr, "Error: Image file has larger prolog than maximal size of 384 kB\n");
		return false;
	}

	if (checksum32(image, le32_to_cpu(&hdr->prolog_size)) - le32_to_cpu(&hdr->prolog_checksum) != le32_to_cpu(&hdr->prolog_checksum)) {
		fprintf(stderr, "Error: Image file has invalid prolog checksum\n");
		return false;
	}

	if (le32_to_cpu(&hdr->bl_image_size) % 4) {
		fprintf(stderr, "Error: Image file has invalid bootloader size\n");
		return false;
	}

	if (le32_to_cpu(&hdr->bl_image_size) > size || le32_to_cpu(&hdr->prolog_size) + le32_to_cpu(&hdr->bl_image_size) > size) {
		fprintf(stderr, "Error: Image file has larger bootloader than image size\n");
		return false;
	}

	if (checksum32(image + le32_to_cpu(&hdr->prolog_size), le32_to_cpu(&hdr->bl_image_size)) != le32_to_cpu(&hdr->bl_image_checksum)) {
		fprintf(stderr, "Error: Image file has invalid bootloader checksum\n");
		return false;
	}

	if (le32_to_cpu(&hdr->load_addr) % 8) {
		fprintf(stderr, "Error: Image file has invalid load address\n");
		return false;
	}

	if (le32_to_cpu(&hdr->exec_addr) % 4) {
		fprintf(stderr, "Error: Image file has invalid exec address\n");
		return false;
	}

	ext = (const struct ext_header *)((const uint8_t *)hdr + sizeof(*hdr));

	for (uint8_t i = 0; i < hdr->ext_cnt; i++) {
		if (sizeof(*ext) + ext->offset > le32_to_cpu(&ext->size)) {
			fprintf(stderr, "Error: Image file has invalid extension\n");
			return false;
		}
		if (le32_to_cpu(&ext->size) > size || (size_t)((const uint8_t *)ext - image) + le32_to_cpu(&ext->size) > size) {
			fprintf(stderr, "Error: Image file has larger extension than image size\n");
			return false;
		}
		if (ext->type == EXT_TYPE_SECURITY) {
			fprintf(stderr, "Error: Image file is signed\n");
			return false;
		}
		ext = (const struct ext_header *)((const uint8_t *)ext + le32_to_cpu(&ext->size));
	}

	if ((size_t)((const uint8_t *)ext - image) > le32_to_cpu(&hdr->prolog_size)) {
		fprintf(stderr, "Error: Image file has larger extension than prolog size\n");
		return false;
	}

	return true;
}

static uint8_t *read_image_file(const char *file, size_t *size)
{
	uint8_t *image;
	off_t len;
	int fd;

	printf("Reading image file '%s'\n", file);

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error: Cannot open image file '%s': %s\n", file, strerror(errno));
		return NULL;
	}

	len = lseek(fd, 0, SEEK_END);
	if (len == (off_t)-1) {
		fprintf(stderr, "Error: Cannot seek to the end of image file '%s': %s\n", file, strerror(errno));
		close(fd);
		return NULL;
	}

	if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "Error: Cannot seek to the beginning of image file '%s': %s\n", file, strerror(errno));
		close(fd);
		return NULL;
	}

	image = malloc(len + XMODEM_BLOCK_SIZE + XMODEM_BLOCK_SIZE);
	if (!image) {
		fprintf(stderr, "Error: Cannot allocate memory: %s\n", strerror(errno));
		close(fd);
		return NULL;
	}

	*size = 0;
	while (*size < (size_t)len) {
		ssize_t ret = read(fd, image + *size, len - *size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0) {
			fprintf(stderr, "Error: Cannot read image file '%s': %s\n", file, strerror(errno));
			close(fd);
			free(image);
			return NULL;
		}
		*size += ret;
	}

	close(fd);
	return image;
}

static void loop_terminal(int fd)
{
	uint8_t buf_term[512];
	uint8_t buf_fd[512];
	struct termios otio;
	struct termios tio;
	bool restore_term;
	const char *kbs;
	size_t kbs_state;
	size_t kbs_len;
	size_t kbs_pos;
	size_t len_term;
	size_t len_fd;
	fd_set rfds;
	fd_set wfds;
	fd_set efds;
	int state;

	printf("\n");
	restore_term = false;
	kbs = NULL;
	kbs_len = 0;

	if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &tio) == 0) {
		otio = tio;
		cfmakeraw(&tio);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &tio) == 0) {
			restore_term = true;
			printf("[Type Ctrl-\\ + c to quit]\r\n");
			if (setupterm(NULL, STDOUT_FILENO, (int [1]){ 0 }) == 0) {
				kbs = tigetstr("kbs");
				if (kbs == (char *)-1)
					kbs = NULL;
				if (kbs)
					kbs_len = strlen(kbs);
			}
		}
	}

	len_term = 0;
	len_fd = 0;
	state = 0;
	kbs_state = 0;

	while (state != 2) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);

		if (len_term < sizeof(buf_term)-1)
			FD_SET(STDIN_FILENO, &rfds);
		if (len_fd < sizeof(buf_fd))
			FD_SET(fd, &rfds);

		if (len_fd > 0)
			FD_SET(STDOUT_FILENO, &wfds);
		if (len_term > 0)
			FD_SET(fd, &wfds);

		FD_SET(STDIN_FILENO, &efds);
		FD_SET(STDOUT_FILENO, &efds);
		FD_SET(fd, &efds);

		if (select(fd+1, &rfds, &wfds, &efds, NULL) <= 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (FD_ISSET(STDIN_FILENO, &efds) || FD_ISSET(STDOUT_FILENO, &efds) || FD_ISSET(fd, &efds))
			break;

		if (FD_ISSET(STDIN_FILENO, &rfds)) {
			ssize_t ret;
			kbs_pos = len_term;
			if (state == 1)
				buf_term[len_term++] = '\\'+1-'A';
			if (kbs_state) {
				memcpy(&buf_term[len_term], kbs, kbs_state);
				len_term += kbs_state;
				kbs_state = 0;
			}
			ret = read(STDIN_FILENO, buf_term + len_term, sizeof(buf_term) - len_term);
			if (ret <= 0) {
				if (ret == 0 || errno != EINTR)
					break;
				ret = 0;
			}
			for (size_t i = len_term; i < len_term + ret; i++) {
				if (buf_term[i] == '\\'+1-'A')
					state = 1;
				else if (state == 1 && buf_term[i] == 'c')
					state = 2;
				else
					state = 0;
				if (state == 2) {
					len_term = i - 1;
					break;
				}
			}
			len_term += ret;
			if (state == 1)
				len_term--;
			if (kbs_len) {
				for (size_t i = kbs_pos; i < len_term; i++) {
					if (len_term - i < kbs_len) {
						if (memcmp(buf_term + i, kbs, len_term - i) == 0) {
							kbs_state = len_term - i;
							len_term = i;
						}
					} else {
						if (memcmp(buf_term + i, kbs, kbs_len) == 0) {
							buf_term[i] = '\b';
							memmove(buf_term + i + 1, buf_term + i + kbs_len, len_term - i - kbs_len);
							len_term -= kbs_len - 1;
						}
					}
				}
			}
		}

		if (FD_ISSET(fd, &rfds)) {
			ssize_t ret = read(fd, buf_fd + len_fd, sizeof(buf_fd) - len_fd);
			if (ret <= 0) {
				if (ret == 0 || errno != EINTR)
					break;
				ret = 0;
			}
			len_fd += ret;
		}

		if (FD_ISSET(STDOUT_FILENO, &wfds)) {
			ssize_t ret = write(STDOUT_FILENO, buf_fd, len_fd);
			if (ret <= 0) {
				if (ret == 0 || errno != EINTR)
					break;
				ret = 0;
			}
			if (ret > 0 && (size_t)ret != len_fd)
				memmove(buf_fd, buf_fd + ret, len_fd - ret);
			len_fd -= ret;
		}

		if (FD_ISSET(fd, &wfds)) {
			ssize_t ret = write(fd, buf_term, len_term);
			if (ret <= 0) {
				if (ret == 0 || errno != EINTR)
					break;
				ret = 0;
			}
			if (ret > 0 && (size_t)ret != len_term)
				memmove(buf_fd, buf_term + ret, len_term - ret);
			len_term -= ret;
		}
	}

	if (restore_term)
		tcsetattr(STDIN_FILENO, TCSANOW, &otio);

	printf("\n");
}

static void *write_boot_pattern_handler(void *arg)
{
	const uint8_t pattern[] = { 0xBB, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	int fd = (intptr_t)arg;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, (int [1]){ 0 });

	while (1) {
		for (int i = 0; i < 128; i++) {
			if (!write_buf(fd, pattern, sizeof(pattern))) {
				fprintf(stderr, "Error: Failed to write boot pattern: %s\n", strerror(errno));
				exit(1);
			}
		}
		if (tcdrain(fd) != 0) {
			fprintf(stderr, "Error: Failed to write boot pattern: %s\n", strerror(errno));
			exit(1);
		}
		usleep(24 * 1000);
	}
}

static bool loop_boot_pattern(int fd)
{
	struct xmodem_block block;
	pthread_t write_thread;
	uint8_t byte;
	int ret;

	printf("Sending boot pattern...\n");

	ret = pthread_create(&write_thread, NULL, write_boot_pattern_handler, (void *)(intptr_t)fd);
	if (ret) {
		fprintf(stderr, "Error: Failed to create thread: %s\n", strerror(ret));
		return false;
	}

	byte = 0;
	while (byte != NAK) {
		ret = read(fd, &byte, 1);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret != 1) {
			fprintf(stderr, "Error: Failed to read from tty device: %s\n", strerror(errno));
			break;
		}
	}

	ret = pthread_cancel(write_thread);
	if (ret) {
		fprintf(stderr, "Error: Failed to cancel thread: %s\n", strerror(ret));
		return false;
	}

	ret = pthread_join(write_thread, NULL);
	if (ret) {
		fprintf(stderr, "Error: Failed to join thread: %s\n", strerror(ret));
		return false;
	}

	if (tcflush(fd, TCOFLUSH) != 0) {
		fprintf(stderr, "Error: Failed to flush output queue of tty device: %s\n", strerror(errno));
		return false;
	}

	if (byte != NAK)
		return false;

	memset(&block, 0xff, sizeof(block));
	if (!write_buf(fd, (void *)&block, sizeof(block))) {
		fprintf(stderr, "Error: Failed to send sync sequence: %s\n", strerror(errno));
		return false;
	}

	if (tcdrain(fd) != 0) {
		fprintf(stderr, "Error: Failed to drain output queue of tty device: %s\n", strerror(errno));
		return false;
	}

	usleep(24 * 1000);

	if (tcflush(fd, TCIFLUSH) != 0) {
		fprintf(stderr, "Error: Failed to flush input queue of tty device: %s\n", strerror(errno));
		return false;
	}

	printf("BootROM is ready for image file transfer\n");
	return true;
}

static int open_tty(const char *device)
{
	struct termios tio;
	int flags;
	int fd;

	printf("Opening tty device '%s'\n", device);

	fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Error: Cannot open tty device '%s': %s\n", device, strerror(errno));
		return -1;
	}

	if (!isatty(fd)) {
		fprintf(stderr, "Error: '%s' is not tty device\n", device);
		close(fd);
		return -1;
	}

	if (tcgetattr(fd, &tio) != 0) {
		fprintf(stderr, "Error: Failed to initialize tty device '%s': %s\n", device, strerror(errno));
		close(fd);
		return -1;
	}

	cfmakeraw(&tio);
	tio.c_cflag |= CREAD | CLOCAL;
	tio.c_cflag &= ~(CSTOPB | HUPCL | CRTSCTS);
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	if (cfsetospeed(&tio, B115200) != 0) {
		fprintf(stderr, "Error: Failed to set output baudrate to 115200: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (cfsetispeed(&tio, B115200) != 0) {
		fprintf(stderr, "Error: Failed to set input baudrate to 115200: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	if (tcsetattr(fd, TCSANOW, &tio) != 0) {
		fprintf(stderr, "Error: Failed to initialize tty device '%s': %s\n", device, strerror(errno));
		close(fd);
		return -1;
	}

	if ((flags = fcntl(fd, F_GETFL)) < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
		fprintf(stderr, "Error: Failed to set blocking mode for tty device '%s': %s\n", device, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static void usage(void)
{
	puts("Usage: mvebu64boot [-t] [-b] [image] device");
	puts("");
	puts("mvebu64boot - Boot 64-bit Marvell EBU SoC over UART");
	puts("");
	puts("Options:");
	puts("  -b             send boot pattern");
	puts("  -t             run mini terminal");
	exit(0);
}

static bool parse_args(int argc, char *argv[], bool *terminal, bool *boot, const char **file, const char **device)
{
	*terminal = false;
	*boot = false;
	*file = NULL;

	if (argc > 0) {
		argc--;
		argv++;
	}

	while (argc > 0 && argv[0][0] == '-') {
		if (strcmp(argv[0], "-t") == 0) {
			*terminal = true;
		} else if (strcmp(argv[0], "-b") == 0) {
			*boot = true;
		} else if (strcmp(argv[0], "--") == 0) {
			argc--;
			argv++;
			break;
		} else if (strcmp(argv[0], "-h") == 0) {
			usage();
		} else {
			fprintf(stderr, "Error: Unknown option %s\n", argv[0]);
			return false;
		}
		argc--;
		argv++;
	}

	if (argc == 1) {
		*device = argv[0];
	} else if (argc == 2) {
		*file = argv[0];
		*device = argv[1];
	} else if (argc <= 0) {
		fprintf(stderr, "Error: Missing tty device\n");
		return false;
	} else {
		fprintf(stderr, "Error: Extra argument '%s'\n", argv[0]);
		return false;
	}

	return true;
}

int main(int argc, char *argv[])
{
	const char *device;
	const char *file;
	bool terminal;
	bool boot;
	void *image;
	size_t size;
	int fd;

	image = NULL;
	fd = -1;

	if (!parse_args(argc, argv, &terminal, &boot, &file, &device))
		goto err;

	if (file && !(image = read_image_file(file, &size)))
		goto err;

	if (image && !validate_image_file(image, size))
		goto err;

	if (image && !patch_image_file(image))
		goto err;

	if ((fd = open_tty(device)) < 0)
		goto err;

	if (boot && !loop_boot_pattern(fd))
		goto err;

	if (image && !transfer_image_file(fd, image))
		goto err;

	free(image);
	image = NULL;

	if (terminal)
		loop_terminal(fd);

	close(fd);
	return 0;

err:
	if (fd >= 0)
		close(fd);
	free(image);
	return 1;
}
