#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <termios.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

static int waitfor(int fd, int timeout)
{
	fd_set rfds;
	struct timeval tv = { timeout, 0 };

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	return select(fd + 1, &rfds, NULL, NULL, (timeout > 0) ? &tv : NULL);
}

int press_any_key_main(int argc, char *argv[])
{
	int fd;

	if ((fd = open("/dev/console", O_RDWR)) < 0) {
		perror("/dev/console");
		return 0;
	}

	//wait console
	fprintf(stderr, "Press any key to stop...\n");
	if (waitfor(fd, 3) <= 0) {
		return 1;
	}

	return 0;
}