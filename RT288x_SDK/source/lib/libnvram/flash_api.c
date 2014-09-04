#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/autoconf.h>

#include "flash_api.h"

struct mtd_info_user {
	u_char type;
	u_int32_t flags;
	u_int32_t size;
	u_int32_t erasesize;
	u_int32_t oobblock;
	u_int32_t oobsize;
	u_int32_t ecctype;
	u_int32_t eccsize;
};

struct erase_info_user {
	u_int32_t start;
	u_int32_t length;
};

#define MEMGETINFO	_IOR('M', 1, struct mtd_info_user)
#define MEMERASE	_IOW('M', 2, struct erase_info_user)

int mtd_open(const char *name, int flags)
{
	FILE *fp;
	char dev[80];
	int i, ret;

	if ((fp = fopen("/proc/mtd", "r"))) {
		while (fgets(dev, sizeof(dev), fp)) {
			if (sscanf(dev, "mtd%d:", &i) && strstr(dev, name)) {
				snprintf(dev, sizeof(dev), "/dev/mtd/%d", i);
				if ((ret = open(dev, flags)) < 0) {
					snprintf(dev, sizeof(dev), "/dev/mtd%d", i);
					ret = open(dev, flags);
				}
				fclose(fp);
				return ret;
			}
		}
		fclose(fp);
	}
	return -1;
}

int flash_read_mac(char *buf)
{
	int fd, ret;

	if (!buf)
		return -1;
	fd = mtd_open("Factory", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open mtd device\n");
		return -1;
	}
#if ! defined (NO_WIFI_SOC)
	lseek(fd, 0x2E, SEEK_SET);
#else
	lseek(fd, 0xE006, SEEK_SET);
#endif
	ret = read(fd, buf, 6);
	close(fd);
	return ret;
}

int flash_read_NicConf(char *buf)
{
	int fd, ret;

	if (!buf)
		return -1;
	fd = mtd_open("Factory", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open mtd device\n");
		return -1;
	}
	lseek(fd, 0x34, SEEK_SET);
	ret = read(fd, buf, 6);
	close(fd);
	return ret;
}

int flash_read(char *buf, off_t from, size_t len)
{
	int fd, ret;
	struct mtd_info_user info;

	fd = mtd_open("Config", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Could not open mtd device\n");
		return -1;
	}

	if (ioctl(fd, MEMGETINFO, &info)) {
		fprintf(stderr, "Could not get mtd device info\n");
		close(fd);
		return -1;
	}
	if (len > info.size) {
		fprintf(stderr, "Too many bytes - %d > %d bytes\n", len, info.erasesize);
		close(fd);
		return -1;
	}

	lseek(fd, from, SEEK_SET);
	ret = read(fd, buf, len);
	if (ret == -1) {
		fprintf(stderr, "Reading from mtd failed\n");
		close(fd);
		return -1;
	}

	close(fd);
	return ret;
}

#define min(x,y) ({ typeof(x) _x = (x); typeof(y) _y = (y); (void) (&_x == &_y); _x < _y ? _x : _y; })

int flash_write(char *buf, off_t to, size_t len)
{
	int fd, ret = 0;
	char *bak = NULL;
	struct mtd_info_user info;
	struct erase_info_user ei;

	fd = mtd_open("Config", O_RDWR | O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "Could not open mtd device\n");
		return -1;
	}

	if (ioctl(fd, MEMGETINFO, &info)) {
		fprintf(stderr, "Could not get mtd device info\n");
		close(fd);
		return -1;
	}
	if (len > info.size) {
		fprintf(stderr, "Too many bytes: %d > %d bytes\n", len, info.erasesize);
		close(fd);
		return -1;
	}

	while (len > 0) {
		if ((len & (info.erasesize-1)) || (len < info.erasesize)) {
			int piece_size;
			unsigned int piece, bakaddr;

			bak = (char *)malloc(info.erasesize);
			if (bak == NULL) {
				fprintf(stderr, "Not enough memory\n");
				close(fd);
				return -1;
			}

			bakaddr = to & ~(info.erasesize - 1);
			lseek(fd, bakaddr, SEEK_SET);

			ret = read(fd, bak, info.erasesize);
			if (ret == -1) {
				fprintf(stderr, "Reading from mtd failed\n");
				close(fd);
				free(bak);
				return -1;
			}

			piece = to & (info.erasesize - 1);
			piece_size = min(len, info.erasesize - piece);
			memcpy(bak + piece, buf, piece_size);

			ei.start = bakaddr;
			ei.length = info.erasesize;
			if (ioctl(fd, MEMERASE, &ei) < 0) {
				fprintf(stderr, "Erasing mtd failed\n");
				close(fd);
				free(bak);
				return -1;
			}

			lseek(fd, bakaddr, SEEK_SET);
			ret = write(fd, bak, info.erasesize);
			if (ret == -1) {
				fprintf(stderr, "Writing to mtd failed\n");
				close(fd);
				free(bak);
				return -1;
			}

			free(bak);
			buf += piece_size;
			to += piece_size;
			len -= piece_size;
		}
		else {
			ei.start = to;
			ei.length = info.erasesize;
			if (ioctl(fd, MEMERASE, &ei) < 0) {
				fprintf(stderr, "Erasing mtd failed\n");
				close(fd);
				return -1;
			}

			ret = write(fd, buf, info.erasesize);
			if (ret == -1) {
				fprintf(stderr, "Writing to mtd failed\n");
				close(fd);
				free(bak);
				return -1;
			}

			buf += info.erasesize;
			to += info.erasesize;
			len -= info.erasesize;
		}
	}

	close(fd);
	return ret;
}

unsigned int flush_mtd_size(char *part)
{
	char buf[128], name[32], size[32], dev[32], erase[32];
	unsigned int result=0;
	FILE *fp = fopen("/proc/mtd", "r");
	if(!fp){
		fprintf(stderr, "mtd support not enable?");
		return 0;
	}
	while(fgets(buf, sizeof(buf), fp)){
		sscanf(buf, "%s %s %s %s", dev, size, erase, name);
		if(!strcmp(name, part)){
			result = strtol(size, NULL, 16);
			break;
		}
	}
	fclose(fp);
	return result;
}

int mtd_write_bootloader(char *filename, int offset, int len)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/bin/mtd_write -o %d -l %d write %s Bootloader", offset, len, filename);
	fprintf(stderr, "write bootloader...");
    return system(cmd);
}

int mtd_write_firmware(char *filename, int offset, int len)
{
	char cmd[512];
	int status;
#if defined (CONFIG_RT2880_FLASH_8M) || defined (CONFIG_RT2880_FLASH_16M)
    /* workaround: erase 8k sector by myself instead of mtd_erase */
    /* this is for bottom 8M NOR flash only */
    snprintf(cmd, sizeof(cmd), "/bin/flash -f 0x400000 -l 0x40ffff");
    system(cmd);
#endif

#if defined (CONFIG_RT2880_ROOTFS_IN_RAM)
    snprintf(cmd, sizeof(cmd), "/bin/mtd_write -o %d -l %d write %s Kernel", offset, len, filename);
    status = system(cmd);
#elif defined (CONFIG_RT2880_ROOTFS_IN_FLASH)
  #ifdef CONFIG_ROOTFS_IN_FLASH_NO_PADDING
    snprintf(cmd, sizeof(cmd), "/bin/mtd_write -o %d -l %d write %s Kernel_RootFS", offset, len, filename);
    status = system(cmd);
  #else
    snprintf(cmd, sizeof(cmd), "/bin/mtd_write -o %d -l %d write %s Kernel", offset,  CONFIG_MTD_KERNEL_PART_SIZ, filename);
    status = system(cmd);
	if (status != 0)
		return -1;
    if(len > CONFIG_MTD_KERNEL_PART_SIZ ){
		snprintf(cmd, sizeof(cmd), "/bin/mtd_write -o %d -l %d write %s RootFS", offset + CONFIG_MTD_KERNEL_PART_SIZ, len - CONFIG_MTD_KERNEL_PART_SIZ, filename);
		status = system(cmd);
    }
  #endif
#else
    fprintf(stderr, "flash api: no CONFIG_RT2880_ROOTFS defined!");
#endif
    return status;
}

/*
 *  taken from "mkimage -l" with few modified....
 */
int image_check(int image_fd, int offset, int len, char *err_msg)
{
	struct stat sbuf;

	int  data_len;
	char *data;
	unsigned char *ptr;
	unsigned long checksum;

	image_header_t header;
	image_header_t *hdr = &header;

	if(image_fd < 0) {
		sprintf (err_msg, "Can't open file %s\n", strerror(errno));
		return 0;
	}

	if ((unsigned)len < sizeof(image_header_t)) {
		sprintf (err_msg, "Bad size is no valid image.\n");
		return 0;
	}

	if (fstat(image_fd, &sbuf) < 0) {
		sprintf (err_msg, "Can't stat %s\n", strerror(errno));
		return 0;
	}

	ptr = (unsigned char *) mmap(0, sbuf.st_size, PROT_READ, MAP_SHARED, image_fd, 0);
	if ((caddr_t)ptr == (caddr_t)-1) {
		sprintf (err_msg, "Can't mmap: %s\n", strerror(errno));
		return 0;
    }
	ptr += offset;

	/*
	 *  handle Header CRC32
	 */
    memcpy (hdr, ptr, sizeof(image_header_t));

    if (ntohl(hdr->ih_magic) != IH_MAGIC) {
		munmap(ptr, len);
		sprintf (err_msg, "Bad Magic Number is no valid image\n");
		return 0;
	}

	data = (char *)hdr;

    checksum = ntohl(hdr->ih_hcrc);
    hdr->ih_hcrc = htonl(0);	/* clear for re-calculation */

    if (crc32 (0, data, sizeof(image_header_t)) != checksum) {
		munmap(ptr, len);
		sprintf (err_msg, "*** Warning: has bad header checksum!\n");
		return 0;
    }

	/*
	 *  handle Data CRC32
	 */
    data = (char *)(ptr + sizeof(image_header_t));
    data_len  = len - sizeof(image_header_t) ;

    if (crc32 (0, data, data_len) != ntohl(hdr->ih_dcrc)) {
		munmap(ptr, len);
		sprintf (err_msg, "*** Warning: has corrupted data!\n");
		return 0;
    }

    /*
    * ROY: fw name match 
    */
    if(strncmp(hdr->ih_name, "MR", 2) != 0) {
    	munmap(ptr, len);
    	sprintf(err_msg, "Fireware name not match!\n");
    	return 0;
    }

	/*
	 * compare MTD partition size and image size
	 */
#if defined (CONFIG_RT2880_ROOTFS_IN_RAM)
	if(len > flush_mtd_size("\"Kernel\"")){
		munmap(ptr, len);
		sprintf(err_msg, "*** Warning: the image file(0x%x) is bigger than Kernel MTD partition.\n", len);
		return 0;
	}
#elif defined (CONFIG_RT2880_ROOTFS_IN_FLASH)
  #ifdef CONFIG_ROOTFS_IN_FLASH_NO_PADDING
	if(len > flush_mtd_size("\"Kernel_RootFS\"")){
		munmap(ptr, len);
		sprintf(err_msg, "*** Warning: the image file(0x%x) is bigger than Kernel_RootFS MTD partition.\n", len);
		return 0;
	}
  #else
	if(len < CONFIG_MTD_KERNEL_PART_SIZ){
		munmap(ptr, len);
		sprintf(err_msg, "*** Warning: the image file(0x%x) size doesn't make sense.\n", len);
		return 0;
	}

	if((len - CONFIG_MTD_KERNEL_PART_SIZ) > flush_mtd_size("\"RootFS\"")){
		munmap(ptr, len);
		sprintf(err_msg, "*** Warning: the image file(0x%x) is bigger than RootFS MTD partition.\n", len - CONFIG_MTD_KERNEL_PART_SIZ);
		return 0;
	}
  #endif
#else
#error "flash api: no CONFIG_RT2880_ROOTFS defined!"
#endif
	
	munmap(ptr, len);
	return 1;
}
