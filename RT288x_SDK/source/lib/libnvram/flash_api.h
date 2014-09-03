#ifndef __FLASH_API
#define __FLASH_API

#include <inttypes.h>

/* mkimage */
#define IH_MAGIC    0x27051956
#define IH_NMLEN    32
typedef struct image_header {
    uint32_t    ih_magic;   /* Image Header Magic Number    */
    uint32_t    ih_hcrc;    /* Image Header CRC Checksum    */
    uint32_t    ih_time;    /* Image Creation Timestamp */
    uint32_t    ih_size;    /* Image Data Size      */
    uint32_t    ih_load;    /* Data  Load  Address      */
    uint32_t    ih_ep;      /* Entry Point Address      */
    uint32_t    ih_dcrc;    /* Image Data CRC Checksum  */
    uint8_t     ih_os;      /* Operating System     */
    uint8_t     ih_arch;    /* CPU architecture     */
    uint8_t     ih_type;    /* Image Type           */
    uint8_t     ih_comp;    /* Compression Type     */
    uint8_t     ih_name[IH_NMLEN];  /* Image Name       */
} image_header_t;

int flash_read(char *buf, off_t from, size_t len);
int flash_write(char *buf, off_t to, size_t len);
unsigned int flush_mtd_size(char *part);

int image_check(int image_fd, int offset, int len, char *err_msg);
int mtd_write_firmware(char *imagefile, int offset, int len);
int mtd_write_bootloader(char *imagefile, int offset, int len);

#endif
