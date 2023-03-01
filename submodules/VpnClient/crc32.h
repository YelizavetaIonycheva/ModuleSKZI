#ifndef __CRC32_H
#define __CRC32_H

unsigned int crc32(unsigned char *buf, unsigned int len);
unsigned int KS_MOD32(unsigned short *pBuffer, unsigned int len, unsigned int T, unsigned char isEnd);
#endif
