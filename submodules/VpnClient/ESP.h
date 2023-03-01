#ifndef _ESP_H 
#define _ESP_H

#include "IKEv2.h"
// Структура пакета ESP

typedef struct esp_packet {
	unsigned int SPI;		// SPI
	unsigned int SN;		// Sequence Number (Порядковый номер)
	unsigned char VI[8];
	unsigned char IZV[8];
	unsigned char * encrData;
	unsigned char nextH;
	unsigned char padLen; 
	unsigned char IMZ[8];
} ESP_PACKET;

/***** Функции обработки данных протокола IKEv2 *****/

int esp_processing_data(unsigned char * dataIn, int lenDataIn, unsigned char ** dataOut, int * lenDataOut);

int createBlockESPfromBuf(unsigned char * data, int lenData, ESP_PACKET * block_SA);

//Функция формирования пакета ESP
int esp_encapsul_data(unsigned char * dataIn, int lenDataIn, unsigned char ** dataOut, int * lenDataOut);

int esp_mmt_encapsul_data(IKEv2_STRUCT_SA * ikev2_sa_a, unsigned char * dataIn, int lenDataIn, unsigned char ** dataOut, int * lenDataOut, unsigned char protocol);

#endif
