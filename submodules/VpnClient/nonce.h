#ifndef NONCE_H_
#define NONCE_H_


#ifndef NONCE_EXT
#define NONCE_GLOBAL extern
#else
#define NONCE_GLOBAL
#endif


void nonce_init(void);
void nonce_get(unsigned int *pNonce);
unsigned int nonce_test(void);

#endif /* NONCE_H_ */