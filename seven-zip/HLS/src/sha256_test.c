#include <string.h>
#include "sha256.h"

int main(int argc, char **argv)
{
	unsigned char sUPwd[14] = { 'h',NULL,'a',NULL,'s',NULL,'h',NULL,'c',NULL,'a',NULL,'t',NULL };
	unsigned char digest[32];
	sha256_encrypt(sUPwd, digest);
	printf("ciphertext = \n");
	for(int i = 0; i < 32; i++)
		printf("%x",digest[i]);
	printf("\n");
}
