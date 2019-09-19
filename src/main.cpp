#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include <stdio.h>
#include <stdlib.h>
#include "aes.h"
#include "aes_omac.h"

#define SC_KEY_BITS           128

#define SC_INIT_STATUS_OFFSET 0x00
#define EID1_EPROM_OFFSET     0x10
#define SNVS_REGION_OFFSET    0x560

#define SC_KEY_SIZE           0x10
#define SC_INIT_STATUS_SIZE   0x10
#define CMAC_HASH_SIZE        0x10
#define SNVS_REGION_SIZE      0x400
#define EID1_SIZE             0x280


const unsigned char sc_init_status_key[SC_KEY_SIZE] = 
{
	0xA4, 0x6B, 0xA2, 0xB8, 0x3D, 0x4E, 0x7E, 0xE5, 0x59, 0xF2, 0x39, 0xE0, 0x08, 0x7A, 0x38, 0x08
};

const unsigned char sc_eprom_eid1_key[SC_KEY_SIZE] =
{
	0x88, 0x22, 0x8B, 0x0F, 0x92, 0xC4, 0xC3, 0x6A, 0xF0, 0x97, 0xF1, 0xFE, 0x94, 0x8D, 0x27, 0xCE
};

const unsigned char sc_snvs_keygen_key[SC_KEY_SIZE] = 
{
	0xA0, 0x96, 0x31, 0xB4, 0xF8, 0xAF, 0xC7, 0x77, 0x80, 0xCB, 0x6C, 0x9E, 0xEB, 0x08, 0x70, 0xFC
};

const unsigned char sc_init_status_personalized [SC_KEY_SIZE] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

unsigned char zero_iv [SC_KEY_SIZE] = 
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool is_sc_personalized(FILE *eprom)
{
	unsigned char *sc_init_status = (unsigned char *)malloc(SC_INIT_STATUS_SIZE);
	fseek(eprom, SC_INIT_STATUS_OFFSET, SEEK_SET);
	fread(sc_init_status, SC_INIT_STATUS_SIZE, 1, eprom);
	
	aes_context aes_ctx;
	aes_setkey_dec(&aes_ctx, sc_init_status_key, SC_KEY_BITS);
	aes_crypt_ecb(&aes_ctx, AES_DECRYPT, sc_init_status, sc_init_status);
	
	if (memcmp(sc_init_status, sc_init_status_personalized, SC_INIT_STATUS_SIZE) != 0)
		return false;

	return true;
}

bool verify_eid1(FILE *eprom, unsigned char *eid1)
{
	unsigned char *eid1_hash = (unsigned char *)malloc(CMAC_HASH_SIZE);
	unsigned char *eid1_real_hash = (unsigned char *)malloc(CMAC_HASH_SIZE);
	fseek(eprom, EID1_EPROM_OFFSET, SEEK_SET);
	fread(eid1, EID1_SIZE, 1, eprom);
	fread(eid1_hash, CMAC_HASH_SIZE, 1, eprom);
	aes_omac1(eid1_real_hash, eid1, EID1_SIZE, (unsigned char *)sc_eprom_eid1_key, SC_KEY_BITS);
	
	if (memcmp(eid1_real_hash, eid1_hash, CMAC_HASH_SIZE) != 0)
		return false;
	
	aes_context aes_ctx;
	aes_setkey_dec(&aes_ctx, sc_eprom_eid1_key, SC_KEY_BITS);
	aes_crypt_cbc(&aes_ctx, AES_DECRYPT, EID1_SIZE, zero_iv, eid1, eid1);
	return true;
}

void decrypt_snvs_region(FILE *eprom, unsigned char *eid1, unsigned int region_id, unsigned char *snvs_region)
{
	unsigned char *eid1_snvs_keyseed = (unsigned char *)malloc(SC_KEY_SIZE);
	memcpy(eid1_snvs_keyseed, eid1+0x150, SC_KEY_SIZE);
	
	unsigned int i;
	aes_context aes_ctx;
	aes_setkey_enc(&aes_ctx, sc_snvs_keygen_key, SC_KEY_BITS);
	for (i = 0; i < region_id + 1; i++)
	{
		aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, eid1_snvs_keyseed, eid1_snvs_keyseed);
	}

	fseek(eprom, (SNVS_REGION_OFFSET+(region_id * SNVS_REGION_SIZE)), SEEK_SET);
	fread(snvs_region, SNVS_REGION_SIZE, 1, eprom);
	aes_setkey_dec(&aes_ctx, eid1_snvs_keyseed, SC_KEY_BITS);
	for (i = 0; i < SNVS_REGION_SIZE / 0x10; i++)
	{
		aes_crypt_ecb(&aes_ctx, AES_DECRYPT, (snvs_region+ (i*0x10)), (snvs_region+ (i*0x10)));
		snvs_region[i*0x10] ^= i;
	}
}


int main(int argc, char **argv)
{
	if ((argc != 3))
	{
		printf("Usage: snvs_decrypt.exe <file_eprom> <file_out>\n");
		return 0;
	}

	FILE *eprom = NULL;

	eprom = fopen(argv[1], "rb");
	if(eprom == NULL)
	{
		printf("Error! Could not load eprom file.\n");
		return 0;
	}
	printf("Eprom file loaded.\n");
	
	fseek(eprom, 0, SEEK_END);
	unsigned int eprom_size = ftell(eprom);
	fseek(eprom, 0, SEEK_SET);
//	printf("Eprom file size: 0x%08x bytes\n", eprom_size);
	
	if(eprom_size != 0x8000)
	{
		printf("Error! Incorrect eprom file size.\n");
		fclose(eprom);
		return 0;
	}
	if(is_sc_personalized(eprom) == false)
	{
		printf("Error! Syscon is not personalized.\n");
		fclose(eprom);
		return 0;
	}
	printf("Syscon is personalized.\n");
	
	unsigned char *eid1 = (unsigned char *)malloc(EID1_SIZE);
	memset(eid1, 0, EID1_SIZE);
	if(verify_eid1(eprom, eid1) == false)
	{
		printf("Error! verify_eid1() failed.\n");
		fclose(eprom);
		return 0;
	}
	printf("EID1 verified.\n");

	FILE *region = NULL;

	region = fopen(argv[2], "wb");
	if(region == NULL)
	{
		printf("Error! Could not create region file.\n");
		fclose(eprom);
		return 0;
	}

	unsigned int region_id;
	unsigned char *snvs_region = (unsigned char *)malloc(SNVS_REGION_SIZE);
	memset(snvs_region, 0, SNVS_REGION_SIZE);
	
	for (region_id = 0; region_id < 8; region_id++)
	{
		decrypt_snvs_region(eprom, eid1, region_id, snvs_region);
		fwrite(snvs_region, SNVS_REGION_SIZE, 1, region);
	}
	printf("SNVS region written to file %s.\n", argv[2]);

	free(snvs_region);
	free(eid1);
	fclose(region);
	fclose(eprom);
	return 0;
}