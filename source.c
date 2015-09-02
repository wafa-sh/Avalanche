
//
//  main.c
//  A3
//
//  Created by Avalanche Team on 8/6/15.
//  Copyright (c) 2015 Avalanche team. All rights reserved.
//

#include <stdio.h>
#include <string.h>              // memcpy
#include <stdlib.h>              // callc, allov, srand, rand
#include <time.h>
#include <openssl/aes.h>
#include <openssl/bn.h>          // Big Number for RMAC

#include "Avalanche_128.h"
//#include <openssl/rand.h>        // Prime random number


void PCMAC(unsigned char       *c, unsigned long long  clen,
	const unsigned char *m, unsigned long long  mlen, unsigned char *key,
	unsigned char *PCMAC_tau, unsigned char *nonce)
{



}



void RMAC(const unsigned char *ad, unsigned long long  adlen,
	unsigned char *RMAC_key, unsigned char *prime, unsigned char *RMAC_tau)
{
	BIGNUM  *bn_ad, *bn_RMAC_Prime, *bn_RMAC_Key;      // BIG NUM  Variables


	*RMAC_key |= (char)128;                                                // set the high order bit to 1 (RMAC key > Prime/2)

	bn_RMAC_Key = BN_bin2bn(RMAC_key, BLOCK_SIZE, NULL);                    // convert RMAC key to BN number

	bn_ad = BN_bin2bn(ad, adlen, NULL);

	BN_set_bit(bn_ad, adlen * 8);                                   // append 1 to the most significant bit of ad

	bn_RMAC_Prime = BN_bin2bn(prime, BLOCK_SIZE, NULL);                       // convert prime to big num
	BN_CTX *ctx = BN_CTX_new();
	BN_mod(bn_ad, bn_ad, bn_RMAC_Prime, ctx);                               // bn_ad = bn_ad mod bn_RMAC_Prime
	BN_mul(bn_ad, bn_ad, bn_RMAC_Key, ctx);                                 // bn_ad = bn_ad * bn_RMAC_Key
	BN_mod(bn_ad, bn_ad, bn_RMAC_Prime, ctx);                               // bn_ad = bn_ad mod bn_RMAC_Prime
	BN_bn2bin(bn_ad, RMAC_tau);                                             // prepare the  RMAC tau into unsigned chars form


	BN_clear_free(bn_ad);                                               // Free BN ad Variable
	BN_clear_free(bn_RMAC_Prime);                                           // Free BN RMAC prime Variable
	BN_clear_free(bn_RMAC_Key);                                             // Free BN RMAC key Variable


}

void crypto_aead_encrypt(unsigned char       *c, unsigned long long clen,
	const unsigned char *m, unsigned long long  mlen,
	const unsigned char *ad, unsigned long long  adlen,
	  unsigned char *nonce,
	  unsigned char *key, unsigned char *prime)
{

	unsigned char *RMAC_key = (unsigned char *)calloc(RMAC_KEY_SIZE, sizeof(unsigned char));

	unsigned char *PCMAC_tau = (unsigned char *)calloc(BLOCK_SIZE, sizeof(unsigned char));
	unsigned char *RMAC_tau = (unsigned char *)calloc(BLOCK_SIZE, sizeof(unsigned char));
	int i,j;


	memcpy(RMAC_key, key + BLOCK_SIZE, BLOCK_SIZE);
	AES_KEY aes_key;

		unsigned char *m_ptr, *c_ptr;  //
		unsigned long long  L; //
		unsigned long long  NB;  //
		unsigned long long Counter = 0;



		unsigned char *padd = (unsigned char *)calloc(BLOCK_SIZE, sizeof(unsigned char));
		unsigned char *PCMAC_key = (unsigned char *)calloc(RMAC_KEY_SIZE, sizeof(unsigned char));



		L = mlen % BLOCK_SIZE;
		NB = mlen / BLOCK_SIZE;
		// ---------------------------//


		// ; Xoring key with Nonce

		for (i = NONCE_SIZE - 1; i >= 0; i--)
		{
			PCMAC_key[i + CTR_SIZE] = key[i + CTR_SIZE] ^ nonce[i];

		}

		memcpy(PCMAC_key, &key, CTR_SIZE);       // copying key value to the first 6 - unsigned char for random


		// ---------------------------//

		// AES for Random block

		srand(time(0));


		for (i = BLOCK_SIZE - 1; i >= 0; i--)
		{

			PCMAC_tau[i] = rand();    //no need for r
			//printf("Random number: %x", PCMAC_tau[i]);
		}



		AES_set_encrypt_key((const unsigned char *)PCMAC_key, 128, &aes_key);  //header file
		AES_encrypt((const unsigned char *)PCMAC_tau, c, (const AES_KEY *)&aes_key);

		// ---------------------------//



		// Padding

		memcpy(padd, m + mlen - L, L);
		padd[L] = 0x03;


		// ---------------------------//

		// AES encryption for m
		m_ptr = (unsigned char *)m;
		c_ptr = (unsigned  char *)c + BLOCK_SIZE;



		for (i = NB - 1; i >= 0; i--, m_ptr += BLOCK_SIZE, c_ptr += BLOCK_SIZE, ++Counter) {


			memcpy(PCMAC_key, &Counter, CTR_SIZE);

			for (j = CTR_SIZE - 1; j >= 0; j--)
			    PCMAC_key[j] = PCMAC_key[j] ^ key[j];





			for (j = BLOCK_SIZE - 1; j >= 0; j--)
			     PCMAC_tau[j] ^= m_ptr[j]; // or:     PCMAC_tau[j] ^= m[i*BLOCK_SIZE + j];






			AES_set_encrypt_key((const unsigned char *)PCMAC_key, 128, &aes_key);
			AES_encrypt((const unsigned char *)m_ptr, c_ptr, (const AES_KEY *)&aes_key);   //   (const AES_KEY *) ??



		}

		// ---------------------------//

		// AES encryption for extra block


		Counter++;
		memcpy(PCMAC_key, &Counter, CTR_SIZE);

		for (j = CTR_SIZE - 1; j >= 0; j--)
			PCMAC_key[j] ^= key[j];


		for (j = BLOCK_SIZE - 1; j >= 0; j--)
			PCMAC_tau[j] ^= padd[j]; // or:     PCMAC_tau[j] ^= padd[i*BLOCK_SIZE + j];


		AES_set_encrypt_key((const unsigned char *)PCMAC_key, 128, &aes_key);
		AES_encrypt((const unsigned char *)padd, c_ptr, (const AES_KEY *)&aes_key);




		//free(key);
		//free(padd);
		//free(PCMAC_key);

		//free(padd);
		//free(nonce);



//	PCMAC(c, clen, m, mlen, key, PCMAC_tau, nonce);
	RMAC(ad, adlen,RMAC_key,prime, RMAC_tau);


	// Generate tau
	for (i = BLOCK_SIZE - 1; i >= 0; i--)
		PCMAC_tau[i] ^= RMAC_tau[i];




	memcpy(c + clen - BLOCK_SIZE, PCMAC_tau, BLOCK_SIZE);     //explain why



}

int crypto_aead_decrypt(unsigned char       *m, unsigned long long mlen,
	const unsigned char *c, unsigned long long  clen,
	const unsigned char *ad, unsigned long long  adlen,
	  unsigned char *nonce,
	  unsigned char *key, unsigned char *prime)
{
	unsigned char *RMAC_key = (unsigned char *)calloc(RMAC_KEY_SIZE, sizeof(unsigned char));
	unsigned char *PCMAC_key = (unsigned char *)calloc(RMAC_KEY_SIZE, sizeof(unsigned char));


		unsigned char *PCMAC_tau = (unsigned char *)calloc(BLOCK_SIZE, sizeof(unsigned char));
		unsigned char *RMAC_tau = (unsigned char *)calloc(BLOCK_SIZE, sizeof(unsigned char));
		int i,j;


		memcpy(RMAC_key, key + BLOCK_SIZE, BLOCK_SIZE);
		AES_KEY aes_key;

			unsigned char *m_ptr, *c_ptr, *padd;  //
			unsigned long long  L; //
			unsigned long long  NB;  //
			unsigned long long Counter = 0;

			// ******* PCMAC: Block 0 (random number)
					   for (i = 0; i < NONCE_SIZE; i++)                                  // XORing high part of PCMAC Key with Nonce (N)
			      PCMAC_key[ i + CTR_SIZE ] = key[ i + CTR_SIZE ] ^ nonce[ i ];

			   PCMAC_tau = (unsigned char *) malloc(BLOCK_SIZE * sizeof (unsigned char));                // PCMAC Message Authintaction Tag (PCMAC_tau) allocation

			   AES_set_decrypt_key( (const unsigned char *) PCMAC_key, 128, &aes_key); // AES Decryption for Random Vector (r = PCMAC_tau)
			   AES_decrypt( (const unsigned char *) c, PCMAC_tau, (const AES_KEY *) &aes_key);



			// ******* PCMAC: Block number 1 .. Number of full blocks
			   m_ptr = (unsigned char *) m;                                                      // pointer to the plain text
			   c_ptr = (unsigned char *) c + BLOCK_SIZE;                                         // pointer to the cihper text


				for (i = NB - 1; i >= 0; i--, m_ptr += BLOCK_SIZE, c_ptr += BLOCK_SIZE, ++Counter)
				{

					memcpy(PCMAC_key, &Counter, CTR_SIZE);			// copy the counter value to PCMAC_key

					for (j = CTR_SIZE - 1; j >= 0; j--)				// XORing low half of the key with the counter
					    PCMAC_key[j] = PCMAC_key[j] ^ key[j];

					for (j = BLOCK_SIZE - 1; j >= 0; j--)
					     PCMAC_tau[j] ^= m_ptr[j]; 					 // PCMAC Tag = XOR M[1] XOR ...  M[counter]

					AES_set_decrypt_key((const unsigned char *)PCMAC_key, 128, &aes_key);		// AES Decryption for one block of m of number counter
					AES_decrypt((const unsigned char *)c_ptr, m_ptr, (const AES_KEY *)&aes_key);

				}

			// ******* PCMAC: Block number LAST

			   memcpy(PCMAC_key, &Counter, CTR_SIZE);                              // copy the counter value to PCMAC_key
			   for (i = 0; i < CTR_SIZE; i++)                                      // XORing low half of the key with the counter
			      PCMAC_key[i] ^= key[i];

			   padd    = (unsigned char *) malloc(BLOCK_SIZE * sizeof(unsigned char));                 // padding computation
			   AES_set_decrypt_key((const unsigned char *) PCMAC_key, 128, &aes_key);  // AES Decryption for the m_padd last block
			   AES_decrypt((const unsigned char *) c_ptr, padd, (const AES_KEY *)&aes_key);

			   for (i = BLOCK_SIZE-1; i >=0 && padd[i] != 0x03; i--); // Display error message if padding is corrupted
			   if (i == 0 && padd[i] != 0x03) {
			      fprintf(stderr, "Decryption error: cipher text EOT is mising! Exiting ...\n");
			      return -1;
			   }
			   memcpy(m_ptr, padd, i);  //start

			   free(PCMAC_key);                                                        // free PCMAC Key

			   RMAC(ad, adlen,RMAC_key,prime, RMAC_tau);

			   // *******  Tau = PCMAC Tau XOR RMAC Tau
			      c_ptr += BLOCK_SIZE;                                                     // pointer to the final place of Tau in the cipher text
			      for(i = 0; i < BLOCK_SIZE && (c_ptr[i] == (padd[i] ^ PCMAC_tau[i] ^ RMAC_tau[i])); i++);

			      if (i < BLOCK_SIZE) {
			         fprintf(stderr, "Decryption error: Bad Tag ...\n");
			         return -1;
			      }

			   //compare m with m'


			   return 0;



}


int main(void) {

	unsigned char *nonce = (unsigned char *)calloc(NONCE_SIZE, sizeof(unsigned char));

	unsigned char *key = (unsigned char *)calloc(32, sizeof(unsigned char));





	unsigned char *prime = (unsigned char *)malloc(BLOCK_SIZE);

	unsigned char ad[] = { '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1' };

	unsigned char m[] = { '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '5', '7' };
	unsigned long long int mlen = sizeof(m);
	unsigned long long int clen = mlen + (3 * BLOCK_SIZE);
	unsigned char *c = (unsigned char *)calloc(clen, sizeof(unsigned char));   //

	unsigned long long int  adlen = sizeof(ad);
	printf("error 1");

	crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nonce, key, prime);
	int result = crypto_aead_decrypt(m, mlen, c, clen, ad, adlen, nonce, key, prime);
	if(result != 0)
		printf("fail");
	else
		printf("Success");

printf("error ");
}
