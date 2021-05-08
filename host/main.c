/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char keytext[64] = {0, };
	int len=64;
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	if(strcmp(argv[1], "-e") == 0) { //encrypt
		printf("========================Encryption========================\n");
		FILE *fp1;
		fp1 = fopen(argv[2], "r");
		fread(plaintext, sizeof(plaintext), 1, fp1); //file read
		fclose(fp1);
		printf("Plaintext : %s\n", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		int encrypted_key = op.params[1].value.a;
		printf("encrypted key : %d\n", op.params[1].value.a); //print key
		FILE *fp2;
		fp2 = fopen("/root/encryptedkey.txt", "w");
		sprintf(keytext, "%d", encrypted_key); //int -> string
		fwrite(keytext, strlen(keytext), 1, fp2); //write key
		fclose(fp2);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		FILE *fp3;
		fp3 = fopen("/root/cipher.txt", "w"); 
		fwrite(ciphertext, strlen(ciphertext), 1, fp3); //write
		fclose(fp3);
		printf("Ciphertext : %s\n", ciphertext);
	}
	else if(strcmp(argv[1], "-d") == 0) { //decrypt
		printf("========================Decryption========================\n");
		FILE *fp1;
		fp1 = fopen(argv[2], "r");
		fread(ciphertext, sizeof(ciphertext), 1, fp1); //file read
		fclose(fp1);
		printf("Ciphertext : %s\n", ciphertext);
		FILE *fp2;
		fp2 = fopen(argv[3], "r");	
		fread(keytext, sizeof(keytext), 1, fp2); //file read
		fclose(fp2);
		op.params[1].value.a = atoi(keytext); //atoi : string -> int
		printf("encrypted key : %d\n", op.params[1].value.a); //print key
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		FILE *fp3;
		fp3 = fopen("/root/decryptedresult.txt", "w"); 
		fwrite(plaintext, strlen(plaintext), 1, fp3); //write
		fclose(fp3);
		printf("Plaintext : %s\n", plaintext);
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
