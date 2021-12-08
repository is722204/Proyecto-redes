#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sodium.h>
#include <string>
#include <iostream>
#include <sstream> 
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 4096
using namespace std;

static int encrypt(const char *target_file, const char *source_file,
	const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	unsigned char  buf_in[CHUNK_SIZE];
	unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE          *fp_t, *fp_s;
	unsigned long long out_len;
	size_t         rlen;
	int            eof;
	unsigned char  tag;

	fp_s = fopen(source_file, "rb");
	fp_t = fopen(target_file, "wb");
	crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
	fwrite(header, 1, sizeof header, fp_t);
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
			NULL, 0, tag);
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);
	fclose(fp_t);
	fclose(fp_s);
	return 0;
}

static int decrypt(const char *target_file, const char *source_file,
	const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char  buf_out[CHUNK_SIZE];
	unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	FILE          *fp_t, *fp_s;
	unsigned long long out_len;
	size_t         rlen;
	int            eof;
	int            ret = -1;
	unsigned char  tag;

	fp_s = fopen(source_file, "rb");
	fp_t = fopen(target_file, "wb");
	fread(header, 1, sizeof header, fp_s);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
		goto ret; /* incomplete header */
	}
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
		eof = feof(fp_s);
		if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
			buf_in, rlen, NULL, 0) != 0) {
			goto ret; /* corrupted chunk */
		}
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
			goto ret; /* premature end (end of file reached before the end of the stream) */
		}
		fwrite(buf_out, 1, (size_t)out_len, fp_t);
	} while (!eof);

	ret = 0;
ret:
	fclose(fp_t);
	fclose(fp_s);
	return ret;
}


static int sign(const char* target_file, unsigned char* pk, unsigned char* sk, unsigned char* sig) {

	crypto_sign_keypair(pk, sk);

	unsigned char msg[CHUNK_SIZE];

	FILE *file;

	file = fopen(target_file, "rb");
	fread(msg, 1, sizeof msg, file);

	int ret = 0;
	
	crypto_sign_detached(sig, NULL, msg, sizeof msg, sk);

	if (crypto_sign_verify_detached(sig, msg, sizeof msg, pk) != 0) {
		std::cout << "Error en la firma";
		ret = -1; 
	}

	fclose(file);
	return ret;
}


static int verify_sign(const char* target_file, unsigned char* pk, unsigned char* sig) {
	unsigned char msg[CHUNK_SIZE];
	int ret = 0;

	FILE* file;

	file = fopen(target_file, "rb");
	fread(msg, 1, sizeof msg, file);

	if (crypto_sign_verify_detached(sig, msg, sizeof msg, pk) != 0) {
		//Incorrect signature!
		std::cout << "No esta firmado o archivo incorrecto" << std::endl;
		ret = 1;
	}
	else
	{
		std::cout << "El archivo si esta firmado" << std::endl;

	}
	fclose(file);

	return ret;
}


int main(void)
{
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	unsigned char sig[crypto_sign_BYTES];
	int op=0;



	while (op != 5){
		std::cout << "Inserta una opcion" << std::endl;
		std::cout << "1. Encriptar archivo" << std::endl;
		std::cout << "2. Desencriptar archivo" << std::endl;
		std::cout << "3. Firmar archivo" << std::endl;
		std::cout << "4. Comprobar la firma del archivo" << std::endl;
		std::cout << "5. salir" << std::endl;
		std::cin >> op;
		if (op == 1) {
			char  path1Case1[CHUNK_SIZE], path2Case1[CHUNK_SIZE];
			std::cout << "ruta para el archivo encriptado: " << std::endl;
			std::cin >> path1Case1;

			std::cout << "ruta para el archivo origen: " << std::endl;
			std::cin >> path2Case1;

			if (encrypt(path1Case1, path2Case1, key) != 0) {
				return 1;
			}
		}
		else if (op==2)
		{
			char path1Case2[CHUNK_SIZE];
			char path2Case2[CHUNK_SIZE];
			std::cout << "ruta para el archivo encriptado: " << std::endl;
			std::cin >> path1Case2;

			std::cout << "ruta para el archivo destino: " << std::endl;
			std::cin >> path2Case2;

			if (decrypt(path2Case2, path1Case2, key) != 0) {
				return 1;
			}
		}
		else if(op==3)
		{
			char path1Case3[CHUNK_SIZE];
			std::cout << "ruta para el archivo a firmar: " << std::endl;
			std::cin >> path1Case3;
			if (sign(path1Case3, &*pk, &*sk, &*sig) == 0) {
				std::cout << "Archivo firmado" << std::endl;
			}

		}
		else if (op==4) {
			char  path1Case4[CHUNK_SIZE];
			std::cout << "ruta para el archivo a firmar: " << std::endl;
			std::cin >> path1Case4;
			verify_sign(path1Case4, &*pk, &*sig);
		}
		else{
			return 1;
		}
		
	}


	return 0;
}