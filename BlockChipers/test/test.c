#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../Block_API.h"

int encrypt_function(int argc, const char** argv) {
	if (argc < 3) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	char* key = (char*)argv[2];
	char* source_file = (char*)argv[3];

	FILE* fp = fopen(source_file, "r");
	fseek(fp, 0, SEEK_END);
	size_t file_size = ftell(fp);
	rewind(fp);
	bytes_t file_content = (bytes_t)malloc(file_size);
	fread(file_content, 1, file_size, fp);
	fclose(fp);

	int res = encrypt_to_file((bytes_t)"encrypted.txt", file_content, key, file_size);

	free(file_content);

	return res;
}

int decrypt_function(int argc, const char** argv) {
	if (argc < 3) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	char* key = (char*)argv[2];
	char* source_file = (char*)argv[3];

	bytes_t plain_text = NULL;

	off_t file_size = decrypt_from_file(source_file, &plain_text, key);

	FILE* fp = fopen("decrypted.txt", "w");
	fwrite(plain_text, 1, file_size, fp);
	fclose(fp);

	return 0;
}

int encrypt_AES128CTR(int argc, const char** argv) {

	if (argc < 4) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	// Configure session
	InitContext(RC6_192);
	SetMode(CTR, (char*)argv[4]);
	SetPadding(PKCS_5_7);	

	return encrypt_function(argc, argv);
}

int decrypt_AES128CTR(int argc, const char** argv) {

	if (argc < 4) {
		printf("Not enough arguments!!!\n");
		return 1;
	}

	// Configure session
	InitContext(RC6_192);
	SetMode(CTR, (char*)argv[4]);
	SetPadding(PKCS_5_7);	

	return decrypt_function(argc, argv);
}

int main(int argc, const char** argv) {
	if (!strcmp(argv[1], "enc"))
		return encrypt_AES128CTR(argc, argv);
	else if (!strcmp(argv[1], "dec"))
		return decrypt_AES128CTR(argc, argv);
}
