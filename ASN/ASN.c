#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "../Base64/Base64.h"
#include "ASN.h"

#define READ_ASN_INT(text) (((unsigned int)(text)[0] << 24) & 0xff000000) + (((unsigned int)(text)[1] << 16) & 0xff0000) + (((unsigned int)(text)[2] << 8) & 0xff00) + ((unsigned int)(text)[3] & 0xff); (text) += 4
#define COPY_DATA(dest, src, len) for (size_t i = 0; i < (len); (dest)[i] = (src)[i], ++i)
#define WRITE_ASN_INT(buf, num) do { \
	unsigned char int_buf[4];\
	int_buf[3] = ((num) & 0xff); \
	int_buf[2] = (((num) >> 8) & 0xff); \
	int_buf[1] = (((num) >> 16) & 0xff); \
	int_buf[0] = (((num) >> 24) & 0xff); \
	COPY_DATA((buf), int_buf, 4); \
	buf += 4; \
} while (0)
#define ALLOCATE_DATA(dest, src, len) do { \
	dest = (unsigned char*)malloc(len); \
	COPY_DATA(dest, src, len); \
	(src) += (len); \
} while (0)
#define ALLOCATE_FIELD(dest, src) do { \
	(dest).length = READ_ASN_INT(src);\
	ALLOCATE_DATA((dest).text, (src), (dest).length); \
} while (0)
#define GET_FIELD_LENGTH(field) (((field).text != NULL) ? (field).length + 4 : 0)
#define WRITE_ASN_FIELD(buf, field) do { \
	WRITE_ASN_INT((buf), (field).length); \
	COPY_DATA((buf), (field).text, (field).length); \
	buf += (field).length; \
} while (0)

void destroy_asn1field(asn1field field) {
	if (field.text != NULL)
		free(field.text);
	field.text = NULL;
	field.length = 0;
}

void destroy_asn1elem(asn1elem** elem) {
	if ((*elem)->ssh_version)
		free((*elem)->ssh_version);

	destroy_asn1field((*elem)->crypt_type);
	destroy_asn1field((*elem)->salt);
	destroy_asn1field((*elem)->key_type);
	destroy_asn1field((*elem)->key_modulus);
	destroy_asn1field((*elem)->aes_version);
	destroy_asn1field((*elem)->public_key_exp);
	destroy_asn1field((*elem)->private_key_exp);
	destroy_asn1field((*elem)->iqmp);
	destroy_asn1field((*elem)->p);
	destroy_asn1field((*elem)->q);
	destroy_asn1field((*elem)->comment);


	free(*elem);
	*elem = NULL;
}

int Extract_public_key(asn1elem** elem, const char* path) {
	int result = 0;
	
	if (*elem == NULL)
		*elem = (asn1elem*)calloc(1, sizeof(asn1elem));

	int fd = open(path, O_RDONLY);
	size_t file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	char* file_content = (char*)malloc(file_size);
	read(fd, file_content, file_size);
	close(fd);
	
	char *content_start, *content_end;

	for (content_start = file_content; *content_start != ' '; content_start++);
	for (++content_start, content_end = content_start; *content_end != ' '; ++content_end);

	*content_end = '\0';
	file_size = content_end - content_start;
	unsigned char* decoded_text = decode_text(content_start, file_size);
	free(file_content);

	char* p = decoded_text;

	ALLOCATE_FIELD((*elem)->key_type, p);

	ALLOCATE_FIELD((*elem)->public_key_exp, p);

	ALLOCATE_FIELD((*elem)->key_modulus, p);
	
	free(decoded_text);

	return 0;
}

int Create_public_key(asn1elem* elem, const char* path) {

	int res = 0;
	unsigned char* encoded_text = NULL;
	
	// 4 "sizeof(unsigned int)" * 3 "signature + exp + modulus"
	size_t size = GET_FIELD_LENGTH(elem->public_key_exp) + GET_FIELD_LENGTH(elem->key_modulus) + 11;
	unsigned char* raw_text = (unsigned char*)malloc(size);

	if (raw_text == NULL)
		return 1;

	unsigned char* p = raw_text;

	WRITE_ASN_INT(p, 0x7);

	COPY_DATA(p, "ssh-rsa", 0x7);

	p += 7;

	WRITE_ASN_FIELD(p, elem->public_key_exp);

	WRITE_ASN_FIELD(p, elem->key_modulus);

	encoded_text = encode_text(raw_text, size);

	free(raw_text);

	size_t path_len;

	for (path_len = 0; path[path_len] != '\0'; ++path_len);

	char* pub_path = (char*)malloc(path_len + 4);

	for (path_len = 0; path[path_len] != '\0'; pub_path[path_len] = path[path_len], ++path_len);

	for (size_t ind = 0; ".pub"[ind] != '\0'; pub_path[path_len] = ".pub"[ind], ++ind, ++path_len);

	int fd = open(pub_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	
	free(pub_path);

	if (fd < 0) return 1;

	if (
		(write(fd, "ssh-rsa ", 8) == -1) ||
		(write(fd, encoded_text, (size / 3 + (size % 3 > 0)) * 4) == -1) ||
		(write(fd, " vlad@riv\n", 10) == -1)
	) {
		res = 1;
		goto finish;
	}

finish:

	close(fd);

	if (encoded_text != NULL)
		free(encoded_text);

	return 0;
}

int Extract_private_key(asn1elem** elem, const char* path) {
	
	int result = 0;

	if (*elem == NULL)
		*elem = (asn1elem*)calloc(1, sizeof(asn1elem));

	asn1elem* asn_handler = *elem;

	int fd = open(path, O_RDONLY);
	size_t file_size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	char* file_content = (char*)malloc(file_size);
	read(fd, file_content, file_size);
	close(fd);
	
	char* content_start = file_content + 1;
	while (*(content_start - 1) != '\n') ++content_start;
	char* content_end = content_start;
	while (*(content_end + 1) != '-') ++content_end;
	*content_end = '\0';
	file_size = content_end - content_start;
	unsigned int offset = 0;
	for (unsigned int i = 0; i + offset < file_size; ++i) {
		if (content_start[i + offset] == '\n')
			++offset;
		content_start[i] = content_start[i + offset];
	}
	file_size -= offset;
	unsigned char* decoded_text = decode_text(content_start, file_size);
	free(file_content);

	char *p = decoded_text;

	for (offset = 0; p[offset] != '\0'; ++offset);

	p += 15;

	ALLOCATE_FIELD(asn_handler->aes_version, p);

	ALLOCATE_FIELD(asn_handler->crypt_type, p);

	offset = READ_ASN_INT(p);

	if (offset > 0) {
		ALLOCATE_FIELD(asn_handler->salt, p);
		const char* salt_ptr = asn_handler->salt.text + (asn_handler->salt.length - 4);
		asn_handler->number_of_rounds =
			((salt_ptr[0] & 0xff) << 24) |
			((salt_ptr[1] & 0xff) << 16) |
			((salt_ptr[2] & 0xff) << 8) |
			(salt_ptr[3] & 0xff);
	}

	asn_handler->number_of_keys = READ_ASN_INT(p);

	offset = READ_ASN_INT(p);

	ALLOCATE_FIELD(asn_handler->key_type, p);

	ALLOCATE_FIELD(asn_handler->public_key_exp, p);

	ALLOCATE_FIELD(asn_handler->key_modulus, p);

	offset = READ_ASN_INT(p);

	offset = READ_ASN_INT(p);

	unsigned int temp = READ_ASN_INT(p);

	if (offset != temp) {
		printf("The two check integers don't match!\n");
		result = 1;
		goto finish;
	}

	offset = READ_ASN_INT(p);

	for (size_t i = 0; i < offset; ++i) {
		if (p[i] != asn_handler->key_type.text[i]) {
			printf("Key type doesn't match\n");
			result = 1;
			goto finish;
		}
	}

	p += offset;

	offset = READ_ASN_INT(p);

	for(size_t i = 0; i < offset; ++i) {
		if (p[i] != asn_handler->key_modulus.text[i]) {
			printf("Modulus doesn't match\n");
			result = 1;
			goto finish;
		}
	}

	p += offset;

	offset = READ_ASN_INT(p);

	for (size_t i = 0; i < offset; ++i) {
		if (p[i] != asn_handler->public_key_exp.text[i]) {
			printf("Exponent doesn't match\n");
			result = 1;
			goto finish;
		}
	}

	p += offset;

	ALLOCATE_FIELD(asn_handler->private_key_exp, p);

	ALLOCATE_FIELD(asn_handler->iqmp, p);

	ALLOCATE_FIELD(asn_handler->p, p);
	
	ALLOCATE_FIELD(asn_handler->q, p);

finish:
	free(decoded_text);

	return result;
}

int Create_private_key(asn1elem* elem, const char* path) {

	int res = 0;

	unsigned int block_size;

	unsigned char* encoded_text = NULL;

	const char asn1comment[] = {0x0, 0x0, 0x0, 0x6, 't', 'u', 'i', 'a', 's', 'i'};

	if (elem->comment.text == NULL) {
		const char* p = asn1comment;
		ALLOCATE_FIELD(elem->comment, p);
	}

	size_t public_key_length = GET_FIELD_LENGTH(elem->public_key_exp) +
		GET_FIELD_LENGTH(elem->key_modulus) +
		GET_FIELD_LENGTH(elem->key_type);
	
	size_t private_key_length = 8 + // 2 * sizeof(unsigned int) for the two check-ints
		GET_FIELD_LENGTH(elem->key_type) +
		GET_FIELD_LENGTH(elem->key_modulus) +
		GET_FIELD_LENGTH(elem->public_key_exp) +
		GET_FIELD_LENGTH(elem->private_key_exp) + 
		GET_FIELD_LENGTH(elem->iqmp) + 
		GET_FIELD_LENGTH(elem->p) +
		GET_FIELD_LENGTH(elem->q) +
		GET_FIELD_LENGTH(elem->comment);

	//if (elem->aes_version.text == "none")
		block_size = 8;

	private_key_length = (private_key_length % block_size != 0) ? ((private_key_length / block_size  * block_size) + block_size) : private_key_length;

	size_t size = 15 + // AUTH_MAGIC: hardcoded value of "openssh-key-v1\0"
		GET_FIELD_LENGTH(elem->aes_version) +
		GET_FIELD_LENGTH(elem->crypt_type) +
		GET_FIELD_LENGTH(elem->salt) +
		4 + // unsigned int used for representing the number of keys
		4 + // unsigned int used for representing the length of the private key
		public_key_length +
		4 + // unsigned int used for representing the length of the public key
		private_key_length;

	unsigned char* raw_text = (unsigned char*)malloc(size);

	if (raw_text == NULL)
		return 1;

	COPY_DATA(raw_text, "openssh-key-v1", 14);
	raw_text[14] = '\0';

	unsigned char* p = raw_text + 15;

	WRITE_ASN_FIELD(p, elem->aes_version);

	WRITE_ASN_FIELD(p, elem->crypt_type);

	if (elem->salt.text != NULL) {
		WRITE_ASN_FIELD(p, elem->salt); // Number of rounds is already present in the salt text buffer
	} else {
		WRITE_ASN_INT(p, 0x0);
	}

	WRITE_ASN_INT(p, elem->number_of_keys);

	WRITE_ASN_INT(p, public_key_length);
	WRITE_ASN_FIELD(p, elem->key_type);
	WRITE_ASN_FIELD(p, elem->public_key_exp);
	WRITE_ASN_FIELD(p, elem->key_modulus);
	
	WRITE_ASN_INT(p, private_key_length);
	
	// Random number used to check wether the key used for encrypted private keys was correct
	// After decryption they should be the same
	// NOTE: This can be whatever, preferably a randomly generated number but such an equation works
	unsigned int check_int =
		(elem->private_key_exp.text[elem->private_key_exp.length / 4] & 0xff) << 24 +
		(elem->private_key_exp.text[elem->private_key_exp.length / 2] & 0xff) << 16 +
		(elem->private_key_exp.text[elem->private_key_exp.length / 4 * 3] & 0xff) << 8 +
		(elem->private_key_exp.text[elem->private_key_exp.length - 4] & 0xff);

	WRITE_ASN_INT(p, check_int);
	WRITE_ASN_INT(p, check_int);

	WRITE_ASN_FIELD(p, elem->key_type);
	WRITE_ASN_FIELD(p, elem->key_modulus);
	WRITE_ASN_FIELD(p, elem->public_key_exp);
	WRITE_ASN_FIELD(p, elem->private_key_exp);
	WRITE_ASN_FIELD(p, elem->iqmp);
	WRITE_ASN_FIELD(p, elem->p);
	WRITE_ASN_FIELD(p, elem->q);
	WRITE_ASN_FIELD(p, elem->comment);

	for(size_t padding = 0x0; p + padding < raw_text + size; ++padding)
		p[padding] = padding + 1;

	encoded_text = encode_text(raw_text, size);

	free(raw_text);

	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	
	if (fd < 0) {
		if (encoded_text != NULL)
			free(encoded_text);
		return 1;
	}

	if (write(fd, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36) == -1) {
		res = 1;
		goto finish;
	}
	
	for (size_t offset = 0, limit = ((size / 3 + (size % 3 > 0)) * 4) - 1; offset < limit; offset += ((offset + 70 < limit) ? 70 : limit - offset)) {
		if (write(fd, encoded_text + offset, ((offset + 70 < limit) ? 70 : (limit - offset - 1))) == -1 || write(fd, "\n", 1) == -1) {
			res = 1;
			goto finish;
		}
	}

	if (write(fd, "-----END OPENSSH PRIVATE KEY-----\n", 34) == -1) {
		res = 1;
		goto finish;
	}

finish:

	close(fd);

	if (encoded_text != NULL)
		free(encoded_text);

	return res;
}
