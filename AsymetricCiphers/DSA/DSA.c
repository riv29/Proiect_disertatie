#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "DSA.h"
#include "../SHA/SHA.h"

int
init_dsa_ctx(dsa_ctx** ctx) {
	
	if (*ctx == NULL) {
		if ((*ctx = (dsa_ctx*)calloc(1, sizeof(dsa_ctx))) == NULL)
			return 1;
	}
	
	dsa_ctx* ctx_handler = *ctx;

	init_keypair_ctx(&(ctx_handler->keys));

	ALLOC_MPZ_PTR(ctx_handler->g);
	ALLOC_MPZ_PTR(ctx_handler->k);

	return 0;
}

int
free_dsa_ctx(dsa_ctx** ctx) {
	
	dsa_ctx* ctx_handler = *ctx;	

	FREE_MPZ_PTR(ctx_handler->g);
	FREE_MPZ_PTR(ctx_handler->k);

	free_keypair_ctx(&(ctx_handler->keys));

	if (*ctx != NULL) {
		free(*ctx);
		*ctx = NULL;
	}

	return 0;
}
