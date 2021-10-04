#include <openssl/err.h>

void init_errors();
int get_pem_size(void * pem);
void copy_pem_to(void * pem, void * dst, int size);
void free_pem(void * pem) ;
char * pfx_to_pem(void * data, long size, char * pwd, void ** key, void ** crt);