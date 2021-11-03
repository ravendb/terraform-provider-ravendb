#include <string.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
void init_errors(){
    ERR_load_crypto_strings();
}
int get_pem_size(void * pem) {
  char * buf;
  int len = BIO_get_mem_data(pem, & buf);
  return len;
}
void copy_pem_to(void * pem, void * dst, int size) {
  char * buf;
  int len = BIO_get_mem_data(pem, & buf);
  memcpy(dst, buf, len > size ? size : len);
}
void free_pem(void * pem) {
  BIO_free(pem);
}
char * pfx_to_pem(void * data, long size, char * pwd, void ** key, void ** crt) {
  char * rc = NULL;
  BIO * bio = NULL;
  PKCS12 * p12 = NULL;
  EVP_PKEY * pkey = NULL;
  X509 * cert = NULL;
  STACK_OF(X509) * ca = NULL;
  BIO * key_bio = NULL;
  BIO * crt_bio = NULL;
  bio = BIO_new_mem_buf(data, size);
  if (!bio) {
    rc = "Unable to allocate memory buffer";
    goto cleanup;
  }
  p12 = d2i_PKCS12_bio(bio, NULL);
  if (!p12) {
    rc = "Unable to read certificate";
    goto cleanup;
  }
  if (!PKCS12_parse(p12, pwd, & pkey, & cert, & ca)) {
    rc = "Unable to parse certificate";
    goto cleanup;
  }
  key_bio = BIO_new(BIO_s_mem());
  if (!key_bio) {
    rc = "Out of memory, cannot create mem BIO for key";
    goto cleanup;
  }
  if (!PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
    rc = "Failed to write PEM key output";
    goto cleanup;
  }
  * key = key_bio;
  crt_bio = BIO_new(BIO_s_mem());
  if (!crt_bio) {
    rc = "Out of memory, cannot create mem BIO for cert";
    goto cleanup;
  }
  if (!PEM_write_bio_X509(crt_bio, cert)) {
    rc = "Failed to write PEM crt output";
    goto cleanup;
  }
  * crt = crt_bio;
  goto success;
  cleanup:
    if (key_bio)
      BIO_free(key_bio);
  if (crt_bio)
    BIO_free(crt_bio);
  success:
    if (bio)
      BIO_free(bio);
  if (p12)
    PKCS12_free(p12);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (cert)
    X509_free(cert);
  return rc;
}