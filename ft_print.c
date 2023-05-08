#include "ft_corsair.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/err.h>



void ft_print_warning_nl(char *s){
    printf("\033[0;31m%s\033[0m", s);
}

void ft_print_warning(char *s){
    printf("\033[0;31m%s\n\033[0m", s);
}

void ft_print_rsa(RSA *rsa) {
    BIO *bio_out;
    bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    RSA_print(bio_out, rsa, 0);
    BIO_free(bio_out);
}

int ft_usage_warning() {
    ft_print_warning_nl("usage: ./coRSAir -k key1 key2 -f files_by_key1 file_by_key2");
    ft_print_warning_nl("\t-k files: will try to find vulnerable ciphers.");
    ft_print_warning_nl("\t-f key_file encrypted_file: given the corresponding key, if vulnerable, decrypts the encrypted file.");
    return (1);
}
void ft_print_bignumber(BIGNUM * result) {
    char *number_s = BN_bn2dec(result);
    printf("%s\n", number_s);
    OPENSSL_free(number_s);
}