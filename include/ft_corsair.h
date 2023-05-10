#ifndef FT_CORSAIR_H
#define FT_CORSAIR_H
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

typedef struct corsair
{
    char *name;
    char *filename;
    EVP_PKEY *key;
} corsair_t;


void ft_print_warning_nl(char *s);
void ft_print_warning(char *s);
void ft_print_rsa(RSA *rsa);
int ft_usage_warning();
void ft_print_bignumber(BIGNUM * result);

#endif