#include "ft_corsair.h"
#include <math.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define DEBUG_CORSAIR 0

void ft_save_private_key(RSA *priv_key, char *name) {
    unsigned char buffer_ciphered[1024];
    unsigned char buffer_plain[1024];
    int char_read = 0;
    int fd = open(name, O_RDONLY);

    #if DEBUG_CORSAIR == 1
        printf("\033[0;32mPrivate key for %s\n\033[0m", name);
        ft_print_rsa(priv_key);
    #endif
    if (fd <= 0) {
        printf("Error - Could not open the file %s\n", name);
        return;
    }
    printf("The plain text for %s is:%s\n", name, buffer_plain);
    do {
        char_read = read(fd, buffer_ciphered, 1024);
        if (char_read == 0 )
            break;
        if (char_read < 0 ) {
            printf("Error - Could not read from %s", name);
        } else if (char_read > 0 && RSA_private_decrypt(char_read, buffer_ciphered, buffer_plain, priv_key, RSA_PKCS1_PADDING) > 0) {
            printf("%s", buffer_plain);
        } else {
            printf("Error - Could not decipher %s", name);
        }
    } while (char_read > 0);
    printf("\n");
    close(fd);
}

// My version of modular inverse
int ft_bezout(BIGNUM *integer, BIGNUM *modulus, BIGNUM **result){
    const BIGNUM *one = BN_value_one();
    BIGNUM *aux = NULL;
    BIGNUM *aux_modular = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    if (BN_is_one(integer)) {
        *result = BN_dup(one);
    } else {
        // Get res = ft_bezout(modulus % integer, integer)
        BN_div(NULL, aux_modular, modulus, integer, ctx);
        ft_bezout(aux_modular, integer, &aux);
        // Get res = integer - res
        BN_sub(aux, integer, aux);
        // Get res = res * modulus
        BN_mul(aux, aux, modulus, ctx);
        // Get res = res + 1
        BN_add(aux, aux, one);
        // Get res = res  / integer
        *result = BN_new();
        BN_div(*result, NULL, aux, integer, ctx);
    }
    BN_free(aux);
    BN_free(aux_modular);
    BN_CTX_free(ctx);
    return (0);
}

// My version of gcd
int ft_euclides(BIGNUM *a, BIGNUM *b, BIGNUM **res){
    BN_CTX *ctx;
    BIGNUM *remanent = NULL;
    int err;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        return (-1);
    remanent = BN_new();
    if (remanent == NULL){
        printf("Allocating memory for remanent error\n");
        return (-1);
    }
    err = BN_div(NULL, remanent, a, b, ctx);
    if (err == 0) { 
        printf("Division error\n");
        BN_free(remanent);
        return (-1);
    }
    BN_CTX_free(ctx);
    if (BN_is_zero(remanent)) {
        BN_free(remanent);
        *res = BN_dup(b);
        return (0);
    } else {
        err = ft_euclides(b, remanent, res);
        BN_free(remanent);
        return (err);
    }
}

RSA *ft_create_new_private_key(BIGNUM *number_from_key, BIGNUM *common_prime, BIGNUM *exponent, BN_CTX *ctx)
{
    BIGNUM *the_other_prime = BN_new();
    BIGNUM * common_prime_minus_1 = NULL;
    BIGNUM * the_other_prime_minus_1 = NULL;
    BN_div(the_other_prime, NULL, number_from_key, common_prime, ctx);  

    common_prime_minus_1 = BN_new();
    the_other_prime_minus_1 = BN_new();
    BN_sub(common_prime_minus_1, common_prime, BN_value_one());
    BN_sub(the_other_prime_minus_1, the_other_prime, BN_value_one());
    BIGNUM *theta = BN_new();
    BN_mul(theta, common_prime_minus_1, the_other_prime_minus_1, ctx);
    BIGNUM *new_prime = BN_new();
    BN_mod_inverse(new_prime, exponent, theta, ctx);
    // ft_bezout(exponent, theta, &new_prime); Does not need to generate memory before for new_prime

    RSA *rsa = RSA_new();
    RSA_set0_key(rsa, BN_dup(number_from_key), BN_dup(exponent), BN_dup(new_prime));

    BN_free(theta);
    BN_free(new_prime);
    BN_free(common_prime_minus_1);
    BN_free(the_other_prime_minus_1);
    BN_free(the_other_prime);
    return (rsa);
}

void ft_read_keys(corsair_t *keys, int len, char **key_files, char **decipher_files){
    for (int i = 0; i < len; i++)
    {
        printf("\033[0;36m%d - %s\n\033[0m", i, key_files[i]);
        keys[i].name = key_files[i];
        keys[i].filename = decipher_files[i];
        BIO *bufio = BIO_new_file(key_files[i], "r");
        if (bufio != NULL) {
            keys[i].key = PEM_read_bio_PUBKEY(bufio, &keys[i].key, NULL, NULL);
            BIO_free(bufio);
        } else {
            printf("\033[0;31m\tCould not be read %s\n\033[0m", key_files[i]);
        }
    }
}

void ft_get_vulnerable(corsair_t *keys, int len){
    BIGNUM * a = NULL;
    BIGNUM * b = NULL;
    BIGNUM * common_prime = NULL;
    BN_CTX *ctx = BN_CTX_new();

    for (int i = 0; i < len; i++)
    {   
        if (keys[i].key == NULL) continue;
        for (int j = i + 1; j < len; j++)
        {
            if (keys[j].key == NULL) continue;
            a = BN_new();
            b = BN_new();
            common_prime = BN_new();
            EVP_PKEY_get_bn_param(keys[i].key, "n", &a);
            EVP_PKEY_get_bn_param(keys[j].key, "n", &b);
            BN_gcd(common_prime, a, b, ctx);
            // ft_euclides(a, b, &common_prime); Does not need to generate memory before for common_prime
            if (BN_is_one(common_prime)) {
                printf("\033[0;32m%d and %d are coprimes\n\033[0m", i, j);
            } else {
                printf("\033[0;31m%d and %d are not coprimes\n\033[0m", i, j);
                BIGNUM *exponent = NULL;
                RSA *priv_key = NULL;

                EVP_PKEY_get_bn_param(keys[i].key, "e", &exponent);
                priv_key = ft_create_new_private_key(a, common_prime, exponent, ctx);
                ft_save_private_key(priv_key, keys[i].filename);
                RSA_free(priv_key);
                BN_free(exponent);

                exponent = NULL;
                priv_key = NULL;
                EVP_PKEY_get_bn_param(keys[j].key, "e", &exponent);
                priv_key = ft_create_new_private_key(b, common_prime, exponent, ctx);
                ft_save_private_key(priv_key, keys[j].filename);
                RSA_free(priv_key);
                BN_free(exponent);

            }
            BN_free(a);
            BN_free(b);
            BN_free(common_prime);
        }
    }
    BN_CTX_free(ctx);
}

corsair_t * ft_initialize_keys(int len){
    corsair_t *keys = (corsair_t *) malloc(len * sizeof(corsair_t));
    for (int i = 0; i < len; i++) {
        keys[i].name = NULL;
        keys[i].key = NULL;
    }
    return keys;
}

void ft_free_keys(corsair_t *keys, int len) {
    for (int i = 0; i < len; i++)
        EVP_PKEY_free(keys[i].key);
    free(keys);
}

int main(int argc, char **argv) {
    ERR_load_crypto_strings();
    int len = 2;
    char **key_files = &argv[2];
    char **ciphered_files = &argv[5];
    corsair_t *keys = NULL;

    if (argc != 7)
        return ft_usage_warning();
    if (strcmp("-k", argv[1]) == 0 && (strcmp("-f", argv[4]) == 0)) {
        keys = ft_initialize_keys(len);
        ft_read_keys(keys, len, key_files, ciphered_files);
        ft_get_vulnerable(keys, len);
        ft_free_keys(keys, len);
    } else {
        return ft_usage_warning();
    }
}