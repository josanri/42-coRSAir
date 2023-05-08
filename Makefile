all:
	gcc main.c ft_print.c openssl/libcrypto.a -I openssl/include -DOPENSSL_API_COMPAT=10002 -o coRSAir 