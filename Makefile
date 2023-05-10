NAME	:=	coRSAir

SRC		:=	src/main.c src/ft_print.c
OBJS	:=	$(SRC:.c=.o)

CC := gcc
CFLAGS := -Wall -Wextra -Werror
RM := rm -f

INCLUDES := -I openssl-master/include -I include -DOPENSSL_API_COMPAT=10002

LIBCRYPTO := openssl-master/libcrypto.a

.c.o:
	@$(CC) $(CFLAGS) -c $< -o $(<:.c=.o) $(INCLUDES) 

all: $(NAME)

$(NAME): $(OBJS)
	@$(CC) $(CFLAGS) $(OBJS) $(LIBCRYPTO) -o $(NAME) $(INCLUDES) 
	@echo "coRSAir compiled"

clean:
	@$(RM) $(OBJS) $(OBJS_BONUS)
	@echo "🗑 Temporal files from coRSAir removed 🗑"

fclean: clean
	$(RM) $(NAME)
	@echo "🗑 More files from coRSAir removed 🗑"

re: fclean all

.PHONY: all fclean clean re install
