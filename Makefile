
all: test

test:
	gcc -O3 sha3.c test_sha3.c -o test_sha3
	./test_sha3
