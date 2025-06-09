# SHA3

This is an implementation of the SHA3 ([FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)) family of hash functions and XOF that includes:
- SHA3-256;
- SHA3-512;
- SHAKE128;
- SHAKE256.

There is no warranty for its usage, and you should not rely it on production.

## Usage

Compilation:
```
gcc -O3 -Wall -Wformat -c sha3 -o sha3.o
```

Add the file `sha3.h` in your project that contains documentation for each function of the API.

Each mechanism can be used with a single call:
```c
void sha3_256(uint8_t output[SHA3_256_LEN], const uint8_t *input, const size_t len);
void sha3_512(uint8_t output[SHA3_512_LEN], const uint8_t *input, const size_t len);
void shake128(uint8_t *output, const size_t output_len, const uint8_t *input, const size_t input_len);
void shake256(uint8_t *output, const size_t output_len, const uint8_t *input, const size_t input_len);
```

Alternatively, the following function can be used for multiple calls to abosrb input data in several parts.
Example for SHA3-256:
```c
/* SHA3-256 initialization */
void sha3_256_init(sha3_state_t *state);

/* SHA3-256 update (can be called multiple times) */
void sha3_256_update(sha3_state_t *state, const uint8_t *input, const size_t len);

/* SHA3-256 digest */
void sha3_256_digest(sha3_state_t *state, uint8_t output[SHA3_256_LEN]);
```

For SHAKE, the absoption and squeezing phases can be called multiple times.
Exemple for SHAKE128:
```c
/* SHAKE128 initialization */
void shake128_init(shake_state_t *state);

/* SHAKE128 absorb (can be called multiple times) */
void shake128_absorb(shake_state_t *state, const uint8_t *input, const size_t len);

/* SHAKE128 finalize (terminate the absorption phase) */
void shake128_finalize(shake_state_t *state);

/* SHAKE128 squeeze (can be called multiple times) */
void shake128_squeeze(shake_state_t *state, uint8_t *output, const size_t len);
```

## Tests

The folder `sha3vectors/` contains test vectors from the
[CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)
program using byte-oriented test vectors.

To run the tests:
```
make
```

## License

This work is released under the [MIT License](./LICENSE).

> MIT License
> 
> Copyright (c) 2025 A. Russon
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
