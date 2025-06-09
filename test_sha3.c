/*
 * Copyright (C) 2025 A. Russon
 * 
 * Released under the MIT license.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha3.h"

#define MAX_LINE 35000
#define MAX_BUF  17500 // MAX_LINE / 2

#define SHA3_256 1
#define SHA3_512 2
#define SHAKE128 3
#define SHAKE256 4

int is_hex(char c) {
  c |= 32;
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/**
 * Convert two hexadecimal characters into a byte.
 * Inputs must be valid hexadecimal characters.
 */
uint8_t hex_to_byte(char c1, char c2) {
  uint8_t b;
  c1 |= 32;
  c2 |= 32;

  if (c1 <= '9') {
    b = (c1 - '0') << 4;
  }
  else {
    b = (c1 - 'a' + 10) << 4;
  }
  if (c2 <= '9') {
    b |= c2 - '0';
  }
  else {
    b |= c2 - 'a' + 10;
  }
  return b;
}

/**
 * Decode an hexadecimal string to a buffer array.
 * Returns 0 in case of success, or -1 if a character is not hexadecimal.
 * 
 * Arguments:
 *  - buf:       pointer to output buffer of length input_len/2 (must be allocated by caller)
 *  - s:         pointer to hexadecimal string
 *  - input_len: length of hexdecimal string
 */
int hex_decode(uint8_t *buf, const size_t len, const char *s) {
  size_t i;
  int ret = 0;

  for (i = 0; i < len; i++) {
    if (!is_hex(s[2*i]) || !is_hex(s[2*i + 1])) {
      ret = -1;
      break;
    }
    buf[i] = hex_to_byte(s[2*i], s[2*i + 1]);
  }

  return ret;
}

/**
 * Load byte array from hex string from next line that starts with a specific prefix.
 * All other lines are ignored until the correct line has been found.
 * Returns 0 in case of success, -1 if line not found or the string is not hexadecimal.
 * 
 * Arguments:
 *  - buf:    pointer to buffer array (dynamically allocated), NULL if nothing found
 *  - len:    length of the loaded buffer array
 *  - fp:     file pointer to read from
 *  - prefix: hex string must follow this prefix
 */
int load_values(uint8_t *buf, size_t *len, FILE *fp, const char *prefix) {
  char line[MAX_LINE];
  size_t prefix_len, line_len;
  int ret = -1;

  while (fgets(line, MAX_LINE, fp) != NULL) {
    line_len = strlen(line);
    if (line[line_len - 1] == '\n') {
      line[line_len - 1] = '\0';
      line_len -= 1;
    }
    if (line[line_len - 1] == '\r') {
      line[line_len - 1] = '\0';
      line_len -= 1;
    }

    prefix_len = strlen(prefix);
    if (memcmp(prefix, line, prefix_len) == 0) {
      *len = (line_len - prefix_len) / 2;
      ret = hex_decode(buf, *len, &line[prefix_len]);
      if (ret != 0) {
        fprintf(stderr, "Error: cannot decode hexadecimal string\n");
      }
      break;
    }
  }
  return ret;
}

/**
 * Read a length in a line that starts with "Len = " or "Outputlen = ".
 * The length read is in bits, and is converted into a number of bytes.
 * 
 * Arguments:
 *  - len: pointer to length read from the file
 *  - fp:  file pointer to read from
 *  - is_outputlen: pointer to a boolean value set to 1 for "Outputlen = " or 0 if "Len = "
 */
int load_len(size_t *len, FILE *fp, int *is_outputlen) {
  char line[MAX_LINE];
  int ret = -1;

  while(fgets(line, MAX_LINE, fp) != NULL) {
    // look for prefix
    if (memcmp("Len = ", line, 6) == 0) {
      *is_outputlen = 0;
      *len = strtoul(&line[6], NULL, 10);
      if (*len % 8 == 0) {
        *len /= 8;
        ret = 0;
      }
      break;
    }
    else if (memcmp("Outputlen = ", line, 12) == 0) {
      *is_outputlen = 1;
      *len = strtoul(&line[12], NULL, 10);
      if (*len % 8 == 0) {
        *len /= 8; 
        ret = 0;
      }
      break;
    }
  }

  return ret;
}

int test_sha3_256(const uint8_t *input, const size_t len, const uint8_t expected[SHA3_256_LEN]) {
  uint8_t output[SHA3_256_LEN];
  sha3_state_t state;
  int ret = 0;

  // single call
  sha3_256(output, input, len);
  if (memcmp(expected, output, SHA3_256_LEN) != 0) {
    ret = 1;
  }

  // multiple call (calling update twice)
  memset(output, 0, SHA3_256_LEN);
  sha3_256_init(&state);
  sha3_256_update(&state, input, len / 2);
  sha3_256_update(&state, input + len / 2, len - len / 2);
  sha3_256_digest(&state, output);
  if (memcmp(expected, output, SHA3_256_LEN) != 0) {
    ret |= 2;
  }

  // multiple call (calling update once)
  memset(output, 0, SHA3_256_LEN);
  sha3_256_init(&state);
  sha3_256_update(&state, input, len);
  sha3_256_digest(&state, output);
  if (memcmp(expected, output, SHA3_256_LEN) != 0) {
    ret |= 4;
  }

  return ret;
}

int test_sha3_512(const uint8_t *input, const size_t len, const uint8_t expected[SHA3_512_LEN]) {
  uint8_t output[SHA3_512_LEN];
  sha3_state_t state;
  int ret = 0;

  // single call
  sha3_512(output, input, len);
  if (memcmp(expected, output, SHA3_512_LEN) != 0) {
    ret = 1;
  }

  // multiple call (calling update twice)
  memset(output, 0, SHA3_512_LEN);
  sha3_512_init(&state);
  sha3_512_update(&state, input, len / 2);
  sha3_512_update(&state, input + len / 2, len - len / 2);
  sha3_512_digest(&state, output);
  if (memcmp(expected, output, SHA3_512_LEN) != 0) {
    ret |= 2;
  }

  // multiple call (calling update once)
  memset(output, 0, SHA3_512_LEN);
  sha3_512_init(&state);
  sha3_512_update(&state, input, len);
  sha3_512_digest(&state, output);
  if (memcmp(expected, output, SHA3_512_LEN) != 0) {
    ret |= 4;
  }

  return ret;
}

int test_shake128(const uint8_t *input, const size_t len,
                  const uint8_t *expected, const size_t exp_len) {
  uint8_t output[MAX_BUF];
  int res = 0;
  shake_state_t state;

  // single call
  shake128(output, exp_len, input, len);
  if (memcmp(expected, output, exp_len) != 0) {
    res = 1;
  }

  // multiple call (absorb and squeeze twice)
  memset(output, 0, exp_len);
  shake128_init(&state);
  shake128_absorb(&state, input, len / 2);
  shake128_absorb(&state, input + len / 2, len - len / 2);
  shake128_finalize(&state);
  shake128_squeeze(&state, output, exp_len / 2);
  shake128_squeeze(&state, output + exp_len / 2, exp_len - exp_len / 2);
  if (memcmp(expected, output, exp_len) != 0) {
    res |= 2;
  }

  // multiple call (absorb and squeeze once)
  memset(output, 0, 21);
  shake128_init(&state);
  shake128_absorb(&state, input, len);
  shake128_finalize(&state);
  shake128_squeeze(&state, output, exp_len);

  if (memcmp(expected, output, exp_len) != 0) {
    res |= 4;
  }

  return res;
}

int test_shake256(const uint8_t *input, const size_t len,
                  const uint8_t *expected, const size_t exp_len) {
  uint8_t output[MAX_BUF];
  int res = 0;
  shake_state_t state;

  // single call
  shake256(output, exp_len, input, len);
  if (memcmp(expected, output, exp_len) != 0) {
    res = 1;
  }

  // multiple call (absorb and squeeze twice)
  memset(output, 0, exp_len);
  shake256_init(&state);
  shake256_absorb(&state, input, len / 2);
  shake256_absorb(&state, input + len / 2, len - len / 2);
  shake256_finalize(&state);
  shake256_squeeze(&state, output, exp_len / 2);
  shake256_squeeze(&state, output + exp_len / 2, exp_len - exp_len / 2);
  if (memcmp(expected, output, exp_len) != 0) {
    res |= 2;
  }

  // multiple call (absorb and squeeze once)
  memset(output, 0, 21);
  shake256_init(&state);
  shake256_absorb(&state, input, len);
  shake256_finalize(&state);
  shake256_squeeze(&state, output, exp_len);

  if (memcmp(expected, output, exp_len) != 0) {
    res |= 4;
  }

  return res;
}

void test_general(const char *msg, const char *file_name, const size_t expected_count,
                  const int alg) {
  FILE *fp = NULL;
  size_t count = 0;
  size_t len, msg_len, exp_len;
  uint8_t message[MAX_BUF];
  uint8_t expected[MAX_BUF];
  int is_outputlen;
  int ret = -1;

  printf("%s", msg);

  fp = fopen(file_name, "r");
  if (fp == NULL) {
    fprintf(stderr, "Error: cannot open file %s\n", file_name);
    goto end;
  }

  while (load_len(&len, fp, &is_outputlen) != -1) {
    ret = load_values(message, &msg_len, fp, "Msg = ");
    if (ret == -1) {
      fprintf(stderr, "Error: cannot read line with prefix \"Msg = \"\n");
      break;
    }

    if (alg == SHA3_256 || alg == SHA3_512) {
      ret = load_values(expected, &exp_len, fp, "MD = ");
      if (ret == -1) {
        fprintf(stderr, "Error: cannot read line with prefix \"MD = \"\n");
        break;
      }  
    }
    else {
      ret = load_values(expected, &exp_len, fp, "Output = ");
      if (ret == -1) {
        fprintf(stderr, "Error: cannot read line with prefix \"Output = \"\n");
        break;
      }
    }

    count += 1;
    /* check consistency of length in file and corresponding hexadecimal string */
    if (!is_outputlen) {
      if (msg_len != len && (msg_len != 1 || len != 0)) {
        fprintf(stderr,
                "Error: count %ld, input file corrupted (length != message length)\n",
                count);
        ret = -1;
        break;
      }
      /* if Len = 0, then Msg is "00", but must be considered an empty message */
      if (len == 0) {
        msg_len = 0;
      }
    }
    else {
      if (len != exp_len) {
        fprintf(stderr,
                "Error: count %ld, input file corrupted (length != output length)\n",
                count);
        ret = -1;
        break; 
      }
    }

    if (alg == SHA3_256) {
      ret = test_sha3_256(message, len, expected);
    }
    else if (alg == SHA3_512) {
      ret = test_sha3_512(message, len, expected);
    }
    else if (alg == SHAKE128) {
      ret = test_shake128(message, msg_len, expected, exp_len);
    }
    else {
      ret = test_shake256(message, msg_len, expected, exp_len);
    }

    if (ret != 0) {
      fprintf(stderr, "Error: count %ld, error: %d\n", count, ret);
      ret = -1;
      break;
    }
  }

  if (ret == 0 && count != expected_count) {
    fprintf(stderr, "Error: count %ld instead of %ld\n", count, expected_count);
    ret = -1;
  }

  if (ret == 0) {
    printf("OK\n");
  }
  else {
    printf("KO\n");
  }

end:
  if (fp != NULL) {
    fclose(fp);
  }
}

int main() {
  printf("[*] SHA3-256\n");  
  test_general("[-]   Short messages...  ", "test_vectors/SHA3_256ShortMsg.rsp", 137, SHA3_256);
  test_general("[-]   Long messages...   ", "test_vectors/SHA3_256LongMsg.rsp",  100, SHA3_256);

  printf("[*] SHA3-512\n");
  test_general("[-]   Short messages...  ", "test_vectors/SHA3_512ShortMsg.rsp", 73, SHA3_512);  
  test_general("[-]   Long messages...   ", "test_vectors/SHA3_512LongMsg.rsp", 100, SHA3_512);

  printf("[*] SHAKE128\n");
  test_general("[-]   Short messages...  ", "test_vectors/SHAKE128ShortMsg.rsp",     337, SHAKE128);
  test_general("[-]   Long messages...   ", "test_vectors/SHAKE128LongMsg.rsp",      100, SHAKE128);
  test_general("[-]   Variable output... ", "test_vectors/SHAKE128VariableOut.rsp", 1126, SHAKE128);

  printf("[*] SHAKE256\n");
  test_general("[-]   Short messages...  ", "test_vectors/SHAKE256ShortMsg.rsp",     273, SHAKE256);
  test_general("[-]   Long messages...   ", "test_vectors/SHAKE256LongMsg.rsp",      100, SHAKE256);
  test_general("[-]   Variable output... ", "test_vectors/SHAKE256VariableOut.rsp", 1246, SHAKE256);

  return 0;
}
