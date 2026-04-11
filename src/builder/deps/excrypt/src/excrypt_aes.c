#include <string.h>

/* Architecture Detection */
#if defined(_M_AMD64) || defined(__amd64__) || defined(__x86_64__)
  #define EXCRYPT_X64
#elif defined(_M_ARM64) || defined(__aarch64__) || defined(__arm64__)
  #define EXCRYPT_ARM64
#endif

/* Header Selection */
#ifdef EXCRYPT_X64
  #include <wmmintrin.h>  // AES-NI
#elif defined(EXCRYPT_ARM64)
  #include <arm_neon.h>   // NEON
#endif

#ifdef __WIN32
#include <intrin.h> // cpuid
#endif

#if defined(__linux__) || defined(__APPLE__)
#define __cpuid(out, infoType)\
        asm("cpuid": "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]): "a" (infoType));
#endif

#include "excrypt.h"

// reference rijndael implementation, from http://www.efgh.com/software/rijndael.htm
#include "rijndael.h"

// function signature shared between reference impl. and our hardware-accelerated versions
typedef void(*rijndaelCrypt_fn)(const uint32_t*, int, const uint8_t*, uint8_t*);

rijndaelCrypt_fn AesEnc = rijndaelEncrypt;
rijndaelCrypt_fn AesDec = rijndaelDecrypt;

/* --- ARMv8 NEON Path --- */
#ifdef EXCRYPT_ARM64
void rijndaelDecrypt_ARMv8(const uint32_t* rk, int nrounds, const uint8_t* ciphertext, uint8_t* plaintext)
{
    const uint8_t* round_keys = (const uint8_t*)rk;
    uint8x16_t block = vld1q_u8(ciphertext);

    // Initial AddRoundKey
    block = veorq_u8(block, vld1q_u8(round_keys));
    round_keys += 16;

    // Main rounds
    for (int round = 1; round < nrounds; ++round)
    {
        block = vaesdq_u8(block, vld1q_u8(round_keys));
        block = vaesimcq_u8(block);
        round_keys += 16;
    }

    // Final round (no InvMixColumns)
    block = vaesdq_u8(block, vld1q_u8(round_keys));
    round_keys += 16;
    block = veorq_u8(block, vld1q_u8(round_keys));

    vst1q_u8(plaintext, block);
}

void rijndaelEncrypt_ARMv8(const uint32_t* rk, int nrounds, const uint8_t* plaintext, uint8_t* ciphertext)
{
    const uint8_t* round_keys = (const uint8_t*)rk;
    uint8x16_t block = vld1q_u8(plaintext);

    // Initial AddRoundKey
    block = veorq_u8(block, vld1q_u8(round_keys));
    round_keys += 16;

    // Main rounds
    for (int round = 1; round < nrounds; ++round)
    {
        block = vaeseq_u8(block, vld1q_u8(round_keys));
        block = vaesmcq_u8(block);
        round_keys += 16;
    }

    // Final round (no MixColumns)
    block = vaeseq_u8(block, vld1q_u8(round_keys));
    round_keys += 16;
    block = veorq_u8(block, vld1q_u8(round_keys));

    vst1q_u8(ciphertext, block);
}
#endif

/* --- x86_64 AES-NI Path --- */
#ifdef EXCRYPT_X64
/* AESNI code based on https://gist.github.com/acapola/d5b940da024080dfaf5f */
void rijndaelEncrypt_AESNI(const uint32_t* rk, int nrounds, const uint8_t* plaintext, uint8_t* ciphertext)
{
  __m128i block = _mm_loadu_si128((const __m128i*)plaintext);
  __m128i* enc_table = (__m128i*)rk;

  block = _mm_xor_si128(block, enc_table[0]);
  block = _mm_aesenc_si128(block, enc_table[1]);
  block = _mm_aesenc_si128(block, enc_table[2]);
  block = _mm_aesenc_si128(block, enc_table[3]);
  block = _mm_aesenc_si128(block, enc_table[4]);
  block = _mm_aesenc_si128(block, enc_table[5]);
  block = _mm_aesenc_si128(block, enc_table[6]);
  block = _mm_aesenc_si128(block, enc_table[7]);
  block = _mm_aesenc_si128(block, enc_table[8]);
  block = _mm_aesenc_si128(block, enc_table[9]);
  block = _mm_aesenclast_si128(block, enc_table[10]);

  _mm_storeu_si128((__m128i*)ciphertext, block);
}

void rijndaelDecrypt_AESNI(const uint32_t* rk, int nrounds, const uint8_t* ciphertext, uint8_t* plaintext)
{
  __m128i block = _mm_loadu_si128((const __m128i*)ciphertext);
  __m128i* dec_table = (__m128i*)rk;

  block = _mm_xor_si128(block, dec_table[0]);
  block = _mm_aesdec_si128(block, dec_table[1]);
  block = _mm_aesdec_si128(block, dec_table[2]);
  block = _mm_aesdec_si128(block, dec_table[3]);
  block = _mm_aesdec_si128(block, dec_table[4]);
  block = _mm_aesdec_si128(block, dec_table[5]);
  block = _mm_aesdec_si128(block, dec_table[6]);
  block = _mm_aesdec_si128(block, dec_table[7]);
  block = _mm_aesdec_si128(block, dec_table[8]);
  block = _mm_aesdec_si128(block, dec_table[9]);
  block = _mm_aesdeclast_si128(block, dec_table[10]);

  _mm_storeu_si128((__m128i*)plaintext, block);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}
#endif

static int hardware_aes_supported = 0;
int aes_hw_supported()
{
#ifdef EXCRYPT_X64
  int regs[4];
  __cpuid(regs, 1);
  hardware_aes_supported = (regs[2] >> 25) & 1;

  if (hardware_aes_supported)
  {
    AesEnc = rijndaelEncrypt_AESNI;
    AesDec = rijndaelDecrypt_AESNI;
  }
#elif defined(EXCRYPT_ARM64)
  // On ARM64/Apple Silicon, cryptography extensions are usually guaranteed or detectable via sysctl.
  // For most targets we assume AArch64 has the crypto extensions if the compiler is told to use them.
  hardware_aes_supported = 1; 
  AesEnc = rijndaelEncrypt_ARMv8;
  AesDec = rijndaelDecrypt_ARMv8;
#else
  hardware_aes_supported = 0;
#endif
  return hardware_aes_supported;
}

void ExCryptAesKey(EXCRYPT_AES_STATE* state, const uint8_t* key)
{
  if (hardware_aes_supported || aes_hw_supported())
  {
#ifdef EXCRYPT_X64
    __m128i* enc_table = (__m128i*)state->keytabenc;
    enc_table[0] = _mm_loadu_si128((const __m128i*)key);
    enc_table[1] = AES_128_key_exp(enc_table[0], 0x01);
    enc_table[2] = AES_128_key_exp(enc_table[1], 0x02);
    enc_table[3] = AES_128_key_exp(enc_table[2], 0x04);
    enc_table[4] = AES_128_key_exp(enc_table[3], 0x08);
    enc_table[5] = AES_128_key_exp(enc_table[4], 0x10);
    enc_table[6] = AES_128_key_exp(enc_table[5], 0x20);
    enc_table[7] = AES_128_key_exp(enc_table[6], 0x40);
    enc_table[8] = AES_128_key_exp(enc_table[7], 0x80);
    enc_table[9] = AES_128_key_exp(enc_table[8], 0x1B);
    enc_table[10] = AES_128_key_exp(enc_table[9], 0x36);

    // generate decryption keys in reverse order.
    __m128i* dec_table = (__m128i*) & state->keytabdec;
    dec_table[0] = enc_table[10];
    dec_table[1] = _mm_aesimc_si128(enc_table[9]);
    dec_table[2] = _mm_aesimc_si128(enc_table[8]);
    dec_table[3] = _mm_aesimc_si128(enc_table[7]);
    dec_table[4] = _mm_aesimc_si128(enc_table[6]);
    dec_table[5] = _mm_aesimc_si128(enc_table[5]);
    dec_table[6] = _mm_aesimc_si128(enc_table[4]);
    dec_table[7] = _mm_aesimc_si128(enc_table[3]);
    dec_table[8] = _mm_aesimc_si128(enc_table[2]);
    dec_table[9] = _mm_aesimc_si128(enc_table[1]);
    dec_table[10] = _mm_loadu_si128((const __m128i*)key);
#else
    // Reference Key Setup handles non-x86 hardware features natively in the rijndael implementation
    rijndaelSetupEncrypt((uint32_t*)state->keytabenc, key, 128);
    memcpy(state->keytabdec, state->keytabenc, sizeof(state->keytabdec));
    rijndaelSetupDecrypt((uint32_t*)state->keytabdec, key, 128);
#endif
  }
  else
  {
    rijndaelSetupEncrypt((uint32_t*)state->keytabenc, key, 128);
    memcpy(state->keytabdec, state->keytabenc, sizeof(state->keytabdec));
    rijndaelSetupDecrypt((uint32_t*)state->keytabdec, key, 128);
  }
}

void ExCryptAesEcb(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint8_t* output, uint8_t encrypt)
{
  if (encrypt)
  {
    AesEnc((uint32_t*)state->keytabenc, 10, input, output);
  }
  else
  {
    AesDec((uint32_t*)state->keytabdec, 10, input, output);
  }
}

void xorWithIv(const uint8_t* input, uint8_t* output, const uint8_t* iv)
{
  for (uint32_t i = 0; i < AES_BLOCKLEN; i++)
  {
    output[i] = input[i] ^ iv[i];
  }
}

void rijndaelCbcEncrypt(const uint32_t* rk, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    xorWithIv(input, output, iv);
    AesEnc(rk, 10, output, output);
    iv = output;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void rijndaelCbcDecrypt(const uint32_t* rk, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t current_input[AES_BLOCKLEN];
  uint8_t iv[AES_BLOCKLEN];
  memcpy(iv, feed, AES_BLOCKLEN);

  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    memcpy(current_input, input, AES_BLOCKLEN);
    AesDec(rk, 10, input, output);
    xorWithIv(output, output, iv);
    memcpy(iv, current_input, AES_BLOCKLEN);

    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }

  // Store the last ciphertext block in feed for the next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesCbc(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed, uint8_t encrypt)
{
  if (encrypt)
  {
    rijndaelCbcEncrypt((uint32_t*)state->keytabenc, input, input_size, output, feed);
  }
  else
  {
    rijndaelCbcDecrypt((uint32_t*)state->keytabdec, input, input_size, output, feed);
  }
}

uint32_t* aesschedule_dectable(EXCRYPT_AES_SCHEDULE* state)
{
  return (uint32_t*)&state->keytab[state->num_rounds + 1]; // dec table starts at last entry of enc table
}

void ExCryptAesCreateKeySchedule(const uint8_t* key, uint32_t key_size, EXCRYPT_AES_SCHEDULE* state)
{
  if (key_size != 0x10 && key_size != 0x18 && key_size != 0x20)
  {
    return; // invalid key size, must be 128/192/256 bits
  }

  state->num_rounds = (key_size >> 2) + 5; // seems to be nr - 1 ?

  rijndaelSetupEncrypt((uint32_t*)state->keytab, key, key_size * 8);
  memcpy(aesschedule_dectable(state), state->keytab, (state->num_rounds + 2) * 0x10);
  rijndaelSetupDecrypt(aesschedule_dectable(state), key, key_size * 8);
}

void ExCryptAesCbcEncrypt(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    xorWithIv(input, output, iv);
    rijndaelEncrypt((uint32_t*)state->keytab, state->num_rounds + 1, output, output);
    iv = output;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesCbcDecrypt(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t current_input[AES_BLOCKLEN];
  uint8_t iv[AES_BLOCKLEN];
  memcpy(iv, feed, AES_BLOCKLEN);

  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    memcpy(current_input, input, AES_BLOCKLEN);
    rijndaelDecrypt(aesschedule_dectable(state), state->num_rounds + 1, input, output);
    xorWithIv(output, output, iv);
    memcpy(iv, current_input, AES_BLOCKLEN);

    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }

  // Store the last ciphertext block in feed for the next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesEncryptOne(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint8_t* output)
{
  uint8_t feed[0x10];
  memset(feed, 0, 0x10);

  ExCryptAesCbcEncrypt(state, input, 0x10, output, feed);
}

void ExCryptAesDecryptOne(EXCRYPT_AES_SCHEDULE* state, const uint8_t* input, uint8_t* output)
{
  uint8_t feed[0x10];
  memset(feed, 0, 0x10);

  ExCryptAesCbcDecrypt(state, input, 0x10, output, feed);
}
