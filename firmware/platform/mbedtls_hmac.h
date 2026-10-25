#ifndef GMR_MBEDTLS_HMAC_H
#define GMR_MBEDTLS_HMAC_H

#include <stddef.h>
#include <stdint.h>

/* Use protected platform provisioning; never compile production keys here. */
typedef struct {
    const uint8_t *key;
    size_t key_length;
} gmr_mbedtls_key;

int gmr_mbedtls_hmac(void *context, const uint8_t *message, size_t message_len,
                     uint8_t output[32]);

#endif
