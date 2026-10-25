#include "mbedtls_hmac.h"

#include <mbedtls/md.h>

int gmr_mbedtls_hmac(void *context, const uint8_t *message, size_t message_len,
                     uint8_t output[32]) {
    const gmr_mbedtls_key *key = (const gmr_mbedtls_key *)context;
    const mbedtls_md_info_t *md;
    if (key == NULL || key->key == NULL || key->key_length < 32u ||
        message == NULL || output == NULL) {
        return -1;
    }
    md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return -1;
    }
    return mbedtls_md_hmac(md, key->key, key->key_length,
                           message, message_len, output);
}
