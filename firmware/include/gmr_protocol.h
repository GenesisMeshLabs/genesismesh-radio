#ifndef GMR_PROTOCOL_H
#define GMR_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GMR_VERSION 1u
#define GMR_HEADER_SIZE 19u
#define GMR_TAG_SIZE 16u
#define GMR_MAX_PAYLOAD 16u
#define GMR_MAX_FRAME 51u
#define GMR_MAX_AUDIENCE 128u

#define GMR_TELEMETRY 1u
#define GMR_COMMAND 2u
#define GMR_OUTCOME 3u
#define GMR_SUCCESS 0u
#define GMR_REJECTED 1u
#define GMR_UNCERTAIN 2u

#define GMR_OK 0
#define GMR_INVALID -1
#define GMR_AUTH_FAILED -2
#define GMR_EXPIRED -3
#define GMR_CRYPTO_FAILED -4

typedef struct {
    uint8_t kind;
    uint32_t device_id;
    uint64_t counter;
    uint32_t expires_at;
    uint8_t payload_len;
    uint8_t payload[GMR_MAX_PAYLOAD];
} gmr_frame;

/* The platform supplies vetted HMAC-SHA256 using a per-device key >=32 bytes.
 * Return zero and write all 32 output bytes on success; nonzero on failure.
 * context owns the key and its storage. The codec never provisions keys. */
typedef int (*gmr_hmac_sha256)(void *context, const uint8_t *message,
                             size_t message_len, uint8_t output[32]);

/* Reserve the counter durably before encoding/transmitting. Payload privacy,
 * replay state, trusted time, routing and physical actions are caller concerns. */
int gmr_encode(const gmr_frame *frame, const uint8_t *audience, size_t audience_len,
               gmr_hmac_sha256 hmac, void *context, uint8_t *output,
               size_t capacity, size_t *written);

/* Output is written only after authentication, framing and freshness pass.
 * max_frame is the transport's full application payload allowance. */
int gmr_decode(const uint8_t *packet, size_t packet_len,
               const uint8_t *audience, size_t audience_len,
               gmr_hmac_sha256 hmac, void *context, uint32_t now,
               uint32_t max_future_seconds, size_t max_frame, gmr_frame *output);

int gmr_telemetry_payload(uint8_t metric, int32_t value, uint8_t output[5]);
int gmr_parse_telemetry(const uint8_t *payload, size_t payload_len,
                        uint8_t *metric, int32_t *value);
int gmr_command_payload(uint16_t interval_seconds, uint8_t output[3]);
int gmr_parse_command(const uint8_t *payload, size_t payload_len,
                      uint16_t *interval_seconds);
int gmr_outcome_payload(uint64_t command_counter, uint8_t status,
                        uint16_t applied_interval, uint8_t output[11]);
int gmr_parse_outcome(const uint8_t *payload, size_t payload_len,
                      uint64_t *command_counter, uint8_t *status,
                      uint16_t *applied_interval);

#ifdef __cplusplus
}
#endif
#endif
