#include "gmr_protocol.h"

#include <string.h>

static const uint8_t domain[] = "GenesisMeshRadio\0v1";

static void put_be(uint8_t *out, uint64_t value, size_t count) {
    size_t i;
    for (i = 0; i < count; ++i) {
        out[count - i - 1u] = (uint8_t)(value & 255u);
        value >>= 8;
    }
}

static uint64_t get_be(const uint8_t *in, size_t count) {
    uint64_t value = 0;
    size_t i;
    for (i = 0; i < count; ++i) {
        value = (value << 8) | in[i];
    }
    return value;
}

static int valid_audience(const uint8_t *audience, size_t length) {
    size_t i;
    if (audience == NULL || length == 0 || length > GMR_MAX_AUDIENCE) {
        return 0;
    }
    for (i = 0; i < length; ++i) {
        if (audience[i] < 33u || audience[i] > 126u) {
            return 0;
        }
    }
    return 1;
}

static int valid_payload(const gmr_frame *frame) {
    uint8_t metric, status;
    int32_t value;
    uint16_t interval;
    uint64_t command_counter;
    if (frame->payload_len > GMR_MAX_PAYLOAD) {
        return 0;
    }
    switch (frame->kind) {
    case GMR_TELEMETRY:
        return gmr_parse_telemetry(frame->payload, frame->payload_len,
                                   &metric, &value) == GMR_OK;
    case GMR_COMMAND:
        return gmr_parse_command(frame->payload, frame->payload_len,
                                 &interval) == GMR_OK;
    case GMR_OUTCOME:
        return gmr_parse_outcome(frame->payload, frame->payload_len,
                                 &command_counter, &status, &interval) == GMR_OK;
    default:
        return 0;
    }
}

static int authenticate(const uint8_t *body, size_t body_len, uint8_t kind,
                        const uint8_t *audience, size_t audience_len,
                        gmr_hmac_sha256 hmac, void *context, uint8_t tag[32]) {
    uint8_t message[sizeof(domain) + 2u + GMR_MAX_AUDIENCE + 1u +
                    GMR_HEADER_SIZE + GMR_MAX_PAYLOAD];
    size_t length = sizeof(domain);
    memcpy(message, domain, length);
    put_be(message + length, audience_len, 2u);
    length += 2u;
    memcpy(message + length, audience, audience_len);
    length += audience_len;
    message[length++] = kind == GMR_COMMAND ? 2u : 1u;
    memcpy(message + length, body, body_len);
    length += body_len;
    return hmac(context, message, length, tag) == 0 ? GMR_OK : GMR_CRYPTO_FAILED;
}

int gmr_encode(const gmr_frame *frame, const uint8_t *audience, size_t audience_len,
               gmr_hmac_sha256 hmac, void *context, uint8_t *output,
               size_t capacity, size_t *written) {
    uint8_t tag[32];
    size_t body_len;
    int status;
    if (written != NULL) {
        *written = 0;
    }
    if (frame == NULL || output == NULL || written == NULL || hmac == NULL ||
        !valid_audience(audience, audience_len) || frame->device_id == 0 ||
        frame->counter == 0 || frame->expires_at == 0 || !valid_payload(frame)) {
        return GMR_INVALID;
    }
    body_len = GMR_HEADER_SIZE + frame->payload_len;
    if (capacity < body_len + GMR_TAG_SIZE) {
        return GMR_INVALID;
    }
    output[0] = GMR_VERSION;
    output[1] = frame->kind;
    put_be(output + 2, frame->device_id, 4u);
    put_be(output + 6, frame->counter, 8u);
    put_be(output + 14, frame->expires_at, 4u);
    output[18] = frame->payload_len;
    memcpy(output + GMR_HEADER_SIZE, frame->payload, frame->payload_len);
    status = authenticate(output, body_len, frame->kind, audience, audience_len,
                          hmac, context, tag);
    if (status != GMR_OK) {
        return status;
    }
    memcpy(output + body_len, tag, GMR_TAG_SIZE);
    *written = body_len + GMR_TAG_SIZE;
    return GMR_OK;
}

int gmr_decode(const uint8_t *packet, size_t packet_len,
               const uint8_t *audience, size_t audience_len,
               gmr_hmac_sha256 hmac, void *context, uint32_t now,
               uint32_t max_future_seconds, size_t max_frame, gmr_frame *output) {
    gmr_frame frame;
    uint8_t tag[32], different = 0;
    size_t body_len, i;
    int status;
    if (packet == NULL || output == NULL || hmac == NULL ||
        !valid_audience(audience, audience_len) || max_future_seconds == 0 ||
        packet_len < GMR_HEADER_SIZE + GMR_TAG_SIZE ||
        packet_len > GMR_MAX_FRAME || packet_len > max_frame ||
        packet[0] != GMR_VERSION || packet[1] < GMR_TELEMETRY ||
        packet[1] > GMR_OUTCOME || packet[18] > GMR_MAX_PAYLOAD ||
        packet_len != GMR_HEADER_SIZE + (size_t)packet[18] + GMR_TAG_SIZE) {
        return GMR_INVALID;
    }
    body_len = packet_len - GMR_TAG_SIZE;
    status = authenticate(packet, body_len, packet[1], audience, audience_len,
                          hmac, context, tag);
    if (status != GMR_OK) {
        return status;
    }
    for (i = 0; i < GMR_TAG_SIZE; ++i) {
        different |= tag[i] ^ packet[body_len + i];
    }
    if (different != 0) {
        return GMR_AUTH_FAILED;
    }
    memset(&frame, 0, sizeof(frame));
    frame.kind = packet[1];
    frame.device_id = (uint32_t)get_be(packet + 2, 4u);
    frame.counter = get_be(packet + 6, 8u);
    frame.expires_at = (uint32_t)get_be(packet + 14, 4u);
    frame.payload_len = packet[18];
    memcpy(frame.payload, packet + GMR_HEADER_SIZE, frame.payload_len);
    if (frame.device_id == 0 || frame.counter == 0 || !valid_payload(&frame)) {
        return GMR_INVALID;
    }
    if (frame.expires_at <= now ||
        (uint64_t)frame.expires_at > (uint64_t)now + max_future_seconds) {
        return GMR_EXPIRED;
    }
    *output = frame;
    return GMR_OK;
}

int gmr_telemetry_payload(uint8_t metric, int32_t value, uint8_t output[5]) {
    if (output == NULL) {
        return GMR_INVALID;
    }
    output[0] = metric;
    put_be(output + 1, (uint32_t)value, 4u);
    return GMR_OK;
}

int gmr_parse_telemetry(const uint8_t *payload, size_t payload_len,
                        uint8_t *metric, int32_t *value) {
    uint32_t bits;
    if (payload == NULL || metric == NULL || value == NULL || payload_len != 5u) {
        return GMR_INVALID;
    }
    *metric = payload[0];
    bits = (uint32_t)get_be(payload + 1, 4u);
    /* Avoid implementation-defined conversion of large unsigned integers. */
    *value = bits <= INT32_MAX ? (int32_t)bits : -(int32_t)(~bits) - 1;
    return GMR_OK;
}

int gmr_command_payload(uint16_t interval_seconds, uint8_t output[3]) {
    if (output == NULL || interval_seconds == 0) {
        return GMR_INVALID;
    }
    output[0] = 1u;
    put_be(output + 1, interval_seconds, 2u);
    return GMR_OK;
}

int gmr_parse_command(const uint8_t *payload, size_t payload_len,
                      uint16_t *interval_seconds) {
    if (payload == NULL || interval_seconds == NULL || payload_len != 3u ||
        payload[0] != 1u || get_be(payload + 1, 2u) == 0) {
        return GMR_INVALID;
    }
    *interval_seconds = (uint16_t)get_be(payload + 1, 2u);
    return GMR_OK;
}

int gmr_outcome_payload(uint64_t command_counter, uint8_t status,
                        uint16_t applied_interval, uint8_t output[11]) {
    if (output == NULL || command_counter == 0 || status > GMR_UNCERTAIN ||
        (status == GMR_SUCCESS && applied_interval == 0)) {
        return GMR_INVALID;
    }
    put_be(output, command_counter, 8u);
    output[8] = status;
    put_be(output + 9, applied_interval, 2u);
    return GMR_OK;
}

int gmr_parse_outcome(const uint8_t *payload, size_t payload_len,
                      uint64_t *command_counter, uint8_t *status,
                      uint16_t *applied_interval) {
    if (payload == NULL || command_counter == NULL || status == NULL ||
        applied_interval == NULL || payload_len != 11u ||
        get_be(payload, 8u) == 0 || payload[8] > GMR_UNCERTAIN ||
        (payload[8] == GMR_SUCCESS && get_be(payload + 9, 2u) == 0)) {
        return GMR_INVALID;
    }
    *command_counter = get_be(payload, 8u);
    *status = payload[8];
    *applied_interval = (uint16_t)get_be(payload + 9, 2u);
    return GMR_OK;
}
