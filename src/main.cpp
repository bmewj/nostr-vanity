#include <stdio.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <random>
#include <thread>
#include <atomic>

struct Key {
    uint8_t padding[8];
    union {
        uint8_t bytes[32];
        uint64_t longs[4];
    };
};

static bool bech32_create_bitfield(const char* text, uint64_t* mask, uint64_t* value);
static const char* bytes_to_bech32(uint8_t* bytes, size_t len);
static const char* bytes_to_hex(const uint8_t* bytes, size_t len);

static inline void compute_pubkey(const secp256k1_context* ctx, const Key* seckey, Key* pubkey) {
    secp256k1_pubkey pubkey_raw;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey_raw, seckey->bytes)) {
        return;
    }

    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey->bytes - 1, &len, &pubkey_raw, SECP256K1_EC_COMPRESSED);
    // ec_pubkey_serialize() produces a 33 byte compressed EC public key. The first byte is unnecessary
    // and won't be used. To avoid an extra copy, padding is added to our Key struct so that we can
    // hand ec_pubkey_serialize() a negative index into the bytes array.
}

static void run_thread(uint64_t prefix_mask, uint64_t prefix_value, std::atomic_long* total_count) {
    constexpr int REPORT_AMOUNT = 1000;

    auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    std::random_device rd_for_seed;
    std::uniform_int_distribution<uint64_t> dist;
    std::mt19937_64 rd(dist(rd_for_seed));

    Key seckey;
    seckey.longs[0] = dist(rd);
    seckey.longs[1] = dist(rd);
    seckey.longs[2] = dist(rd);
    seckey.longs[3] = dist(rd);

    int i = 0;
    while (true) {

        // Compute the pubkey
        Key pubkey;
        compute_pubkey(ctx, &seckey, &pubkey);

        // Check for the prefix
        if ((pubkey.longs[0] & prefix_mask) == prefix_value) {
            printf("npub1%s... %s\n", bytes_to_bech32(pubkey.bytes, 16), bytes_to_hex(seckey.bytes, sizeof(seckey.bytes)));
        }

        // Change (one part of) the seckey
        seckey.longs[i % 4] = dist(rd);
        i++;

        // Update the total count?
        if (i == REPORT_AMOUNT) {
            i = 0;
            total_count->fetch_add(REPORT_AMOUNT);
        }
    }
}

int main(int argc, const char** argv) {

    if (argc != 2) {
        printf("./nostr-vanity [prefix]\n");
        return 0;
    }

    printf("Searching for vanity pubkeys starting with \"%s\"\n", argv[1]);

    uint64_t prefix_mask, prefix_value;
    if (!bech32_create_bitfield(argv[1], &prefix_mask, &prefix_value)) {
        return 1;
    }

    printf("\n... represented as hex ...\n");
    printf("  prefix to find (in hex) = %s\n", bytes_to_hex((uint8_t*)&prefix_value, sizeof(uint64_t)));
    printf("  prefix mask    (in hex) = %s\n", bytes_to_hex((uint8_t*)&prefix_mask,  sizeof(uint64_t)));
    printf("\n");

    int num_threads = std::thread::hardware_concurrency();
    printf("Running search on %d threads!\n\n", num_threads);

    std::atomic_long total_count = 0;

    std::thread threads[num_threads];
    for (int i = 0; i < num_threads; ++i) {
        threads[i] = std::thread(&run_thread, prefix_mask, prefix_value, &total_count);
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        auto curr_count = total_count.load();
        auto curr_time = std::chrono::high_resolution_clock::now();

        auto dt = (float)std::chrono::duration_cast<std::chrono::milliseconds>(curr_time - start_time).count() / 1000.0;
        printf("  ... tested %ld keys (%d/s) ...\n", curr_count, (int)((float)curr_count / dt));
    }
    return 0;
}




//// BECH32 encoding

static const char bech32_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t bech32_charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

bool bech32_create_bitfield(const char* text, uint64_t* mask, uint64_t* value) {
    int len = (int)strlen(text);
    int len_bytes = (len * 5) / 8;
    int bits_rem = (len * 5) % 8;
    if (bits_rem > 0) {
        len_bytes += 1;
    }

    if (len_bytes > sizeof(uint64_t)) {
        printf("Prefix search string is too long :(\n");
        printf("This program doesn't support that, and even if it did,\n");
        printf("it would take a loooooooooong time...\n");
        return false;
    }

    // Parse words
    int8_t words[len];
    for (int i = 0; i < len; ++i) {
        words[i] = bech32_charset_rev[text[i]];
        if (words[i] == -1) {
            printf("Invalid character '%c' at index %d (not bech32)\n", text[i], i);
            printf("Valid characters are: a-z 0-9 EXCLUDING b, i, o and 1\n");
            return false;
        }
    }

    // Break into bits
    uint8_t bits[sizeof(uint64_t) * 8];
    memset(bits, 0, sizeof(uint64_t) * 8);
    for (int i = 0; i < len; ++i) {
        bits[i*5 + 0] = (words[i] & 16) ? 1 : 0;
        bits[i*5 + 1] = (words[i] &  8) ? 1 : 0;
        bits[i*5 + 2] = (words[i] &  4) ? 1 : 0;
        bits[i*5 + 3] = (words[i] &  2) ? 1 : 0;
        bits[i*5 + 4] = (words[i] &  1) ? 1 : 0;
    }

    // Convert to bytes
    uint8_t bytes[sizeof(uint64_t)];
    for (int i = 0; i < sizeof(uint64_t); ++i) {
        bytes[i] = (
            (bits[i*8 + 0] ? 0x80 : 0) +
            (bits[i*8 + 1] ? 0x40 : 0) +
            (bits[i*8 + 2] ? 0x20 : 0) +
            (bits[i*8 + 3] ? 0x10 : 0) +
            (bits[i*8 + 4] ? 0x08 : 0) +
            (bits[i*8 + 5] ? 0x04 : 0) +
            (bits[i*8 + 6] ? 0x02 : 0) +
            (bits[i*8 + 7] ? 0x01 : 0)
        );
    }

    // Create bit mask
    uint8_t bytes_mask[sizeof(uint64_t)];
    memset(bytes_mask, 0, sizeof(uint64_t));
    for (int i = 0; i < len_bytes; ++i) {
        bytes_mask[i] = 0xff;
    }
    switch (bits_rem) {
        case 1: bytes_mask[len_bytes - 1] = 0x80; break;
        case 2: bytes_mask[len_bytes - 1] = 0xc0; break;
        case 3: bytes_mask[len_bytes - 1] = 0xe0; break;
        case 4: bytes_mask[len_bytes - 1] = 0xf0; break;
        case 5: bytes_mask[len_bytes - 1] = 0xf8; break;
        case 6: bytes_mask[len_bytes - 1] = 0xfc; break;
        case 7: bytes_mask[len_bytes - 1] = 0xfe; break;
    }

    *mask = *(uint64_t*)bytes_mask;
    *value = *(uint64_t*)bytes;
    return true;
}

const char* bytes_to_bech32(uint8_t* bytes, size_t len) {

    int len_words = ((int)len * 8) / 5;
    int bits_rem  = ((int)len * 8) % 5;
    if (bits_rem > 0) {
        len_words += 1;
    }

    uint8_t bits[len_words * 5];
    memset(bits, 0, len_words * 5);
    for (int i = 0; i < len; ++i) {
        bits[i*8 + 0] = (bytes[i] & 0x80) ? 1 : 0;
        bits[i*8 + 1] = (bytes[i] & 0x40) ? 1 : 0;
        bits[i*8 + 2] = (bytes[i] & 0x20) ? 1 : 0;
        bits[i*8 + 3] = (bytes[i] & 0x10) ? 1 : 0;
        bits[i*8 + 4] = (bytes[i] & 0x08) ? 1 : 0;
        bits[i*8 + 5] = (bytes[i] & 0x04) ? 1 : 0;
        bits[i*8 + 6] = (bytes[i] & 0x02) ? 1 : 0;
        bits[i*8 + 7] = (bytes[i] & 0x01) ? 1 : 0;
    }

    static char output[1024];
    assert(len_words < sizeof(output));

    for (int i = 0; i < len_words; ++i) {
        uint8_t word = (
            (bits[i*5 + 0] ? 0x10 : 0) +
            (bits[i*5 + 1] ? 0x08 : 0) +
            (bits[i*5 + 2] ? 0x04 : 0) +
            (bits[i*5 + 3] ? 0x02 : 0) +
            (bits[i*5 + 4] ? 0x01 : 0)
        );
        output[i] = bech32_charset[word];
    }
    output[len_words] = '\0';

    return output;
}

const char* bytes_to_hex(const uint8_t* bytes, size_t len) {
    static char buffer[1024];

    char* ch = buffer;
    for (int i = 0; i < len; ++i) {
        snprintf(ch, 3, "%02x", bytes[i]);
        ch += 2;
    }
    *ch = '\0';

    return buffer;
}
