# Where Post-Quantum Migration Hurts a Wi-Fi IoT Endpoint: ESP32 Costs, TLS~1.3 Wire Overhead, and Deployment Guidelines

This repository is the artifact for the paper:

> K. Malinka, M. Perešíni, R. Hranický, A. Firc, A. Smrčka, F. Bučko, O. Hujňák, J. Kratochvíl, and G. Sitko,
> "Where Post-Quantum Migration Hurts a Wi-Fi IoT Endpoint: ESP32 Costs, TLS 1.3 Wire Overhead, and Deployment Guidelines,"
> in *Proc. IEEE NCA 2026 Workshops (ICON 2026)*, 2026.

The paper measures two things. The first is the CPU, RAM, and flash cost of
post-quantum primitives on an ESP32 (Xtensa LX6). The second is the size of
TLS 1.3 handshakes on a Raspberry Pi and Linux testbed.

## Contents

| Path | Content |
| --- | --- |
| `data/esp32_primitives.csv` | Cycles (min, mean, max over 20 runs), peak RAM (static, stack, heap), and incremental flash (DRAM, IRAM, code) for each operation. |
| `data/tls13_message_sizes.csv` | TLS 1.3 record bytes per handshake message for 3 configurations and 2 authentication modes. |
| `data/object_sizes.csv` | Key, ciphertext, and signature sizes of the measured parameter sets and their standardized successors. |
| `analysis/derived_models.py` | Compute the numbers from data for figures and analysis. |
| `firmware/` | ESP32 measurement firmware (ESP-IDF v5.2, FreeRTOS). See the note below. |
| `tls/` | wolfSSL TLS 1.3 client and server, certificate scripts, and captures. See the note below. |

## Run analysis

Need Python 3.8 or later. The script uses the standard library.

```
python analysis/derived_models.py
```

## Measurement environment

Primitive measurements:

- Board: ESP32-DevKitC V4 with ESP32-WROOM-32E (dual-core Xtensa LX6, 240 MHz, 520 KiB SRAM, 4 MiB flash).
- Firmware: ESP-IDF v5.2, FreeRTOS, compiler option `-Os`, bootloader log level "warning", assertions silent.
- Post-quantum code: PQClean `clean` implementations. The random-bytes adapter calls `esp_fill_random`.
- Classical code: wolfSSL (`WOLFSSL_ESP32`, `HAVE_CURVE25519`, `HAVE_ED25519`, `USE_FAST_MATH`, `WOLFSSL_SMALL_STACK`).
- Method: each operation runs 20 times in a new high-priority task on core 1. Background tasks run on core 0. An empty-task baseline is subtracted. Cycles come from `xthal_get_ccount`, stack from `uxTaskGetStackHighWaterMark`, heap from the ESP-IDF heap hooks, and flash from `idf.py size` and `esp_idf_size`.

TLS measurements:

- Client: Raspberry Pi 4 Model B (Raspberry Pi OS). Server: Dell Latitude 5521 (Ubuntu 22.04 LTS). Switch: MikroTik hAP ax3, Ethernet.
- TLS stack: wolfSSL post-quantum examples at commit `20d13d8526f5435f2a6a5c637702bf9170d7268e`, liboqs 0.8.0, and the OQS OpenSSL 1.1.1 fork (`OQS-OpenSSL_1_1_1-stable`) for certificates.
- wolfSSL configuration: `./configure --enable-tls13 --enable-ed25519 --enable-curve25519 --disable-rsa --enable-sha3 --enable-sha512 --enable-experimental --with-liboqs CFLAGS="-DHAVE_SECRET_CALLBACK"`
- PKI: root CA (preloaded, not sent), intermediate CA, and end-entity certificates, all in the signature family of the configuration.
- Cipher suite: `TLS_AES_256_GCM_SHA384`. The client offers 12 groups and 9 signature algorithms.
- Captures: OQS Wireshark build with wolfSSL OIDs, capture filter `port 11111 and host <ip>`, decryption with the client key log.
- The byte counts include TLS record headers. They do not include Ethernet, IP, or TCP headers.

## Data

The  `data/` come from the measurement results.
