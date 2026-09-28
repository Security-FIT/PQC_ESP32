#!/usr/bin/env python3
"""
Usage:  python analysis/derived_models.py      (Python 3.8+, standard library only)

The script reads data/esp32_primitives.csv and data/tls13_message_sizes.csv,
prints each derived value
"""
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KIB = 1024.0
CLOCK_HZ = 240e6          # ESP32 clock used in the measurements
APP_BYTES = 189           # 32-byte HTTP request + 157-byte response
REPORT_PERIOD_MIN = 5     # one report every five minutes
TCP_PAYLOAD = 1460        # TCP payload ceiling for the segment lower bound

failures = []


def check(name, value, expected, tol):
    ok = abs(value - expected) <= tol
    if not ok:
        failures.append(name)
    print(f"{'OK  ' if ok else 'FAIL'} {name:58s} {value:>14.4f}  (paper: {expected})")


def load_primitives():
    rows = {}
    with open(ROOT / "data" / "esp32_primitives.csv", newline="") as f:
        for r in csv.DictReader(f):
            rows[(r["algorithm"], r["operation"])] = {
                k: (float(v) if k.startswith(("cycles", "ram", "flash")) else v)
                for k, v in r.items()}
    return rows


def load_tls():
    totals = defaultdict(int)
    parts = defaultdict(lambda: defaultdict(int))
    with open(ROOT / "data" / "tls13_message_sizes.csv", newline="") as f:
        for r in csv.DictReader(f):
            key = (r["configuration"], r["auth_mode"])
            totals[key] += int(r["record_bytes"])
            parts[key][(r["sender"], r["message"])] += int(r["record_bytes"])
    return totals, parts


def main():
    p = load_primitives()
    totals, parts = load_tls()
    C, D, F = "X25519+Ed25519", "Kyber512+Dilithium2", "Kyber512+Falcon-512"

    print("== Device layer (ESP32) ==")
    check("Kyber512 KeyGen Mcy", p["Kyber512", "KeyGen"]["cycles_avg"] / 1e6, 1.08, 0.005)
    check("Kyber512 Decaps Mcy", p["Kyber512", "Decaps"]["cycles_avg"] / 1e6, 1.56, 0.005)
    check("Dilithium2 Sign peak RAM KiB", p["Dilithium2", "Sign"]["ram_total_B"] / KIB, 53.2, 0.05)
    check("Falcon-512 Sign peak RAM KiB", p["Falcon-512", "Sign"]["ram_total_B"] / KIB, 43.0, 0.05)
    check("SPHINCS+ Sign peak RAM KiB",
          p["SPHINCS+-SHA2-128f-simple", "Sign"]["ram_total_B"] / KIB, 19.1, 0.05)
    check("SPHINCS+ Sign time at 240 MHz (s)",
          p["SPHINCS+-SHA2-128f-simple", "Sign"]["cycles_avg"] / CLOCK_HZ, 3.30, 0.005)
    check("Falcon-512 KeyGen flash KiB", p["Falcon-512", "KeyGen"]["flash_total_B"] / KIB, 53.8, 0.05)

    print("\n== Protocol layer (TLS 1.3 record bytes) ==")
    for cfg, mode, exp in [(C, "server-only", 1829), (D, "server-only", 13359),
                           (F, "server-only", 7195), (C, "mutual", 3288),
                           (D, "mutual", 24865), (F, "mutual", 12541)]:
        check(f"H {cfg} {mode}", totals[cfg, mode], exp, 0)
    check("ratio D/C server-only", totals[D, "server-only"] / totals[C, "server-only"], 7.3, 0.05)
    check("ratio F/C server-only", totals[F, "server-only"] / totals[C, "server-only"], 3.9, 0.05)
    check("ratio D/C mutual", totals[D, "mutual"] / totals[C, "mutual"], 7.6, 0.05)
    check("ratio F/C mutual", totals[F, "mutual"] / totals[C, "mutual"], 3.8, 0.05)

    shares = []
    for cfg in (D, F):
        for mode in ("server-only", "mutual"):
            cert = sum(v for (s, m), v in parts[cfg, mode].items() if m == "Certificate")
            shares.append(100 * cert / totals[cfg, mode])
    check("min certificate share of PQ handshakes (%)", min(shares), 64.0, 0.5)
    check("max certificate share of PQ handshakes (%)", max(shares), 73.0, 0.5)

    hourly = (60 // REPORT_PERIOD_MIN) * (totals[D, "mutual"] + APP_BYTES)
    check("bytes/hour, D mutual, reconnect per report", hourly, 300648, 0)
    check("application share (%)", 100 * APP_BYTES / (totals[D, "mutual"] + APP_BYTES), 0.75, 0.005)

    print("\n== Amortization, f_H(N) = H / (H + N*A) ==")
    for cfg, e50, e10 in [(C, 18, 157), (F, 67, 598), (D, 132, 1185)]:
        h = totals[cfg, "mutual"]
        n50 = math.floor(h / APP_BYTES) + 1       # smallest N with f_H < 50 %
        n10 = math.floor(9 * h / APP_BYTES) + 1   # smallest N with f_H < 10 %
        check(f"N for f_H<50% ({cfg})", n50, e50, 0)
        check(f"N for f_H<10% ({cfg})", n10, e10, 0)
    check("hours to 50% (D)", 132 * REPORT_PERIOD_MIN / 60, 11.0, 0.05)
    check("days to 10% (D)", 1185 * REPORT_PERIOD_MIN / 60 / 24, 4.1, 0.05)
    for cfg, exp in [(C, 3), (D, 18), (F, 9)]:
        check(f"min TCP segments ({cfg}, mutual)", math.ceil(totals[cfg, "mutual"] / TCP_PAYLOAD), exp, 0)

    print("\n== Link-rate break-even and sensitivity ==")
    d_bytes = totals[D, "mutual"] - totals[F, "mutual"]
    d_cyc = p["Falcon-512", "Sign"]["cycles_avg"] - p["Dilithium2", "Sign"]["cycles_avg"]
    check("delta B (bytes)", d_bytes, 12324, 0)
    check("delta cycles sign (Mcy)", d_cyc / 1e6, 81.14, 0.005)
    check("delta t sign at 240 MHz (ms)", 1e3 * d_cyc / CLOCK_HZ, 338, 0.5)
    check("verify-only saving, server-only (bytes)",
          totals[D, "server-only"] - totals[F, "server-only"], 6164, 0)

    def r_star(eta, f_hz):
        return 8 * d_bytes * f_hz / (eta * d_cyc)

    check("R* (Mbit/s), eta=1, 240 MHz", r_star(1.0, 240e6) / 1e6, 0.29, 0.005)
    band = [r_star(e, f) / 1e6 for e in (0.3, 1.0) for f in (80e6, 160e6, 240e6)]
    check("R* band low (Mbit/s), eta=1, 80 MHz", min(band), 0.10, 0.005)
    check("R* band high (Mbit/s), eta=0.3, 240 MHz", max(band), 0.97, 0.005)

    print("\n== Transfer to hybrid X25519MLKEM768 key shares ==")
    extra = (1184 + 32 - 800) + (1088 + 32 - 768)
    check("extra bytes per handshake", extra, 768, 0)
    pq = [totals[c, m] for c in (D, F) for m in ("server-only", "mutual")]
    check("min extra share (%)", 100 * extra / max(pq), 3.1, 0.05)
    check("max extra share (%)", 100 * extra / min(pq), 10.7, 0.05)

    print()
    if failures:
        print(f"{len(failures)} value(s) do not match: {failures}")
        return 1
    print("All derived values match.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
