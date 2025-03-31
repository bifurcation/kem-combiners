KEM Combiners
=============

A lot of the options CFRG is considering seem similar.  This repo is to get a
feel for how big the differences are for some of the known contenders, and a few
of my own devising.

## Benchmarks on my MacBook Pro (2021, M1 Pro)

| Scheme        | Raw       | Encap     | Decap     |
|---------------|-----------|-----------|-----------|
| KitchenSink   | 3.9808 µs | 83.392 µs | 79.676 µs |
| Chempat       | 4.2159 µs | 83.782 µs | 79.072 µs |
| DHKEM         | 4.2104 µs | 83.138 µs | 79.057 µs |
| XWing         | 238.76 ns | 79.485 µs | 74.618 µs |
| DHKEM (half)  | 459.53 ns | 79.718 µs | 75.484 µs |

In other words:
* None of the hash-in-everything variants are statistically different.
* XWing looks about 5% faster than the hash-in-everything variants.
* Re-arranging XWing to look more like DHKEM(X25519) + ML-KEM doesn't hurt
  performance.
