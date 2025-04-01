KEM Combiners
=============

A lot of the options CFRG is considering seem similar.  This repo is to get a
feel for how big the differences are for some of the known contenders, and a few
of my own devising.

## Benchmarks with ML-KEM on my MacBook Pro (2021, M1 Pro)

| Scheme            | Raw       | Encap     | Decap     |
|-------------------|-----------|-----------|-----------|
| KitchenSink       | 3.9808 µs | 83.392 µs | 79.676 µs |
| Chempat           | 4.2159 µs | 83.782 µs | 79.072 µs |
| DHKEM             | 4.2104 µs | 83.138 µs | 79.057 µs |
| XWing             | 238.76 ns | 79.485 µs | 74.618 µs |
| DHKEM (half)      | 459.53 ns | 79.718 µs | 75.484 µs |
| KitchenSink (pre) | 2.2274 µs | 81.564 µs | 76.077 µs |
| Chempat (pre)     | 2.2114 µs | 80.783 µs | 76.148 µs |
| DHKEM (pre)       | 2.4736 µs | 81.156 µs | 77.226 µs |

In other words:
* None of the hash-in-everything variants are statistically different.
* XWing looks ~5% faster than the hash-in-everything variants.
* Re-arranging XWing to look more like DHKEM(X25519) + ML-KEM doesn't hurt
  performance much.
* Chempat in its optimal configuration (with the encapsulation keys pre-hashed)
  is no better than KitchenSink with the keys at the front (so that pre-warmed
  hash state can be re-used).
* The pre-warmed variants are only ~3% faster than the just-hash-it variants,
  with ML-KEM encap.

## Benchmarks with Classic McEliece on my MacBook Pro (2021, M1 Pro)

| Scheme            | Raw       | Encap     | Decap     |
|-------------------|-----------|-----------|-----------|
| KitchenSink       | 1.6798 ms | 1.8242 ms | 63.926 ms |
| Chempat           | 1.6788 ms | 1.8434 ms | 64.067 ms |
| DHKEM             | 1.6904 ms | 1.8296 ms | 64.059 ms |
| XWing             | 237.94 ns | 145.24 µs | 62.207 ms |
| DHKEM (half)      | 460.10 ns | 145.50 µs | 62.613 ms |
| KitchenSink (pre) | 681.72 ns | 145.49 µs | 62.233 ms |
| Chempat (pre)     | 679.90 ns | 145.75 µs | 62.323 ms |
| DHKEM (pre)       | 1.1589 µs | 146.01 µs | 62.233 ms |

In other words:
* Holy cow, these numbers are terrible!
* However, pre-hashing the public keys does speed up encapsulation by about an
  order of magnitude.
* One pre-hashing scheme is as good as another.
