# Mental Poker

## Introduction

The library implements the mental poker protocol described in [Mental Poker Revisited](https://www.semanticscholar.org/paper/Mental-Poker-Revisited-Barnett-Smart/8aaa1245c5876c78564c3f2df36ca615686d1402).

The protocol depends on an elliptic curve, without further requirements such as high 2-adicity of its scalar field or being pairing-friendly. This allows it to run in diverse environments, such as L2s and SNARKs.

A series of posts explaining the protocol and our approach to implementing it are available in the [Geometry Notebook](https://geometryresearch.xyz/notebook). [Part 1](https://geometryresearch.xyz/notebook/mental-poker-in-the-age-of-snarks-part-1) covers the protocol and primitives from a high level, [Part 2](https://geometryresearch.xyz/notebook/mental-poker-in-the-age-of-snarks-part-2) goes into some of the math.


## Matchbox collaboration

This library is developed as part of the collaboration between Geometry and Matchbox, and is designated as Geometry - MatchBox Proof 1. 

## Running the example

An example showing how to encode, hide, shuffle and distribute cards is provided under [`mental-poker/barnett-smart-card-protocol/examples/round.rs`](https://github.com/geometryresearch/mental-poker/blob/main/barnett-smart-card-protocol/examples/round.rs). Run the example by running:

```
cargo run --example round
```

## License

&copy; 2022 [Geometry](https://geometryresearch.xyz).

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

The [SPDX](https://spdx.dev) license identifier for this project is `MIT OR Apache-2.0`.
