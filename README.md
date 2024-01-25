# Lydia

![Static Badge](https://img.shields.io/badge/license-apache-blue)
![Static Badge](https://img.shields.io/badge/language-rust-red)

An Attacker Contract Identification Tool Implemented in Rust based on BlockWatchdog.

## Quick Start

### Rust Environment

Before running Lydia, you need to have the Rust environment set up.

### Gigahorse Environment

Lydia requires Gigahorse to be set up for analyzing Ethereum bytecode. To set up Gigahorse, refer to its [repository](https://github.com/nevillegrech/gigahorse-toolchain)

## Run

### Local

To run Lydia locally, use the following command:

```shell
RUST_LOG=info cargo run -- ETH 0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8
```

Replace the address of the contract you want to analyze. Contracts on other platforms (e.g., BSC) are also supported.

### Docker

To build and run Lydia using Docker, use the following commands:

```shell
docker build -t lydia:v1.0 .
```

Run with the following command:

```shell
docker run lydia:v1.0 ETH 0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8
```

## Publication

Based on _*BlockWatchdog*_, the ICSE'24 paper: Uncover the Premeditated Attacks: Detecting Exploitable Reentrancy Vulnerabilities by Identifying Attacker Contracts.
