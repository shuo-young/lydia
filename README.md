<!-- <h1 align="center">Welcome to NFTDefects 👋</h1> -->
<p>
  <img alt="Static Badge" src="https://img.shields.io/badge/rust-1.75.0-blue">
  <img alt="Static Badge" src="https://img.shields.io/badge/ubuntu-20.04-yellow">
  <img alt="Static Badge" src="https://img.shields.io/badge/docker-v0.2-purple">
  <a href="doc url" target="_blank">
    <img alt="Documentation" src="https://img.shields.io/badge/documentation-yes-brightgreen.svg" />
  </a>
  <a href="LICSEN" target="_blank">
    <img alt="License: Apache" src="https://img.shields.io/badge/License-Apache-yellow.svg" />
  </a>
  <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/shuo-young/lydia/publish-docker-image.yml">
</p>

<br />
<div align="center">
  <a href="https://github.com/shuo-young/lydia">
    <img src="logo.png" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">Lydia</h3>

</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Prerequisites</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#install">Install</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
      <ul>
        <li><a href="#local">Local</a></li>
        <li><a href="#docker">Docker</a></li>
      </ul>
    </li>
    <!-- <li><a href="#code-structure">Code Structure</a></li> -->
    <li><a href="#features">Features</a></li>
    <!-- <li><a href="#publication">Publication</a></li> -->
    <li><a href="#license">License</a></li>

  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

An Attacker Contract Identification Tool Implemented in Rust based on [BlockWatchdog](https://github.com/shuo-young/BlockWatchdog).

<!-- [![Product Name Screen Shot][product-screenshot]](https://example.com) -->
<!-- <p align="right">(<a href="#readme-top">back to top</a>)</p> -->

## Prerequisites

-   rust toolchain

    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

-   gigahorse-toolchain

    Lydia requires Gigahorse (commit da473f3) to be set up for analyzing EVM bytecode. To set up Gigahorse, refer to its [repository](https://github.com/nevillegrech/gigahorse-toolchain).

<!-- <img align="left" width="213" src="logo.png"> -->

## Install

1. Rust build locally.

```sh
cargo build --release
```

2. Or you can build or pull the docker image.

```sh
docker build -t lydia:local .
docker pull ghcr.io/shuo-young/lydia:latest
```

## Usage

### Local

```sh
RUST_LOG=info cargo run -- -b ETH -l 0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8
# or use build bin
./target/release/lydia -b ETH -l 0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8
```

### Docker

For the docker image, run with the following command.

```sh
docker run ghcr.io/shuo-young/lydia:latest -b ETH -l 0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8
```

## Features

> more faster for identifying attackers and contracts with malicious intentions

-   Recover all possible call chains in attacker contract (each public function).
-   Report critical attack semantic, e.g., call in hook functions, selfdestruct, use randomnumer, creation (sole and multi) etc.
-   Locating call sites that could perform reentrancy and possible reentrancy targets.

## License

Copyright © 2024 [Shuo Yang](https://github.com/shuo-young).<br />
This project is [Apache](https://github.com/shuo-young/lydia/blob/master/LICENSE) licensed.
