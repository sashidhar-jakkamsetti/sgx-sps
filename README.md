# Scalable Private Signaling

This repository contains the proof-of-concept implementation of Scalable Private Signaling (SPS) using PathORAM and Trusted Execution Environment (TEE).
It contains two prototypes: 
- `ZeroTrace-sps` - SPS prototype that is side-channel resistant, built using [ZeroTrace library](https://github.com/sshsshy/ZeroTrace/tree/master)
- `sgx-ps` - SPS prototype that is not side-channel resistant but faster and optimized.

## Environment and Language

Here we list out the environment (OS, processor) and programming language used at the time of development.

  - TEE: Intel SGXv1 
  - OS: Ubuntu 20.04 LTS
  - CPU hardware: Intel Xeon E-2288G hosted on Azure DC2s v2
  - Number of cores and RAM: 2 vCPUs and 8 GB RAM
  - Language: C++

## Dependencies

Before installing **sgx-sps**, ensure you have the following already installed on your Ubuntu machine:

  - Intel SGX Linux [Drivers](https://github.com/intel/linux-sgx-driver)
  - Intel SGX Linux [SDK](https://github.com/intel/linux-sgx)
  - OpenSSL 1.1.1t [Package](https://learnubuntu.com/install-openssl/)
  - Intel SGX SSL [Library](https://github.com/intel/intel-sgx-ssl)


## Installation

Go to the respective README.md files in each folder to install and run them.
