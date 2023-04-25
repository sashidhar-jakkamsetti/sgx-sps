# Scalable Private Signaling

This repository contains the proof-of-concept implementation of Scalable Private Signalling. It is an improved version of [Private Signalling](https://www.usenix.org/system/files/sec22-madathil.pdf) that builds on private database based on PathORAM and Trusted Execution Environment (TEE). Experimental results show that our server implementation takes < 6 milliseconds to process a sent signal, and < 200 milliseconds to process a retrieval (of 100 signals) request from a recipient. 

## Directory Structure

    sgx-ps
    ├── app               (Prototype entry; contains recipient, test, and experimentation code)
    │   ├── crypto        (Cryptographic wrapper using OpenSSL for recipient communication)
    │   └── storage       (Untrusted storage handler used by the enclave; invoked by the ocalls)
    ├── enclave           (Enclave entry points via ecalls; the core logic for private signaling is implemented here)
    │   ├── crypto        (Cryptographic wrapper using OpenSSL/SGXSSL for enclave communication)
    │   └── oram          (PathORAM implementation using Path Eviction scheme; uses ocalls to access untrusted memory)
    └── include           (Include files; design and test parameters; data structures used for communication)

## Environment and Language

Here we list out the environment (OS, processor) and programming language used at the time of development.

  - TEE: Intel SGXv1 
  - OS: Ubuntu 20.04 LTS
  - CPU hardware: Intel Xeon E-2288G hosted on Azure DC2s v2
  - Number of cores and RAM: 2 vCPUs and 8 GB RAM
  - Language: C++

## Dependencies

Before installing **sgx-ps**, ensure you have the following already installed on your Ubuntu machine:

  - Intel SGX Linux [Drivers](https://github.com/intel/linux-sgx-driver)
  - Intel SGX Linux [SDK](https://github.com/intel/linux-sgx)
  - OpenSSL 1.1.1t [Package](https://learnubuntu.com/install-openssl/)
  - Intel SGX SSL [Library](https://github.com/intel/intel-sgx-ssl)


## Installation
Install **sgx-ps** as follows:

  - Source the Intel SGX SDK as described [here](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1); if your SDK installation path is `/opt/intel/sgxsdk/`, run:
```
$ source /opt/intel/sgxsdk/environment
```

  - Download and build the source code:
```
$ cd sgx-ps
$ make
```

To clean the build files, use `make clean`.

## Run test case
To run the provided sample test case, cd to this repository and run:
```
$ make
$ ./ps
```

To run it in hardware mode on SGX-enabled CPUs use the flag `SGX_MODE=HW`:
```
$ make SGX_MODE=HW
$ ./ps
```

## Run experiments
To run experiments, modify the function `experiment` in `./app/test.c` according to your desired parameters and do the following:

```
$ make clean
$ make
$ ./ps -e experiment-results.txt
```

This should generate a file `./experiment-results.txt` with the results.

To run it in hardware mode on SGX-enabled CPUs use the flag `SGX_MODE=HW`:

```
$ make clean
$ make SGX_MODE=HW
$ ./ps -e experiment-results.txt
```
