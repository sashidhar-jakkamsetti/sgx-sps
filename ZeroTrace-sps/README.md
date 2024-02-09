# Efficient Private Signaling

This repository contains the proof-of-concept implementation of Scalable Private Signaling.
It uses PathORAM and Trusted Execution Environments.
Experimental results show that our server implementation takes < 70 milliseconds to process a sent signal, and < 6 seconds to process a retrieval (of 100 signals) request from a recipient.  

This repo is built atop ZeroTrace ([paper](https://eprint.iacr.org/2017/549.pdf), [repo](https://github.com/sshsshy/ZeroTrace/tree/master)) -- a side-channel resistant ORAM library for Intel SGX.

## Directory Structure

    ZeroTrace-sps
    ├── psapp               (Prototype entry; contains recipient, test, and experimentation code.)
    ├── ZT_Enclave          (Enclave codebase including SPS functionality and ZT ORAM implementation.)
    │   └── ZT_Enclave.cpp  (Core logic for SPS enclave is implemented in this file starting from line 770.)
    └── ZT_Untrusted        (Untrusted driver interface for communicating with ZT_Enclave.)
        └── App.cpp         (Core logic for SPS interface for SPS enclave is implemented in this file starting from line 966.)

## Environment and Language

Here we list out the environment (OS, processor) and programming language used at the time of development.

  - TEE: Intel SGXv1 
  - OS: Ubuntu 20.04 LTS
  - CPU hardware: Intel Xeon E-2288G hosted on Azure DC2s v2
  - Number of cores and RAM: 2 vCPUs and 8 GB RAM
  - Language: C++

## Dependencies

Before installing **ZeroTrace-ps**, ensure you have the following already installed on your Ubuntu machine:

  - Intel SGX Linux [Drivers](https://github.com/intel/linux-sgx-driver)
  - Intel SGX Linux [SDK](https://github.com/intel/linux-sgx)
  - OpenSSL 1.1.1t [Package](https://learnubuntu.com/install-openssl/)
  - Intel SGX SSL [Library](https://github.com/intel/intel-sgx-ssl)


## Installation
Install **ZeroTrace-sps** as follows:

  - Source the Intel SGX SDK as described [here](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1); if your SDK installation path is `/opt/intel/sgxsdk/`, run:
```
$ source /opt/intel/sgxsdk/environment
```

  - Download and build the source code:
```
$ cd ZeroTrace-sps
$ make
```

To clean the build files, use `make clean`.

## Run test case
To run the provided sample test case, cd to this repository and run:
```
$ make SGX_MODE=SIM
$ psapp/psapp
```

To run it in hardware mode on SGX-enabled CPUs use the flag `SGX_MODE=HW`:
```
$ make
$ psapp/psapp
```

## Run experiments
To run experiments, modify the function `experiment` in `./psapp/app.c` according to your desired parameters and do the following:

```
$ make clean
$ make SGX_MODE=SIM
$ psapp/psapp -e experiment-results.txt
```

This should generate a file `./experiment-results.txt` with the results.

To run it in hardware mode on SGX-enabled CPUs use the flag `SGX_MODE=HW`:

```
$ make clean
$ make
$ psapp/psapp -e experiment-results.txt
```