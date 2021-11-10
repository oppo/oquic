# Intel® QuickAssist Technology(QAT) BoringSSL* Library
Intel® QuickAssist Technology BoringSSL* Library is a prototype accelerating asymmetric cryptographic algorithms for BoringSSL*, the Google*'s OpenSSL* fork which doesn't support engine mechanism. It checks the type of user input SSL library during configuration time and builds out a traditional engine library if OpenSSL* is detected or a library fitting in with BoringSSL* private key method if BoringSSL* is applied.

This document details the capabilities, interfaces and limitations of the BoringSSL* based library. Both the hardware and software requirements are explained followed by detailed instructions on how to install and use the library. 
## Licensing
The Licensing of the files within this project is split as follows:

| Component |License |Details |
|---|---|---|
| Intel® QuickAssist Technology(QAT) OpenSSL* Engine | BSD License |Intel® QuickAssist Technology(QAT) OpenSSL* Engine - BSD License. This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/). Please see the LICENSE and LICENSE.OPENSSL file contained in the top-level folder. Further details can be found in the file headers of the relevant files. |
| Intel® QuickAssist Technology(QAT) BoringSSL* Library | BSD License |Intel® QuickAssist Technology(QAT) BoringSSL* Library - BSD License. This product includes software developed by the BoringSSL Project (https://boringssl.googlesource.com/boringssl/). Please see the LICENSE.BORINGSSL contained in the top-level folder. Further details can be found in the file headers of the relevant files. |
| Example Intel® QuickAssist Technology Driver Configuration Files contained within the folder hierarchy qat | Dual BSD/GPLv2 License | Please see the file headers of the configuration files, and the full GPLv2 license contained in the file LICENSE.GPL within the qat folder. |

## Features
  - Synchronous PKE Acceleration  
    - RSA Support for Key Sizes 1024/2048/4096.

  Note: RSA Padding schemes are handled by BoringSSL* rather than accelerated, so the engine supports the same padding schemes as BoringSSL* does natively.

## Limitations
  - Only synchronous RSA1K/2K/4K offloading supported in this version.

## Hardware Requirements
  This Intel® QAT BoringSSL* Engine supports crypto Hardware acceleration to the following acceleration devices:
  - [Intel® Xeon® with Intel® C62X Series Chipset](https://www.intel.com/content/www/us/en/design/products-and-solutions/processors-and-chipsets/purley/intel-xeon-scalable-processors.html)

## Software Requirements
  Successful operation of QAT Hardware acceleration requires a software tool chain that supports BoringSSL* and Intel® QuickAssist Technology Driver for Linux. This release was validated on the following:
  - Operating system: CentOS* 7.5 64-bit version
  - Kernel: GNU*/Linux* 3.10.0-1160.31.1.el7.x86_64
  - Intel® Communications Chipset C62X Series Software for Linux*, version 4.14
  - BoringSSL* 5e7229488844e987207b377968b3cf0340bc4ccf

## Installation Instructions
  The installation is consistent with the traditional procedure defined in https://github.com/intel/QAT_Engine#installation-instructions
  - Install Prerequisites  
    Same as the 'qat_hw Prerequisites' section defined in [general installation instructions](https://github.com/intel/QAT_Engine#installation-instructions)

  - Install BoringSSL  
      Clone BoringSSL* from Github* at the following location:  
      ```bash
      git clone https://github.com/google/boringssl.git
      ```
    
      Navigate to BoringSSL directory:  
      ```bash
      cd <path/to/boringssl/source/code>
      mkdir -p build 
      cd build/
      ```
    
    Note: BoringSSL* builds static library by default. To align with the QAT_Engine use case within NGINX*, an explicit option is added to build it as a dynamic library.
      ```bash
      cmake .. -DBUILD_SHARED_LIBS=1
      make
      ```
    
    BoringSSL* doesn't support "make install" to consolidate build output to an appropriate location. Here is a solution to integrate all output libraries into one customized path 'lib' by symbol links.
      ```bash
      cd .. 
      mkdir -p lib 
      ln -sf $(pwd)/build/libboringssl_gtest.so lib/ 
      ln -sf $(pwd)/build/crypto/libcrypto.so lib/ 
      ln -sf $(pwd)/build/decrepit/libdecrepit.so lib/ 
      ln -sf $(pwd)/build/ssl/libssl.so lib/ 
      ```
    
  - Build the Intel® QuickAssist Technology BoringSSL* Library  
      The prerequisite to run autogen.sh is to have autotools (autoconf, automake, libtool and pkg-config) installed in the system.  
      ```bash
      cd <path/to/qat_engine/source/code>
      ./autogen.sh
      ```
      Note: autogen.sh will regenerate autoconf tools files.
    
      &loz; qat_hw target with BoringSSL* built from source &loz;
    
      To build and install the Intel® QAT BoringSSL* Library:
      ```bash
      ./configure --with-openssl_install_dir=<path/to/boringssl/source/code> --with-qat_hw_dir=<path/to/qat/driver> 
      make
      make install
      ```
      By here, the QAT BoringSSL* Library 'libqatengine.so' is installed to <path/to/boringssl/source/code>/lib/.

## Legal
Intel, Intel Atom, and Xeon are trademarks of Intel Corporation in the U.S. and/or other countries.  
*Other names and brands may be claimed as the property of others.  
Copyright © 2016-2021, Intel Corporation. All rights reserved.