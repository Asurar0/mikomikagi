Mikomikagi (見込み鍵) is a post-quantum cryptographic tool that provides digital signature and asymmetric encryption. It is designed to 
serve a similar purpose as GPG, but with a focus on using cryptographic keys as a means of digital identity, rather than being tied 
to a specific communication paradigm (like E-mail).

You can use Mikomikagi to:
- Publish your identity and associated contact information (e.g., email addresses, Discord IDs, Matrix handles) under your public key.
- Sign messages with your private key.
- Encrypt messages with the public subkeys of other users.

## Why

This software has initially been written with the objective of improving the cryptographic requirements for spontaneous sensitive communications, 
particularly in scenarios where vulnerabilities are disclosed through insecure channels (e.g., email, Discord, IRC). Additionally, the 
goal was to facilitate the integration of various communication methods under a unified public key framework, which is a limitation 
inherent to GPG, which only emphasizes on email addresses. GPG is also very slow (per the RFC process and fair codebase considerations) at adopting new cryptographic
standards.

## Features

* Post-quantum digital signature and key encapsulation mechanism based encryption
* Written in Rust
* Secure deallocation through zeroization
* Configurable keyring paths, allowing for multiple keyring instances for different purposes
* A Trait based design that facilitates easy extension to other databases and schemes
* A user-friendly interface with support for UTF-8 encoding.

## Implementation

Digital signature algorithm (DSA):
- SPHINCS+SHA2-128s
- SPHINCS+SHA2-256s
- Dilithium-3
- Dilithium-5
- Falcon1024

Key encapsulation mechanism (KEM):
- Kyber768
- Kyber1024

## Security

This software has not been reviewed or audited by any third-parties. The cryptographic implementation comes from 
the PQClean project. Any third-party watching this repository is welcome to reviewing and discuss findings in the 
Issue section or report vulnerabilities using github security panel. 

## Code structure

The following dependency hierarchy is used in this code:

```
models -> schemes -> keyring -> lib -> bin
                                        ^
                                       tui
```

The `models` crate defines general-purpose structures that are serialized and deserialized between users. These structures are considered standard in the context of Mikomikagi.
The `schemes` crate defines cryptographic schemes for signature and encryption, along with methods for converting them to and from the `models` structures.
The `keyring` crate defines the database for storing keys and its API, which includes operations such as insertion, removal, and update.
The `lib` crate provides typed builders for common operations, including signing, verification, import, and export.
The `bin` folder contains the actual binary that users are likely to use.
The `tui` crate is a collection of utilities for terminal interfaces.

## License

This software is distributed under the MIT License.