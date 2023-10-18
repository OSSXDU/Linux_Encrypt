# Linux文件加密技术研究与实现
![image](https://github.com/OSSXDU/Linux_Encrypt/assets/70969752/8083a40e-9187-46a0-be44-57041af9bbaa)

## eCryptfs

**简介**

eCryptfs（enterprise Cryptographic Filesystem）是一个用于Linux系统的加密文件系统，它提供了一种在文件级别对数据进行透明加密的方法。eCryptfs允许用户将特定目录下的文件和文件夹进行加密，从而保护敏感数据。

**特点**

- **透明性**：eCryptfs可以在不影响用户体验的情况下进行加密和解密操作，用户可以像使用普通文件系统一样使用它。
- **目录级别加密**：eCryptfs允许用户选择性地对特定目录进行加密，这使得用户可以根据需要选择保护哪些数据。
- **动态扩展**：eCryptfs可以动态调整存储空间，使得加密后的文件系统可以随着数据的增长而扩展。

**使用场景**

eCryptfs常用于保护用户的个人数据，例如家目录、私密文档等。它也可以在企业环境中用于保护敏感数据，确保数据不被未授权访问。

**[调研介绍](https://github.com/OSSXDU/Linux_Encrypt/blob/main/eCryptfs.md#简介)**

## LUKS

**简介**

LUKS（Linux Unified Key Setup）是一个用于Linux系统的磁盘加密规范，它提供了对整个磁盘或者分区进行加密的方法。通过使用LUKS，用户可以创建一个加密容器，将整个文件系统存储在其中。

**特点**

- **全磁盘加密**：LUKS允许用户对整个磁盘进行加密，从而保护所有存储在其中的数据。
- **灵活的密钥管理**：LUKS支持多种密钥管理方案，包括密码、密钥文件等，使得用户可以选择最适合自己需求的方式来保护数据。
- **用户友好**：LUKS提供了一组工具，使得用户可以方便地创建、管理和访问加密容器。

**使用场景**

LUKS通常用于对整个系统的磁盘进行加密，以保护所有存储在其中的数据，包括操作系统和用户文件。

**[调研介绍](https://github.com/OSSXDU/Linux_Encrypt/blob/main/LUKS.md)**

## dm-crypt

**简介**

dm-crypt是Linux内核的一个模块，它提供了一个通用的块设备加密层。它可以用于对整个磁盘、分区或者卷进行加密，从而保护存储在其中的数据。

**特点**

- **通用性**：dm-crypt可以用于对任意块设备进行加密，包括硬盘、分区、卷等。
- **透明加密**：加密和解密操作对用户来说是透明的，用户可以像使用未加密设备一样使用加密设备。
- **与LUKS结合**：通常，dm-crypt与LUKS结合使用，以提供完整的加密解决方案。

**使用场景**

dm-crypt通常用于对整个磁盘或者分区进行加密，它也可以与LUKS结合使用以提供更高级的加密功能。

**[调研介绍](https://github.com/OSSXDU/Linux_Encrypt/blob/main/tracknote.md#dm-crypt)**

