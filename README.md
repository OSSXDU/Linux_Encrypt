# Linux文件加密技术研究与实现

##  使用 LUKS 加密块设备

### 概述

> 通过使用磁盘加密，您可以通过对其进行加密来保护块设备上的数据。要访问设备的解密内容，请输入密码短语或密钥作为验证。这对移动计算机和可移动介质非常重要，因为它有助于保护设备的内容，即使它在物理已从系统中移除。

Linux Unified Key Setup-on-disk-format (LUKS)提供了一组简化管理加密设备的工具。它作为一种加密规范具有以下特点：

- 支持多密码对同一个设备的访问
- 加密密钥不依赖密码
- 可以改变密码而无需重新加密数据
- 采用一种数据分割技术来保存加密密钥，保证密钥的安全性

### 加密原理

LUKS 使用的默认密码是 `aes-xts-plain64`。LUKS 的默认密钥大小为 512 字节。**Anaconda** XTS 模式的 LUKS 的默认密钥大小为 512 位。以下是可用的密码：

- 高级加密标准(AES)
- Twofish
- Serpent

LUKS 执行以下操作

- LUKS 对整个块设备进行加密，因此非常适合保护移动设备的内容，如可移动存储介质或笔记本电脑磁盘驱动器。
- 加密块设备的底层内容是任意的，这有助于加密交换设备。对于将特殊格式化块设备用于数据存储的某些数据库，这也很有用。
- LUKS 使用现有的设备映射器内核子系统。
- LUKS 增强了密码短语，防止字典攻击。
- LUKS 设备包含多个密钥插槽，其允许用户添加备份密钥或密码短语。

### 技术实现





### 复现和部署





### 参考文献

[1] https://wiki.archlinux.org/title/Data-at-rest_encryption

[2] https://gitlab.com/cryptsetup/cryptsetup/-/wikis/FrequentlyAskedQuestions#6-backup-and-data-recovery
