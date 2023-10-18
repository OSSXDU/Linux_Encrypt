## 简介

Enterprise Cryptographic Filesystem 企业级加密文件系统

文件系统级加密

- 优点
    - 灵活性：可直接在已存在的分区中工作，不需要划开特定区域来使用；不同文件可以使用不同的加密算法，只有被成功解密的文件才能在挂载点被访问
    - 细粒度：可加密指定目录或文件
    - 透明性：不需要手动加解密文件
    - 隔离性：不同用户可以拥有自己的加密目录
- 缺点
    - 无法加密整个磁盘或分区
    - 性能开销更大

## 使用方法

### 安装

``` Bash
sudo apt install ecryptfs-utils
```

### 加密指定目录

首先创建两个目录

- `my_cryptfs`：加密目录
- `mount_cryptfs`：挂载点

#### 挂载

``` Bash
sudo mount -t ecryptfs my_cryptfs mount_cryptfs
```

第一次挂载会添加签名

每次挂载需要选择

- 密钥类型
- 加密算法
- 加密分组大小
- 是否通过挂载点访问未加密文件
    - 仅在不加密文件名时有效
    - 可能降低数据安全性
- 是否加密文件名
    - 关闭时只加解密文件内容

挂载后，对文件进行透明加密和解密

#### 卸载

``` Bash
sudo umount mount_cryptfs
```

### 加密默认目录

- 挂载点：`~/Private`
- 加密目录：`~/.Private`

- `ecryptfs-setup-private`：初始化，创建密钥及相应文件
- `ecryptfs-mount-private`：挂载
- `ecryptfs-umount-private`：卸载

## 原理

eCryptfs 位于 VFS 之下，其他文件系统（ext3、ext4 等）之上

1. 用户对文件的读写操作通过 VFS 转发给 eCryptfs
2. eCryptfs 从底层文件系统读取文件的密文
3. 然后调用内核 Crypto API 进行解密操作，获取对应明文放入缓存页中
4. 将修改后的明文再调用内核 Crypto API 进行加密生成密文，写入底层文件系统

![](attachments/Pasted%20image%2020231016200028.png)

### 文件的加密

eCryptfs 使用对称密码算法加密文件名和文件内容，一个文件对应一个加密密钥，称为文件加密密钥（FEK i.e. File Encryption Key），FEK 为随机生成的密钥

eCryptfs 将文件内容分成多个块进行加解密，称为 extent，大小默认为页的大小（4 KB）

#### 加密文件存储格式

- 头部元数据 Metadata
    - 标志位
    - EFEK
    - extent 大小
    - 文件大小等
- 若干加密内容 Encrypted Data Extent

### FEK 的加密

eCryptfs 使用用户的口令（Passphrase）、公钥密码算法（RSA 等）或 TPM 的公钥来加密保护 FEK

加密后的 FEK 称为 EFEK（Encrypted File Encryption Key），用户的口令或公钥称为 FEKEK（File Encryption Key Encryption Key）

### 读写文件流程

![](attachments/Pasted%20image%2020231016165341.png)

- 打开文件
    - 从加密文件的头部中取出 EFEK，解密获得 FEK 保存在 `ecryptfs_crypt_stat` 结构体中
    - 初始化 `ecryptfs_crypt_stat` 结构体，以便后续读写文件进行加解密操作
- 读文件
    - 从 `ecryptfs_crypt_stat` 结构体获取签名、FEK、加密算法等信息
    - 从底层文件系统读取文件内容，经过 FEK 解密，放入缓存页中
- 写文件
    - 从 `ecryptfs_crypt_stat` 结构体获取签名、FEK、加密算法等信息
    - 将写入的内容写入缓存页中，经过 FEK 加密，写入底层文件系统

## 参考文献

[eCryptfs: A Stacked Cryptographic Filesystem](http://dubeyko.com/development/FileSystems/eCryptfs/ecryptfs-article.pdf)

[eCryptfs: An Enterprise-class Cryptographic Filesystem for Linux](https://ecryptfs.sourceforge.net/ecryptfs.pdf)

[深入理解Linux加密文件系统（eCryptfs）](https://zhuanlan.zhihu.com/p/539350620)