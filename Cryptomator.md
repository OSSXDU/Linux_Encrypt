# 使用 Cryptomator 实现云同步端到端加密

## 简介

Cryptomator是为解决在将文件保存到云存储时可能出现的隐私问题而设计的，是一款开源的，安全的，没有后门的文件加密软件，可以轻松的对文件进行加解密，并在锁定文件目录后，自动退出文件目录，不留“痕迹”。

Cryptomator可以有效缓解云提供商或第三方未经许可访问云中存储的数据的风险。只有知道保险库密码的人才能读取库中的文件或在不被察觉的情况下更改文件内容。这对文件内容和文件名都是适用的。



**特点**

- 与 Dropbox、Google Drive、OneDrive、百度网盘、阿里云盘、坚果云和任何其他与本地目录同步的云存储服务一起使用
- 客户端：没有账户，没有与任何在线服务共享的数据
- 完全透明：只需在虚拟驱动器上工作，就像是 usb 闪存一样
- 256 位密钥长度的 AES 加密
- 文件名被加密
- 在你的 Dropbox 中使用任意数量的储藏室，每个储藏室都有单独的密码
- 4000 次提交数据的安全性



**注意事项**

为了允许与云的有效同步，Cryptomator不加密一些metadata。这些元信息包括：

- 文件和文件夹的访问、修改和创建时间戳，
- 保险库和文件夹中的文件和文件夹数量，
- 存储文件的大小。

这意味着Cryptomator并不适用于纯本地加密。

如果在处理加密文件时创建了备份副本，Cryptomator本身无法检测这些备份文件。Cryptomator只关注对库中文件的加密和解密，对于文件的备份不提供直接的监测或管理。

Cryptomator的密码是存在本地的。Cryptomator使用在创建保险库（vault）时设置的密码来加密和解密文件。



## 加密架构

### 虚拟文件系统

Cryptomator提供了一个虚拟磁盘驱动器,可以像在电脑上使用任何磁盘驱动器一样，直接添加、编辑、删除文件，而在Cryptomator每次都是加密这个驱动器内的文件，并且文件在保存时会被透明地加密和解密。这意味着在硬盘上不存在未加密的文件副本。每当我们访问虚拟磁盘内的文件时，Cryptomator 会即时对这些文件进行加密和解密。并且在不同操作系统上使用了不同的技术来实现用户态文件系统，在 Windows 上，Cryptomator 使用 WinFsp，在Linux系统上使用FUSE，而在macOS上使用macFUSE，这些技术实现了Cryptomator与操作系统的文件管理系统的集成，方便用户的操作。但是当上述的技术在相应的系统上不可用，那么前端处理系统将会回退到WebDAV协议。WebDAV 是一种基于 HTTP 的协议。在这种模式下，Cryptomator 作为一个 WebDAV 服务器，仅接受本地机器上的环回连接。

无论何时，当我们通过虚拟驱动访问文件时，Cryptomator 都会通过几层来处理这些请求，确保文件在存储时安全加密，并且在需要时被解密。

### 保险库配置信息

每个 Cryptomator 保险库都有一个名为 `vault.cryptomator` 的配置文件，位于保险库的根目录。此文件是一个包含有关保险库和使用密钥规范的基本信息的 JSON Web Token（JWT）。`JWT`使用512位的原始主密钥进行签名,以确保其真实性和完整性。

以下是一个编码的保险库配置文件示例：

```bash
eyJraWQiOiJtYXN0ZXJrZXlmaWxlOm1hc3RlcmtleS5jcnlwdG9tYXRvciIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiY2U5NzZmN2EtN2I5Mi00Y2MwLWI0YzEtYzc0YTZhYTE3Y2Y1IiwiY2lwaGVyQ29tYm8iOiJTSVZfQ1RSTUFDIn0.IJlu4dHb3fqB2fAk9lf8G8zyEXc7OLB-5m9aNxOEXIQ
```

这个编码文本是一个 JWT，解码后会显示关于保险库的重要信息，包括头部和有效载荷。

解码的头部(header)

```json
{
  "kid": "masterkeyfile:masterkey.cryptomator", /* 获取密钥的位置的URI */
  "typ": "JWT",
  "alg": "HS256" /* 当前实现还支持HS384和HS512 */
}
```

头部包括：

- `kid`：密钥 ID，这里指示了主密钥文件的位置（`URI`）。
- `typ`：令牌类型，即 JWT。
- `alg`：用于签名 JWT 的算法。当前实现支持 HS256、HS384 和 HS512。

其中`alg`的可选字段HS256、HS384和HS512都是HMAC（Hash-based Message Authentication Code）算法的变种，用于生成JWT（JSON Web Token）的签名。它们提供了不同级别的安全性，但通常我们使用HS256，因为其具有较高的性能，并且通常足够用于许多应用程序。

下面是这几种HMAC算法的主要特征的差异，我们可以根据需求选择相应的HMAC算法。

| 特征     | HS256             | HS384             | HS512             |
| -------- | ----------------- | ----------------- | ----------------- |
| 哈希算法 | SHA-256           | SHA-384           | SHA-512           |
| 签名长度 | 256比特（32字节） | 384比特（48字节） | 512比特（64字节） |
| 安全性   | 适度              | 高                | 最高              |
| 计算开销 | 适度              | 较高              | 最高              |

解码的payload:

```json
{
  "format": 8, /* 用于检查软件兼容性的保险库格式 */
  "shorteningThreshold": 220,
  "jti": "ce976f7a-7b92-4cc0-b4c1-c74a6aa17cf5", /* 用于唯一标识保险库的随机 UUID */
  "cipherCombo": "SIV_GCM" /* 块密码的操作模式。其他可能的值是 "SIV_CTRMAC" */
}
```

有效载荷包括：

- `format`：保险库格式号，重要的是软件兼容性。
- `shorteningThreshold`：在缩短之前，密文文件名中的最大字符数。

- `jti`：用于唯一标识保险库的随机 UUID。
- `cipherCombo`：块密码的操作模式，如 "SIV_GCM" 或 "SIV_CTRMAC"。



其中`shorteningThreshold`设置原理是确保加密文件名的长度在可接受范围内，以保证文件系统的兼容性和操作的顺畅。这涉及到文件名加密过程的一个特定步骤，具体来说：

1. **文件名加密**：当我们使用 Cryptomator 时，不仅文件内容会被加密，文件名也会被加密。这是为了保护文件的元数据，比如文件名，因为即使是文件名本身也可能包含敏感信息。
2. **加密后的文件名长度**：文件名在加密后通常会变得更长。这是因为加密过程通常会增加数据的长度，以确保安全性和加密算法的有效性。
3. **“缩短阈值”**（`shorteningThreshold`）：如果加密后的文件名长度超过缩短阈值，Cryptomator 将自动缩短这个文件名。这样做的目的是为了确保文件名不会因为过长而引起文件系统兼容性问题或其他操作问题。



再来讨论`cipherCombo`,这是一种块密码操作模式的设置，指定了Cryptomator在加密过程中所采用的具体加密方案。

**SIV_GCM（AES-GCM-SIV 同步化向量模式下的伽罗瓦/计数器模式）**:

- **SIV（Synthetic Initialization Vector）**：这是一种加密模式，用于生成一个不重复的初始化向量（IV）。在加密时，SIV 模式可以减少重复使用同一密钥和 IV 的风险，提高安全性。因此SIV 模式特别适合在需要抵抗重放攻击的场景中使用。
- **GCM（Galois/Counter Mode）**：这是一种流行的块密码加密模式，它结合了计数器模式（CTR）的高效性和伽罗瓦(Galois)模式的加密认证功能。GCM 模式不仅可以加密数据，还可以对数据的完整性进行验证，提供认证加密（AE）或认证加密与关联数据（AEAD）的功能

![Diagram of AES-GCM-SIV](./Cryptomator.assets/Diagram-of-AES-GCM-SIV-20.png)



**SIV_CTRMAC(同步化向量模式下的计数器模式与消息认证码)**:

- **SIV (Synthetic Initialization Vector):**
  - SIV 依然是块密码操作模式的一部分，用于增强安全性。
- **CTR（Counter）模式**：CTR模式是一种流加密模式，它将对称密钥加密算法转换为流密码。它通过将明文块与一个加密的计数器块进行异或操作来生成密文。CTR模式的优点是加密和解密操作可以并行处理，提高了效率。

![AES in CTR mode of operation](./Cryptomator.assets/AES-in-CTR-mode-of-operation.png)

- **MAC（Message Authentication Code）**：MAC是一种用于验证消息完整性和认证的技术。Cryptomator实现了消息认证码（MAC），具体而言是HMAC-SHA-256，可以检测数据是否被篡改。



打开Vault时，必须按照以下步骤进行：

1. **解码 `vault.cryptomator` 文件**：
   - 此步骤涉及读取 `vault.cryptomator` 文件的内容，通常这个文件是以 JSON Web Token（JWT）格式存储的。
   - 在这一阶段，文件内容被解码（从 Base64 或类似的编码格式转换回文本格式），但尚未进行真实性验证。这意味着系统只是读取文件内容，而不检查它是否未经篡改,也不验证其真实性。
2. **阅读 `kid` 头部**：
   - `kid`（Key ID）头部是 JWT 的一部分，它指示了主密钥文件的位置。这个信息对于后续的验证步骤至关重要。
   - 系统根据这个头部信息去检索主密钥。这个主密钥通常存储在用户的设备上，用于验证和加解密操作。
3. **验证 JWT 签名**：
   - 一旦主密钥被检索，系统就会用它来验证 JWT 的签名。
   - 这个步骤是为了确保 `vault.cryptomator` 文件是真实的，没有被篡改。签名验证确保了文件的完整性和来源的可靠性。
4. **检查兼容性**：
   - 最后，系统将确认文件中指定的 `format`（格式）和 `cipherCombo`（加密算法组合）是否由当前使用的 Cryptomator 软件支持。
   - 这一步骤确保了软件能够正确地处理和加解密保险库中的文件。

graph TD;
  A[开始] -->|解码 vault.cryptomator 而不进行验证| B;
  B[调用解码函数（不验证签名）] --> C[得到解码后的内容（Header, Payload）];
  C -->|读取 kid 头部| D[从解码后的内容中提取 kid 值];
  D -->|根据 kid 从指定位置检索主密钥| E[根据 kid 值构建密钥检索路径];
  E --> F[从指定路径检索主密钥];
  F -->|使用主密钥验证 JWT 签名| G[调用验证签名函数，传递主密钥];
  G --> H[检查签名的有效性];
  H -->|确保支持 format 和 cipherCombo| I[从解码后的内容中获取 format 和 cipherCombo 值];
  I --> J[检查系统是否支持指定的 format 和 cipherCombo];
  J --> K[结束];



### 主密钥派生

保护的下一层是由用户密码本身保护的主密钥。单独的加密文件具有自己的加密密钥，该密钥另外由主密钥保护。

每个 Cryptomator 保险库都有两个主密钥：一个是256位的加密主密钥（用于加密文件特定的密钥），另一个是 MAC 主密钥（用于文件身份认证）。

这些密钥是由**CSPRNG**(密码学安全的伪随机数生成器)生成的随机序列,使用的是Java类[SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html)的SHA1PRNG模式，并且该SecureRandom由 `SecureRandom.getInstanceStrong()` 提供的 440 位种子初始化。

两个密钥都使用 RFC 3394秘钥包装算法进行密钥包装,使用用户密码通过 密钥派生函数scrypt 算法派生的 KEK（密钥加密密钥）对主密钥进行加密。

密钥包装算法使用对称加密来封装（加密）用于加密或解密的主密钥，在存储加密技术中它们通常被广泛使用，因为它们提供了一个独特的功能。如果程序利用密钥包装功能，用户决定更改密码，只需重新封装主密钥。另一方面，如果程序不实现此功能，必须重新加密所有加密的数据，这可能非常低效。

```python
// 生成一个长度为32字节的随机数序列，作为加密主密钥
encryptionMasterKey := createRandomBytes(32)

// 生成一个长度为32字节的随机数序列，作为MAC主密钥
macMasterKey := createRandomBytes(32)

// 使用scrypt函数从用户提供的密码、盐、成本参数和块大小派生出密钥加密器（KEK）
kek := scrypt(password, scryptSalt, scryptCostParam, scryptBlockSize)

// 使用AES密钥包装（Wrap）加密主密钥，以便安全地存储
wrappedEncryptionMasterKey := aesKeyWrap(encryptionMasterKey, kek)

// 使用AES密钥包装（Wrap）MAC主密钥，以便安全地存储
wrappedMacMasterKey := aesKeyWrap(macMasterKey, kek)

```



![KEK Derivation](./Cryptomator.assets/key-derivation@2x.png)



然后，将封装的密钥和派生 KEK 所需的参数存储为整数或 Base64 编码的字符串，存储在名为 masterkey.cryptomator 的 JSON 文件中，该文件位于保险库的根目录中。

```json
{
    "version": 999, /* 不建议使用，现在保险库格式在保险库配置中指定 */
    "scryptSalt": "QGk...jY=",
    "scryptCostParam": 16384,
    "scryptBlockSize": 8,
    "primaryMasterKey": "QDi...Q==", /* wrappedEncryptionMasterKey */
    "hmacMasterKey": "L83...Q==", /* wrappedMacMasterKey */
    "versionMac": "3/U...9Q=" /* 防止未检测到的降级攻击的HMAC-256 */
}
```

### 主秘钥解密

解锁保管库时，KEK 用于解开（即解密）存储的主密钥。



​		<img src="./Cryptomator.assets/masterkey-decryption@2x.png" alt="Masterkey Decryption" style="zoom:80%;" />



```c
// 伪代码表示解锁Vault过程
// 从`masterkey.cryptomator`文件中读取存储的信息
scryptSalt = readFromFile("masterkey.cryptomator", "scryptSalt")
scryptCostParam = readFromFile("masterkey.cryptomator", "scryptCostParam")
scryptBlockSize = readFromFile("masterkey.cryptomator", "scryptBlockSize")
wrappedEncryptionMasterKey = readFromFile("masterkey.cryptomator", "primaryMasterKey")
wrappedMacMasterKey = readFromFile("masterkey.cryptomator", "hmacMasterKey")

// 用户提供的密码
password = getUserPassword()

// 使用scrypt函数从用户提供的密码、盐、成本参数和块大小中派生密钥加密器（KEK）
kek = scrypt(password, scryptSalt, scryptCostParam, scryptBlockSize)

// 使用AES密钥解封装（Unwrap）加密主密钥，得到原始的加密主密钥
encryptionMasterKey = aesKeyUnwrap(wrappedEncryptionMasterKey, kek)

// 使用AES密钥解封装（Unwrap）MAC主密钥，得到原始的MAC主密钥
macMasterKey = aesKeyUnwrap(wrappedMacMasterKey, kek)

// 现在，encryptionMasterKey和macMasterKey可以用于后续的加密和身份验证操作
```



### 文件头加密

这一部分适用于密文组合为 SIV_GCM 的保险库。文件头存储了用于文件内容加密的元数据，它由 68 字节组成。

组成部分：

- 12字节用于头有效负载加密的nonce。
- 40字节[AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)加密有效负载，包含了必要的元数据，如nonce和文件内容密钥
  - 8字节填充为1，供将来使用（先前用于文件大小）。
  - 32字节文件内容密钥。
- 16字节加密有效负载的标签,用于验证文件头的完整性和真实性,是 GCM 模式提供的附加安全特性。

```c
// 生成一个随机的12字节nonce，用于头有效负载的加密
headerNonce := createRandomBytes(12)

// 生成一个随机的32字节文件内容密钥
contentKey := createRandomBytes(32)

// 创建明文有效负载，将32字节文件内容密钥附加到0xFFFFFFFFFFFFFFFF
//这个填充数据原本用于存储文件大小，但现在已经被废弃，仅用于填充。
cleartextPayload := 0xFFFFFFFFFFFFFFFF . contentKey

// 使用AES-GCM算法对明文有效负载进行加密，得到密文有效负载和标签
ciphertextPayload, tag := aesGcm(cleartextPayload, encryptionMasterKey, headerNonce)

```

<img src="./Cryptomator.assets/file-header-encryption@2x.png" alt="File Header Encryption" style="zoom:80%;" />

### 文件内容加密

**目的：** 加密实际的文件内容。

明文会被分割为多个块(chunks),每个块最多32 KiB(32768 字节)加上额外的 28 字节,每个块包括：

- 12字节nonce：对于文件内容的加密，每个加密块（最大 32 KiB）都会使用一个新的、随机生成的 12 字节 nonce。这意味着每个块的加密都使用了不同的 nonce，增加了加密的安全性。即使同一数据在不同块中重复出现，由于使用了不同的 nonce，加密后的结果也会不同。
- 最多32 KiB使用文件内容密钥的AES-GCM加密的有效负载。
- 16字节标签，通过GCM计算，带有特定的附加认证数据（AAD）：
  - 块编号作为32位大端整数（防止未检测到的重新排序）。
  - 文件头nonce（将块与文件头绑定）。这是在加密文件头时使用的一个唯一 nonce（数字仅使用一次）。文件头包含特定的元数据，比如文件内容密钥。文件头 nonce 对于每个文件都是唯一的，并且在整个文件的加密过程中保持不变。

然后，加密的块按原文块的顺序连接。最后一个块的有效载荷可能小于 32 KiB。

```c
// 将明文数据分割成最大为32 KiB + 28字节的块
cleartextChunks[] := split(cleartext, 32KiB)

// 遍历每个明文块并加密
for (int i = 0; i < length(cleartextChunks); i++) {
    // 生成一个随机的12字节nonce，用于块的加密
    chunkNonce := createRandomBytes(12)

    // 准备附加认证数据（AAD）：使用大端序表示的块编号和文件头nonce
    aad := [bigEndian(i), headerNonce]

    // 使用AES-GCM算法对明文块进行加密，得到密文有效负载和标签
    ciphertextPayload, tag := aesGcm(cleartextChunks[i], contentKey, chunkNonce, aad)

    // 构建加密后的密文块，格式为 随机数 + 加密负载 + 标签
    ciphertextChunks[i] := chunkNonce . ciphertextPayload . tag
}

// 将所有密文块连接在一起，形成整个文件内容的密文
ciphertextFileContent := join(ciphertextChunks[])
```

上述伪代码描述了将明文文件内容分割成块，对每个块进行加密（包括生成随机数、计算标签等操作），然后按照原文块的顺序连接加密块。

```mermaid
graph TD
  A[开始] -->B[将明文文件内容分割成块]
  B -->C[初始化计数器 i=0]
  C -->D[循环: i < 块数量]
  D -->E[生成 12 字节的块随机数]
  E -->F[构建附加认证数据 AAD]
  F -->G[使用 AES-GCM 加密块]
  G -->H[构建加密块格式: 随机数 + 加密负载 + 标签]
  H -->I[存储加密块]
  I -->J[增加计数器 i]
  J -->C[循环结束条件]
  C -->K[连接所有加密块，保持原文块的顺序]
  K -->L[结束]
```

<img src="./Cryptomator.assets/file-content-encryption@2x.png" alt="File Content Encryption" style="zoom:67%;" />

### 目录标识符(Directory IDs)

**生成目录 ID**:

每个目录都有一个唯一的ID，在文件名加密时需要使用该ID。出于历史原因，目录ID是一个字符串，尽管任何字节序列都能完成任务。 

根目录的目录ID为空字符串。对于所有其他目录，它是一个最多包含36个ASCII字符的随机序列(通常建议使用随机 UUID 作为目录 ID)。 

```java
import java.util.UUID;

public class Main {
    public static void main(String[] args) {
        // 创建一个随机 UUID
        UUID uuid = UUID.randomUUID();
        // 将 UUID 转换为字符串
        String dirId = uuid.toString();
        // 打印 UUID
        System.out.println("UUID: " + dirId);
    }
}
```

在遍历目录时，给定子目录的目录标识符经过四个步骤处理，以确定在保险库内的存储路径：

1. **目录 ID 加密**:
   - 使用 AES-SIV（对称加密标准-同步化向量模式）加密目录 ID。这一步骤加密了目录层次结构。
   - 加密时使用加密主密钥和 MAC 主密钥。
2. **哈希处理**:
   - 对加密后的目录 ID 创建 SHA1 哈希，以获得统一长度的输出。
3. **Base32 编码**:
   - 将哈希值用 Base32 编码，以得到一串可打印字符。
4. **构建目录路径**:
   - 根据 Base32 编码的哈希构建存储在保险库中的目录路径。

```c#
dirIdHash := base32(sha1(aesSiv(dirId, null, encryptionMasterKey, macMasterKey)))
dirPath := vaultRoot + '/d/' + substr(dirIdHash, 0, 2) + '/' + substr(dirIdHash, 2, 30)
```

这个过程的最终结果是，无论明文路径的层次结构如何，加密后的目录始终以扁平化结构存储。这意味着在加密层面上，所有目录实际上都是同级的（或者更准确地说，是堂兄弟关系）。这种方法使得目录的加密管理变得更加高效，同时也增强了安全性，因为外部无法轻易推断出原始目录的层次结构。

我们可以通过下面的例子能够更直观看到Cryptomator 如何将加密后的目录以扁平化结构存储。

假设我们有以下的文件目录结构：

```bash
Documents/
├── Finance/
│   ├── invoices.pdf
│   └── report.docx
└── Personal/
    ├── diary.txt
    └── wishlist.txt
```

在这个例子中，`Documents` 是一个根目录，它包含两个子目录：`Finance` 和 `Personal`。每个子目录下又有一些文件。

当使用 Cryptomator 对这些目录和文件进行加密时，每个目录和文件都会被赋予一个唯一的加密标识符（例如，使用 UUID），然后这些标识符会被进一步加密和哈希处理。例如：

- `Documents/` → 加密 → `X3Jsd8JN...`（一个随机生成的 UUID）
- `Documents/Finance/` → 加密 → `U2FsdGVk...`
- `Documents/Personal/` → 加密 → `1aMjU2Mz...`

加密后的目录不再保留其原始的层次结构，而是存储在一个扁平化的结构中，例如：

```bash
/d/X3/...    (加密后的 Documents 目录)
/d/U2/...    (加密后的 Documents/Finance 目录)
/d/1a/...    (加密后的 Documents/Personal 目录)
```

在这个加密结构中，每个目录看起来都是在同一层级（即扁平化），使外部观察者无法确定原始的目录结构或其层次关系。这种存储方式使目录的加密管理更高效，并且因为外部无法轻易推断出原始目录的层次结构，因此增强了安全性。

### 文件名加密

**明文名称编码**：

文件的明文名称是在[Normalization Form C](https://unicode.org/reports/tr15/#Norm*Forms)中使用UTF-8进行编码，以获得唯一的二进制表示。



**使用 AES-SIV 加密文件名**：

Cryptomator使用[AES-SIV](https://tools.ietf.org/html/rfc5297)对名称进行加密。父文件夹的目录ID被传递为==关联数据==。这可以防止文件在目录之间被未检测到地移动。

在具体实现中，父文件夹的目录ID在AES-SIV加密算法中作为关联数据传递，以确保每个文件名都与其所属目录的特定信息相关联。这样做可以增加加密的安全性，防止攻击者试图通过将文件从一个目录移动到另一个目录来遍历加密。

假设有以下目录结构：

```
Vault Root
|-- Documents
|   |-- File1.txt
|   `-- File2.txt
`-- Photos
    |-- Pic1.jpg
    `-- Pic2.jpg
```

假设我们要加密 "File1.txt" 文件的文件名。在加密的过程中，父文件夹的目录ID会被传递为关联数据。

对于 "File1.txt" 文件，父文件夹是 "Documents"，而 "Documents" 的目录ID 是一个由系统生成的唯一标识符，比如一个随机的UUID。这个目录ID被传递给文件名加密算法作为关联数据。

在加密 "File1.txt" 文件名时，AES-SIV加密算法使用文件名、父文件夹的目录ID以及其他密钥材料来生成密文。

```c#
//将文件名编码为 UTF-8 且进行规范化处理
normalizedFilename := normalizeToUtf8(cleartextFilename)

//使用 AES-SIV 加密算法对文件名进行加密
//父目录的 ID 作为关联数据 (AAD) 传递给加密函数
encryptedFilename := aesSivEncrypt(normalizedFilename, parentDirId, encryptionMasterKey, macMasterKey)
```

这样，加密后的文件名不仅仅取决于文件名本身，还取决于它所在的目录。即使相同的文件名在不同的目录下也会产生不同的加密结果，这样可以增加安全性，防止攻击者通过检测文件名的移动来破解加密。



**生成加密名称文件**：

加密后的文件名被转换为 base64url 格式，并添加扩展名 `.c9r`。

```c#
ciphertextName := base64url(aesSiv(cleartextName, parentDirId, encryptionMasterKey, macMasterKey)) + '.c9r'
```

<img src="./Cryptomator.assets/filename-encryption@2x.png" alt="Filename Encryption" style="zoom:67%;" />



**不同类型的节点处理**:

根据节点的类型，加密后的名称被用于创建文件或目录。

- **普通文件**：以文件形式存储。

- 非文件节点

  （如目录和符号链接）：以目录形式存储。

  - **目录**：通过名为 `dir.c9r` 的文件表示，该文件包含上述的目录 ID。
  - **符号链接**：通过名为 `symlink.c9r` 的文件表示，该文件包含加密后的链接目标。



**明文与密文目录结构示例**:

假设有以下明文目录结构：

```bash
.
├─ File.txt
├─ SymlinkToFile.txt
├─ Subdirectory
│  └─ ...
└─ ...
```

经过加密之后，一个密文目录结构如下：

```bash
.
├─ d
│  ├─ BZ
│  │  └─ R4VZSS5PEF7TU3PMFIMON5GJRNBDWA
│  │     ├─ 5TyvCyF255sRtfrIv**83ucADQ==.c9r  # 加密后的 File.txt
│  │     ├─ FHTa55bH*sUfVDbEb0gTL9hZ8nho.c9r  # 加密后的 Subdirectory
│  │     │  └─ dir.c9r
│  │     └─ gLeOGMCN358*UBf2Qk9cWCQl.c9r  # 加密后的 SymlinkToFile.txt
│  │        └─ symlink.c9r
│  └─ FC
│     └─ ZKZRLZUODUUYTYA4457CSBPZXB5A77  # Subdirectory 的内容
│        └─ ...
├─ masterkey.cryptomator
├─ masterkey.cryptomator.DFD9B248.bkup
└─ vault.cryptomator
```

在这个加密后的结构中，所有文件和目录的名称都被加密和编码，以确保其内容的安全性。这种加密方法使得即使攻击者获取了加密后的数据，也无法推断出原始文件的名称或目录结构。

### 文件名缩短

Cryptomator 在文件名加密后采用了一种称为“文件名缩短”的过程，以确保最大的兼容性，特别是针对某些云同步服务的限制。这个过程没有提供额外的安全性，但对于保持文件系统兼容性至关重要。

为了最大限度地提高兼容性，我们需要确保密文名称不超过255个字符。由于一些云同步服务可能在冲突时希望为文件添加后缀。为了避免冲突，Cryptomator 决定将加密后的文件名长度限制在 220 个字符以内。

如果一个加密的名称（包括其“.c9r”扩展名）超过了这220个字符，那么创建一个以文件名的 SHA-1 哈希命名的目录，并附加.c9s扩展名。此外，还将创建一个名为“name.c9s”的反向映射文件，该文件包含原始的长文件名。

**这句话怎么理解呢?**我们先来看看下面的代码

```python
if (length(ciphertextName) > 220) {
    # 计算加密文件名的 SHA-1 哈希并进行 Base64 编码
    deflatedName := base64url(sha1(ciphertextName)) + '.c9s'

    # 构建 .c9s 目录内的文件路径
    inflatedNameFilePath := deflatedName + '/name.c9s'  # 反向映射文件
    fileContentsPath := deflatedName + '/contents.c9r'  # 文件内容
    symlinkFilePath := deflatedName + '/symlink.c9r'    # 符号链接
    dirIdFilePath := deflatedName + '/dir.c9r'          # 目录标识符
}
```

这段代码的逻辑是为了确保加密后的文件名不超过220个字符，以便最大限度地提高兼容性。如果加密后的文件名（包括 `.c9r` 扩展名）超过了220个字符，就会采取以下步骤：

**创建哈希目录**:

对超长的加密文件名进行 SHA-1 哈希处理，得到一个较短的哈希值。将这个哈希值进行 Base64 编码，并添加 `.c9s` 扩展名，以形成一个新的、更短的目录名。

**反向映射文件**:

在 `.c9s` 目录内创建一个名为 `name.c9s` 的文件。这个文件包含原始的加密文件名。这样做是为了保留原始文件名的信息，以便于在需要时可以还原。

**存储文件内容**:

如果原始节点是一个文件，它的内容将被存储在名为 `contents.c9r` 的文件中，位于 `.c9s` 目录内。

**符号链接和目录的处理**:

如果原始节点是一个符号链接或目录，将继续以现有方式处理。符号链接的加密目标将存储在名为 `symlink.c9r` 的文件中，而目录的标识将存储在名为 `dir.c9r` 的文件中。



**节点的种类**：

非文件（如符号链接或目录）无论如何都将存储为目录。对于它们，没有任何变化。

但文件需要一个不同的位置来存储它们的内容。因此，我们在 `.c9s` 目录中引入了 `contents.c9r` 文件。

包含具有非常长名称的多个节点的保险库可能会导致如下的密文结构：

```shell
.
├─ d
│  ├─ BZ
│  │  └─ R4VZSS5PEF7TU3PMFIMON5GJRNBDWA
│  │     ├─ 5TyvCyF255sRtfrIv**83ucADQ==.c9r
│  │     ├─ FHTa55bH*sUfVDbEb0gTL9hZ8nho.c9r
│  │     │  └─ dir.c9r
│  │     ├─ gLeOGMCN358*UBf2Qk9cWCQl.c9r
│  │     │  └─ symlink.c9r
│  │     ├─ IjTsXtReTy6bAAuxzLPV9T0k2vg=.c9s  # 缩短后的名称...
│  │     │  ├─ contents.c9r  # ...节点是一个常规文件
│  │     │  └─ name.c9s  # ...映射到这个完整的名称
│  │     ├─ q2nx5XeNCenHyQvkFD4mxYNrWpQ=.c9s  # 缩短后的名称...
│  │     │  ├─ dir.c9r  # ...节点是一个目录
│  │     │  └─ name.c9s  # ...映射到这个完整的名称
│  │     └─ u*JJCJE-T4IH-EBYASUp1u3p7mA=.c9s  # 缩短后的名称...
│  │        ├─ name.c9s  # ...映射到这个完整的名称
│  │        └─ symlink.c9r  # ...节点是一个符号链接
│  └─ FC
│     └─ ZKZRLZUODUUYTYA4457CSBPZXB5A77
│        └─ ...
├─ masterkey.cryptomator
├─ masterkey.cryptomator.DFD9B248.bkup
└─ vault.cryptomator
```

通过创建 `.c9s` 目录和 `name.c9s` 映射文件，Cryptomator 保持了原始文件名的可追溯性，同时确保了文件系统的兼容性。

### 备份目录标识符

这一层是可选的，其目的是在目录文件丢失或损坏的情况下增加数据可恢复性。这一层不是 Cryptomator 加密方案的必要组成部分，也不提供额外的安全性，但它对于数据恢复非常有用。

由于 Cryptomator 使用 `dir.c9r` 文件（包含目录 ID）来隐藏明文路径的层级结构，因此目录结构可能更容易受到诸如不完全同步或位腐败等问题的影响。

如果一个目录文件丢失或损坏，将无法计算出 `dirPath`，这会导致虚拟文件系统中该目录内容变得无法访问。理论上，这些文件的加密内容是可以恢复的，但由于文件名加密依赖于其父文件夹的目录 ID，而这个 ID 只存储在目录文件中，因此所有项目（文件、目录或符号链接）的名称都会丢失。

为了缓解这个问题，在创建目录时，会存储一个备份目录文件。在密文目录中，将创建一个名为 `dirid.c9r` 的文件，该文件包含其父文件夹的目录 ID。这个文件就像普通的密文文件一样进行加密。

```python
function createBackupDirFile(parentDirId, encryptionMasterKey, macMasterKey):
    # 加密父目录的 ID
    encryptedParentDirId = aesSivEncrypt(parentDirId, null, encryptionMasterKey, macMasterKey)

    # 将加密的目录 ID 存储在名为 dirid.c9r 的文件中
    backupDirFilePath = 'dirid.c9r'
    writeFile(backupDirFilePath, encryptedParentDirId)

function writeFile(filePath, content):
    # 将内容写入指定的文件路径
    # ...
```

### 小结

**虚拟文件系统**：Cryptomator 创建一个虚拟驱动器，用户可以在其中以平常的方式操作文件，例如添加、编辑和删除。这个保险库可以存储在本地计算机上，也可以存储在云服务（如Google Drive、Dropbox等）中。

**透明加密和解密**：文件在虚拟驱动器中被透明地加密和解密。用户与文件的互动就像与未加密的文件一样，但所有的文件实际上都是加密存储的。

**主密钥派生**：每个保险库都有一个独特的256位加密和消息认证码（MAC）主密钥，用于加密文件特定密钥和文件认证。这些主密钥是使用密码经过派生函数（如scrypt）生成的。

**文件名和目录ID的加密**：Cryptomator使用AES-SIV对文件名进行加密，同时使用AES-GCM对目录ID进行加密。这样可以确保文件和目录名在存储时保持安全。

**名称缩短**：为了最大兼容性，Cryptomator对较长的文件名进行缩短，以确保不超过一定的字符限制。如果文件名太长，将创建一个包含较短哈希的目录，其中包含原始文件的引用。

**备份目录ID**：为了增加数据可恢复性，Cryptomator在创建目录时存储备份目录文件，以确保即使目录文件丢失或损坏，用户仍然能够访问其文件。



## 应用结构

应用程序分为三个主要模块，即：

**Cryptomator模块**:

- **功能：** 提供用户对容器进行控制的图形界面。
- **用途：** 用户可以通过Cryptomator模块管理和控制文件容器，可能包括创建、打开、关闭、加密和解密容器等操作。

**CryptoFS模块**:

- **功能：** 实现虚拟文件系统的库。
- **用途：** 负责通过操作系统在容器中读取和写入数据。在读取操作时，它解密存储在容器中的数据，并在写入操作时对要存储的数据进行加密。这确保文件在存储和检索过程中都是加密的。

**CryptoLib模块**:

- **功能：** 提供用于加密和解密文件的函数的库。
- **用途：** 被CryptoFS模块调用，处理实际的文件加密和解密操作。可能涉及生成和管理加密密钥、执行加密算法等任务。

由应用程序提供的读取文件的过程可以描述为12个步骤，如图所示。这些步骤如下解释：

1. 用户请求操作系统打开一个文件;
2. 操作系统请求FUSE获取文件数据。FUSE允许用户空间应用程序向Linux内核导出文件系统，具有挂载文件系统、卸载它并与内核通信的功能;
3. FUSE将此请求转发给Cryptomator，使用CryptoFS库;
4. Cryptomator请求操作系统从存储设备中获取文件数据;
5. 操作系统定位数据;
6. 这些数据加载到主内存中;
7. 操作系统将这些数据提供给Cryptomator;
8. CryptoFS库将加密数据发送到CryptoLib库;
9. CryptoLib库解密接收到的数据并将其返回给CryptoFS库;
10. CryptoFS库将解密后的数据发送给FUSE;
11. FUSE将这些数据转发给操作系统;
12. 最终，操作系统向用户提供解密后的文件

![Workflow for reading and decrypting stored data with Cryptomator](./Cryptomator.assets/image-20240105101613171.png)



数据写入过程与读取过程类似，但在将明文数据发送到CryptoLib库之前，它们被发送到操作系统，然后转发到存储设备进行记录。存储在本地设备中的文件也以加密形式与云存储服务同步，云存储提供商可以对其进行第二层加密。

## 使用教程

### **安装Cryptomator**

[官方网站下载](https://cryptomator.org/downloads/)

[Github开源网址](https://github.com/cryptomator/cryptomator)

抛开那些原理，Cryptomator 的工作机制其实很简单。就像之前所说，Cryptomator 会将在你选择的位置创建一个保险柜，而这个保险柜以文件夹的形式存在。

在你通过 Cryptomator 解锁它之后，Cryptomator 会弹出一个虚拟的磁盘，你在虚拟磁盘里的一切写入操作都会被 Cryptomator 实时加密后放入保险柜的文件夹；相反，一切读取操作（例如打开一个文件）都是由 Cryptomator 解密后展现在虚拟的磁盘里。

必要的元素

- 保险库文件夹

- Cryptomator 客户端



### **创建 Vault（保险库）：**

- 启动 Cryptomator 应用程序。

<img src="./Cryptomator.assets/image-20231124234729130.png" alt="image-20231124234729130" style="zoom:67%;" />	

- 点击 "Create a new vault"（创建新的保险库）,并创建一个名称。

<img src="./Cryptomator.assets/image-20231124234807922.png" alt="image-20231124234807922" style="zoom:67%;" />	

- 选择一个位置来保存你的保险库，设置一个密码并点击 "Create Vault"（创建保险库）。

<img src="./Cryptomator.assets/image-20231124235147281.png" alt="image-20231124235147281" style="zoom:67%;" />	

<img src="./Cryptomator.assets/image-20231124235252527.png" alt="image-20231124235252527" style="zoom:67%;" />	

<img src="./Cryptomator.assets/image-20231124235358865.png" alt="	" style="zoom:67%;" />	

<img src="./Cryptomator.assets/image-20231124235433951.png" alt="image-20231124235433951" style="zoom: 67%;" />	

### **打开 Vault：**

- 在 Cryptomator 主界面上，选择 "Unlock Vault"（解锁保险库）。

<img src="./Cryptomator.assets/image-20231124235602441.png" alt="image-20231124235602441" style="zoom: 67%;" />

- 输入之前设置的密码并点击 "Unlock"（解锁）。

![image-20231124235633391](./Cryptomator.assets/image-20231124235633391.png)





### **使用 Vault：**

- 解锁保险库后，你将看到一个虚拟磁盘，就像是一个常规的硬盘驱动器一样。

<img src="./Cryptomator.assets/image-20231124235801665.png" alt="image-20231124235801665" style="zoom:67%;" />

欢迎里面的内容

![image-20231125000104435](./Cryptomator.assets/image-20231125000104435.png)

- 将文件复制到这个虚拟磁盘中，它们将会自动被加密。

<img src="./Cryptomator.assets/image-20231125000140299.png" alt="image-20231125000140299" style="zoom:67%;" />



<img src="./Cryptomator.assets/image-20231125000338590.png" alt="image-20231125000338590" style="zoom:67%;" />



### **关闭 Vault：**

- 在完成文件操作后，返回到 Cryptomator 主界面。
- 点击 "Lock Vault"（锁定保险库）来关闭加密磁盘。

<img src="./Cryptomator.assets/image-20231125000514128.png" alt="image-20231125000514128" style="zoom:67%;" />



![image-20231125000643411](./Cryptomator.assets/image-20231125000643411.png)

加密前的文件夹目录(除文件夹外不显示)

```shell
F:\ ❯ tree F:\
卷 test 的文件夹 PATH 列表
卷序列号为 7D22-80D6
F:\
└─JavaCode
    ├─.idea
    ├─src
    │  ├─main
    │  │  ├─java
    │  │  │  └─org
    │  │  │      └─example
    │  │  └─resources
    │  └─test
    │      └─java
    └─target
        ├─classes
        │  └─org
        │      └─example
        └─generated-sources
            └─annotations
```

当关闭vault之后，这时候可以发现F盘无法访问

<img src="./Cryptomator.assets/image-20231125001008217.png" alt="image-20231125001008217" style="zoom:80%;" />

并且在解锁或者关闭vault都无法通过访问物理文件夹来访问文件，都经过了加密，如下所示，只有通过cryptomator客户端才能够访问

```
D:\CTF\crytotest ❯ tree test
卷 软件盘 的文件夹 PATH 列表
卷序列号为 146F-04B1
D:\CTF\CRYTOTEST\TEST
└─d
    ├─2K
    │  └─CG2CJJJZENWUZXDE7YNF2IICEXQQNH
    ├─2Q
    │  └─6NMDMZPG5MLAIOQ646XVDEYEUSN7KN
    │      └─RLZLzaZI_l6AvoOxmx5GwQa8oA==.c9r
    ├─3F
    │  └─Z44TP6JDQ2YHPW3EJJG63NXO5NOIQD
    │      └─wNvhzQUuQEHz37_TOpivH-3faSsDrAUl.c9r
    ├─65
    │  └─ELKR26XR7YSZ3WKJZMT2XNLS5LFYCT
    │      └─K-DGnTbmsfU0UaxaDS5G9tiCkc678WWWw5xk.c9r
    ├─72
    │  └─UJ5ZTUXBKCQ23FHRKZYIQRCMAG3PRM
    │      └─e1BOASWPF4bhU_y3ANDc5nHhPA==.c9r
    ├─EW
    │  └─3QNDMS3GR5QTA2YEEG4LO5TWBFG2WP
    │      └─3gubnMamAsaYMngzF7LH11hiOzFHpUc=.c9r
    ├─GR
    │  └─BWDMYEVN4IUIKMNGHRPXNDPE46J2HH
    │      ├─HTXb0dBFqX_roeSTEaZ7SCqR9FM=.c9r
    │      └─vASilzHvrYhXlS4TIt7mUMWgk-k=.c9r
    ├─H7
    │  └─3Y6YRU3JBTTTL6JLXWQPPUE5AMMFUX
    │      └─-mrh1RluyYEhmOEfMSqBsZemSmM=.c9r
    ├─LD
    │  └─XX2UZG4DNE23HC3WZUOI7PZLREOZ7S
    │      ├─7kZ_QWAFvVk0ZmPj-isRHIZLCWUHcIk=.c9r
    │      └─mhFglS_01dVaud1vITv7rzxssJkHBsNKF7ufwWkFByb_.c9r
    ├─NE
    │  └─SHBSXPT2AZGSJCB7WTCO7VHIE75WMM
    ├─QU
    │  └─UDFEW5VPYEP7OEKAQBETUET6P6RI3F
    │      └─8bqOajKF4_pSbthHksjgP1FafJhQvgo=.c9r
    ├─RC
    │  └─GTCXOCI5BK3QZZFLO7YGO5QIWLBVLN
    │      ├─-uF9Bmai5h9r0L3vjeckdUt0BDVNbFhMww==.c9r
    │      └─dolUjJdPSZoo6534lyaCYD1y5Pg=.c9r
    ├─RL
    │  └─G3WIS7FVNFRM36D3C73HSLI3OFFA65
    ├─RQ
    │  └─AZXC4RMP7YAHFPKMBZPUHLX2PIBC3W
    ├─SR
    │  └─WX3VHPLWADH7JERJE2EV4Y2M33IKYC
    ├─WW
    │  └─PBO2U62HP3VP7YQZLTTXL3AHX2DG46
    └─XW
        └─44BZMLPJV7FK53HZCS2YBHJBOF44PQ
            ├─5EqU7lpzzYYS0qRAN48QmcNAZSAz.c9r
            ├─d2-xhEl89KuVOx0BwxssLwIQoCCUIw==.c9r
            └─KLDm5ujXxv_PFYmTHnGjuWmf_Q==.c9r
```

几个关键的文件`vault.cryptomator`

![image-20231125001125419](./Cryptomator.assets/image-20231125001125419.png)

`masterkey.cryptomator`

![image-20231125001052918](./Cryptomator.assets/image-20231125001052918.png)

你还能在cryptomator看到它读取文件的效率或者IO性能

<img src="./Cryptomator.assets/image-20231125110528987.png" alt="image-20231125110528987" style="zoom:67%;" />

## 参考文献

[1] https://juejin.cn/post/6974668741980192775

[2] [cryptomator/cryptomator: Multi-platform transparent client-side encryption of your files in the cloud (github.com)](https://github.com/cryptomator/cryptomator)

[3] [Security Architecture — Cryptomator 1.7.0 documentation](https://docs.cryptomator.org/en/latest/security/architecture/)

[4] [Galois/Counter Mode - Wikipedia](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

[5] Rocha, M.D., Valadares, D.C., Perkusich, A., Gorgônio, K.C., Pagno, R.T., & Will, N.C. (2020). Secure Cloud Storage with Client-Side Encryption Using a Trusted Execution Environment. *ArXiv, abs/2003.04163*.
