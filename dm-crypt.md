# dm-crypt

## 概述

Device Mapper 是 Linux 内核中的基础结构, 它提供了一种通用的方法来创建块设备的虚拟层. 而 `dm_crypt` 使用内核加密API提供块设备的透明加密. 用户可以指定一个对称密码, 加密模式, 密钥 (任何允许的大小), iv 生成模式, 然后就可以在 `/dev` 中创建新的块设备. 后续对此设备的写入将被加密, 读取将被解密. 文件系统可以像往常一样被挂载在上面, 例如结合 `RAID` 或 `LVM` 卷管理技术等.

## 用户端使用

```bash
qemu-img create -f qcow2 disk.qcow2 10G
qemu-system-x86_64 --enable-kvm -smp 1 -m 1G -drive file=disk.qcow2,if=virtio -cdrom ~/Downloads/ISOs/archlinux-x86_64.iso
```

VNC 连接后我们可以在 QEMU 中测试 cryptsetup 这一命令行前端的各种用法.

## 吞吐量测试

先用以下命令创建一个 `/dev/ram0` 设备用于测试:

```bash
sudo modprobe brd rd_nr=1 rd_size=4194304
```

接着创建 LUKS 头分离的加密块设备:

```bash
fallocate -l 2M crypthdr.img
sudo cryptsetup luksFormat /dev/ram0 --header crypthdr.img
sudo cryptsetup open --header crypthdr.img /dev/ram0 encrypted-ram0
sudo fio --filename=/dev/ram0 --readwrite=readwrite --bs=4k --direct=1 --loops=1000000 --name=plain
```

查看加密方案:

```
❯ sudo dmsetup table /dev/mapper/encrypted-ram0 
[sudo] password for track: 
0 8388608 crypt aes-xts-plain64 :64:logon:cryptsetup:ffeca43a-7305-4a1a-bc13-5424484cf3fc-d0 0 1:0 0 1 sector_size:4096
```

对原始块设备的吞吐量测试结果:

```
plain: (g=0): rw=rw, bs=(R) 4096B-4096B, (W) 4096B-4096B, (T) 4096B-4096B, ioengine=psync, iodepth=1
fio-3.35
Starting 1 process
Jobs: 1 (f=1): [M(1)][0.0%][r=2252MiB/s,w=2250MiB/s][r=576k,w=576k IOPS][eta 10d:13h:46m:50s]
```

接着对加密设备进行测试:

```
plain: (g=0): rw=rw, bs=(R) 4096B-4096B, (W) 4096B-4096B, (T) 4096B-4096B, ioengine=psync, iodepth=1
fio-3.35
Starting 1 process
Jobs: 1 (f=1): [M(1)][0.0%][r=291MiB/s,w=293MiB/s][r=74.5k,w=75.0k IOPS][eta 83d:05h:36m:04s]
```

可以发现速度慢了很多.

我们先尝试从现有的加密方案中选择一个速度较快的 (从 `/proc/crypto` 中可以看到所有支持的加密方案):

```
❯ sudo cryptsetup benchmark 
[sudo] password for track: 
# Tests are approximate using memory only (no storage IO).
PBKDF2-sha1      1814145 iterations per second for 256-bit key
PBKDF2-sha256    2343186 iterations per second for 256-bit key
PBKDF2-sha512    1661768 iterations per second for 256-bit key
PBKDF2-ripemd160  978149 iterations per second for 256-bit key
PBKDF2-whirlpool  734296 iterations per second for 256-bit key
argon2i      10 iterations, 1048576 memory, 4 parallel threads (CPUs) for 256-bit key (requested 2000 ms time)
argon2id     10 iterations, 1048576 memory, 4 parallel threads (CPUs) for 256-bit key (requested 2000 ms time)
#     Algorithm |       Key |      Encryption |      Decryption
        aes-cbc        128b      1323.4 MiB/s      3895.4 MiB/s
    serpent-cbc        128b       110.5 MiB/s       799.8 MiB/s
    twofish-cbc        128b       260.4 MiB/s       442.8 MiB/s
        aes-cbc        256b      1023.2 MiB/s      3144.0 MiB/s
    serpent-cbc        256b       114.2 MiB/s       844.0 MiB/s
    twofish-cbc        256b       267.3 MiB/s       444.8 MiB/s
        aes-xts        256b      3773.3 MiB/s      3830.9 MiB/s
    serpent-xts        256b       739.9 MiB/s       744.4 MiB/s
    twofish-xts        256b       416.9 MiB/s       425.8 MiB/s
        aes-xts        512b      3166.7 MiB/s      3161.5 MiB/s
    serpent-xts        512b       771.3 MiB/s       772.1 MiB/s
    twofish-xts        512b       426.2 MiB/s       432.2 MiB/s
```

发现正是我们使用的 aes-xtx-256 在速度上最理想且加解密速度平均. 这或许是一个可以优化的点.

## 参考

[1] https://www.cnblogs.com/hugetong/p/6914248.html

[2] https://linux.die.net/man/8/dmsetup

[3] https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMCrypt

[4] https://github.com/torvalds/linux/blob/1da177e4c3f41524e886b7f1b8a0c1fc7321cac2/drivers/md/dm-crypt.c

[5] https://elixir.bootlin.com/linux/latest/source/drivers/md/dm.c
