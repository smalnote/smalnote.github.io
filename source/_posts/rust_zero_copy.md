---
title: Rust 零拷贝测试及代码设计
date: 2024-12-16 15:57:00
---

## 简介

> 本文主要测试一下 Rust 在 Linux 环境下零拷贝的性能，并跟 Linux/C API 做对比，主要
> 场景是 Web 服务器从磁盘文件数据不需要业务逻辑处理直接通过网络连接发送。同时简单
> 读一下 std::io::copy 源代码，看看其是如何做零拷贝优化的。

## 运行环境

- CPU: E5-2680v4
- Mem: 48GB
- OS: AlmaLinux 9
- Host: KVM

## 总结

零拷贝 API 对于**时间复杂度**的降低绝对值上并没有太大效果，原理上减少的时间消耗来自于减少在
Linux 用户态和内核态之间进行上下文切换的次数和在用户态及内核态之间进行的内存拷贝，这部分时间相
对于通过网络伟输数据消耗的时间小了一个量级。

在原理上，零拷贝相对于普通的 Read/Write Loop 减少了内存缓存空间使用和内存拷贝次数，从 CPU 运
行时间占用看，提升理论上应该比较明显，可以**_显著降低 CPU 占用率_**；不需要内存缓存空间在
**_高并发场景下也可以减少内存占用率_**。

## 性能测试

**Unix Domain Socket Server**

```bash
# Use netcat to listen unix domain socket and drop file to /dev/null
nc -lU /tmp/zero_copy.sock >/dev/null && rm /tmp/zero_copy.sock
```

**Copy 1GB file from SSD to local Unix domain socket**

- Scenario: Copy 1GB file from SSD to local Unix domain socket
- File size: 1GB
- Unix Domain Socket Server: nc -lU /tmp/zero_copy.sock >/dev/null

| API                                 | Time  | Diff   |
| ----------------------------------- | ----- | ------ |
| C read/send with buffer(4KB)        | 907ms | 100%   |
| C read/send with buffer(8KB)        | 598ms | 65.9%  |
| C read/send with buffer(16KB)       | 423ms | 46.6%  |
| C read/send with buffer(32KB)       | 354ms | 39.0%  |
| C mmap/send                         | 266ms | 29.3%  |
| C sendfile                          | 131ms | 14.4%  |
| C splice/pipe                       | 158ms | 17.4%  |
| Rust read&write with buffer(4KB)    | 915ms | 100.1% |
| Rust std::io::copy                  | 577ms | 63.6%  |
| Rust libc::sendfile64               | 545ms | 60.1%  |
| Rust nix::sys::sendfile::sendfile64 | 575ms | 63.4%  |

> [!NOTE]
> API splice/pipe use a pipe to connect filefd and sockfd, according to `man 2 spclie`,
> the splice function requires one of file descriptor to be pipe, result in:
> splice(filefd, pipefd[1]) and splice(pipefd[1], sockfd).

**Copy 8GB file from tmpfs to local Unix domain socket**

- Scenario: Copy 8GB file from tmpfs to local Unix domain socket
- File size: 8GB
- Unix Domain Socket Server: nc -lU /tmp/zero_copy.sock >/dev/null

| API                                 | Time   | Diff  |
| ----------------------------------- | ------ | ----- |
| Rust read&write with buffer(4KB)    | 7432ms | 100%  |
| Rust read&write with buffer(8KB)    | 4688ms | 63.1% |
| Rust std::io::copy                  | 4654ms | 62.6% |
| Rust libc::sendfile64               | 4059ms | 54.6% |
| Rust nix::sys::sendfile::sendfile64 | 3937ms | 53.0% |

**Copy 20GB file from tmpfs to local Unix domain socket**

- Scenario: Copy 20GB file from tmpfs to local Unix domain socket
- File size: 20GB
- Unix Domain Socket Server: nc -lU /tmp/zero_copy.sock >/dev/null

| API                                 | Time    | Diff  |
| ----------------------------------- | ------- | ----- |
| Rust read&write with buffer(4K)B    | 18336ms | 100%  |
| Rust std::io::copy                  | 11334ms | 61.8% |
| Rust libc::sendfile64               | 10091ms | 55.0% |
| Rust nix::sys::sendfile::sendfile64 | 10061ms | 54.8% |

## Rust Zero-Copy [Source Code](<(https://github.com/rust-lang/rust/blob/8e37e151835d96d6a7415e93e6876561485a3354/library/std/src/sys/pal/unix/kernel_copy.rs)>)

### Copy Disk file to Unix Domain Socket

```rust
use std::{
    env,
    fs::File,
    io::{self, Result},
    os::unix::net::UnixStream,
    time::Instant,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <file_path> <socket_path>", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    let socket_path = &args[2];
    let now = Instant::now();
    copy_file_to_unix_domain_socket(file_path, socket_path)?;
    let elapsed = now.elapsed();
    println!("***Metrics: time elapsed: {}ns", elapsed.as_nanos());
    Ok(())
}

fn copy_file_to_unix_domain_socket<'a>(file_path: &'a str, socket_path: &'a str) -> Result<()> {
    let mut file = File::open(file_path)?;
    let mut socket = UnixStream::connect(socket_path)?;
    let copied_len = io::copy(&mut file, &mut socket)?;
    debug_assert_eq!(copied_len, file.metadata().unwrap().len());
    Ok(())
}
```

### 分析：从 Disk File 到 Socket 的拷贝并没有走零拷贝 API

从源代码看，对于 input 到 output 的拷贝，使用到零拷贝的情况。

| Input         | Output           | Zero-copy API   |
| ------------- | ---------------- | --------------- |
| File(len > 0) | File             | copy_file_range |
| Block Device  | File             | sendfile        |
| Pipe          | File/Pipe/Socket | splice          |
| Socket/Pipe   | Pipe             | splice          |

> [!NOTE]
> 由于在执行拷贝时，是按顺序尝试 copy_file_range, sendfile, splice，尝试过程可能会改变文件
> 描述符，因此对 sendfile, splice 设置了 safe_kernel_copy 检查，要求 output 是 Pipe/Socket,
> 或 input 是 File，但是 sendfile 要求 output 是 File，导到 File -> Pipe, File -> Socket
> 不能用到 sendfile。

| ｜ Zero-copy API | Input Constraints             | Output constraints |
| ---------------- | ----------------------------- | ------------------ |
| copy_file_range  | File(len > 0)                 | File               |
| sendfile         | File(len > 0) or Block Device | File               |
| splice           | Pipe                          | \*                 |
| splice           | Socket/Pipe                   | Pipe               |

```rust
// kernel_copy.rs

// 判断是否可以用 copy_file_range，输入是文件且长度大于0，输出也是文件
if input_meta.copy_file_range_candidate(FdHandle::Input)
    && output_meta.copy_file_range_candidate(FdHandle::Output)

fn copy_file_range_candidate(&self, f: FdHandle) -> bool {
    match self {
        // copy_file_range will fail on empty procfs files. `read` can determine whether EOF has been reached
        // without extra cost and skip the write, thus there is no benefit in attempting copy_file_range
        FdMeta::Metadata(meta) if f == FdHandle::Input && meta.is_file() && meta.len() > 0 => {
            true
        }
        FdMeta::Metadata(meta) if f == FdHandle::Output && meta.is_file() => true,
        _ => false,
    }
}

// 判断是否可以用 sendfile,
// potential_sendfile_source 需要 src 是文件或文件类型是 block_device
// Block Device: HDD, SDD, etc; e.g.: /dev/sda (stat /dev/sda Access mode start with b)
// safe_kernel_copy 需要 src 是 Socket/Pipe/FIFO，或者 dst 是 File
// 可以看到 potential_sendfile_source 和 safe_kernel_copy 对于 src 的要求是冲突的，
// 实际上不可能用到 sendfile
if input_meta.potential_sendfile_source() && safe_kernel_copy(&input_meta, &output_meta)
fn potential_sendfile_source(&self) -> bool {
    match self {
        // procfs erroneously shows 0 length on non-empty readable files.
        // and if a file is truly empty then a `read` syscall will determine that and skip the write syscall
        // thus there would be benefit from attempting sendfile
        FdMeta::Metadata(meta)
            if meta.file_type().is_file() && meta.len() > 0
                || meta.file_type().is_block_device() =>
        {
            true
        }
        _ => false,
    }
}
/// Returns true either if changes made to the source after a sendfile/splice call won't become
/// visible in the sink or the source has explicitly opted into such behavior (e.g. by splicing
/// a file into a pipe, the pipe being the source in this case).
///
/// This will prevent File -> Pipe and File -> Socket splicing/sendfile optimizations to uphold
/// the Read/Write API semantics of io::copy.
///
/// Note: This is not 100% airtight, the caller can use the RawFd conversion methods to turn a
/// regular file into a TcpSocket which will be treated as a socket here without checking.
fn safe_kernel_copy(source: &FdMeta, sink: &FdMeta) -> bool {
    match (source, sink) {
        // Data arriving from a socket is safe because the sender can't modify the socket buffer.
        // Data arriving from a pipe is safe(-ish) because either the sender *copied*
        // the bytes into the pipe OR explicitly performed an operation that enables zero-copy,
        // thus promising not to modify the data later.
        (FdMeta::Socket, _) => true,
        (FdMeta::Pipe, _) => true,
        (FdMeta::Metadata(meta), _)
            if meta.file_type().is_fifo() || meta.file_type().is_socket() =>
        {
            true
        }
        // Data going into non-pipes/non-sockets is safe because the "later changes may become visible" issue
        // only happens for pages sitting in send buffers or pipes.
        (_, FdMeta::Metadata(meta))
            if !meta.file_type().is_fifo() && !meta.file_type().is_socket() =>
        {
            true
        }
        _ => false,
    }
}

// 判断是否可以用 splice
// src 和 dst 有一个是 pipe
// safe_kernel_copy 需要 src 是 Socket/Pipe/FIFO，或者 dst 不是 FIFO 或 不是 Socket
if (input_meta.maybe_fifo() || output_meta.maybe_fifo())
    && safe_kernel_copy(&input_meta, &output_meta)
```

## std::io::copy API 设计

```rust
// std::io::copy 函数定义
// 只要实现了 Read trait 的 reader 和实现 Write trait 的 writer 即可进行 copy
// 最基本的方法就是定义一个缓冲区，循环从 reader 读到缓冲区，再从缓冲区写到 writer
fn copy<R: Read + ?Sized, W: Write + ?Sized>(reader: &mut R, writer: &mut W) -> Result<u64>;

// 那么 copy 函数的实现又是根据 reader/writer 的类型进行优化调用不同的 zero-copy API 的呢？
// 需要用到 super trait 对特定 reader / writer 扩展 Read / Write trait
// copy 调用 linux 平台的实现
// sys::kernel_copy::copy_spec(reader, writer)
fn copy_spec<R: Read + ?Sized, W: Write + ?Sized>(read: &mut R, write: &mut W) -> Result<u64> {
    let copier = Copier { read, write };
    SpecCopy::copy(copier)
}

// copy_spec 定义了 SpecCopy trait 和 Copier struct
trait SpecCopy {
    fn copy(self) -> Result<u64>;
}
struct Copier<'a, 'b, R: Read + ?Sized, W: Write + ?Sized> {
    read: &'a mut R,
    write: &'b mut W,
}

// 调用 SpecCopy::copy() 会根据 Copier 中的 read, write 类型生成不同的代码实现

// 普通的循环 read/write 实现，这个实现只需要 Read / Write trait
impl<R: Read + ?Sized, W: Write + ?Sized> SpecCopy for Copier<'_, '_, R, W> {
    default fn copy(self) -> Result<u64> {
        generic_copy(self.read, self.write)
    }
}

// 可以进行 zero-copy 优化的 CopyRead / CopyWrite trait 实现
impl<R: CopyRead, W: CopyWrite> SpecCopy for Copier<'_, '_, R, W> {
    fn copy(self) -> Result<u64> {
        // copy_file_range, sendfile, splice ...
    }
}
trait CopyRead: Read {
    /// Extracts the file descriptor and hints/metadata, delegating through wrappers if necessary.
    fn properties(&self) -> CopyParams;
}
trait CopyWrite: Write {
    /// Extracts the file descriptor and hints/metadata, delegating through wrappers if necessary.
    fn properties(&self) -> CopyParams;
}

// 这样只需要对可以进行 zero copy 的 reader / writer 类型分别实现 CopyRead, CopyWrite trait
// 则编译器生成 SpecCopy::copy() 调用的代码时，就会匹配到 zero-copy 优化的实现
// std::sys::kernel_copy 模块中，对 fs::File, std::net::tcp::TcpStream，
// std::os::unix::net::stream::UnixStream 等标准库中的类型都实现了 CopyRead, CopyWrite trait
// 如：
impl CopyRead for UnixStream {
    fn properties(&self) -> CopyParams {
        // ...
    }
}

impl CopyRead for &UnixStream {
    fn properties(&self) -> CopyParams {
        // ...
    }
}

impl CopyWrite for UnixStream {
    fn properties(&self) -> CopyParams {
        // ...
    }
}

impl CopyWrite for &UnixStream {
    fn properties(&self) -> CopyParams {
        // ...
    }
}

// 这样在 File, TcpStream, UnixStream, Pipe, Character Device 等文件描述符之间进行 copy 时
// 就会使用第二个 SpecCopy::copy 实现，利用 Super Trait: CopyRead, CopyWrite 配合泛型参数进行
// 编译时的静态分发，实现多态，高效而巧妙；扩展性方面，有新的 reader / writer 需要支持，只需要实现
// CopyRead, CopyWrite 即可。
```
