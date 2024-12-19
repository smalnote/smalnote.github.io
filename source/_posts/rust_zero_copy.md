---
title: Rust 零拷贝测试及代码设计
date: 2024-12-16 15:57:00
---

## 简介

> 本文主要测试一下 Rust 在 Linux 环境下零拷贝的性能，并跟 Linux/C API 做对比，主要场景是 Web 服务器从磁盘文件数据不需要业务逻辑处理直接通过网络连接发送。同时简单读一下 std::io::copy 源代码，看看其是如何做零拷贝优化的。
## 运行环境

-   CPU: E5-2680v4
-   Mem: 48GB
-   OS: AlmaLinux 9
-   Host: KVM

## 总结

零拷贝 API 对于**时间复杂度**的降低绝对值上并没有太大效果，原理上减少的时间消耗来自于减少在 Linux 用户态和内核态之间进行上下文切换的次数和在用户态及内核态之间进行的内存拷贝，这部分时间相对于通过网络传输数据消耗的时间小了一个量级。

在原理上，零拷贝相对于普通的 Read/Write Loop 减少了内存缓存空间使用和内存拷贝次数，从 CPU 运行时间占用看，提升理论上应该比较明显，可以**显著降低 CPU 占用率**；不需要内存缓存空间在**高并发场景下也可以减少内存占用率**。

## 性能测试

**Unix Domain Socket Server**

```bash
# Use netcat to listen unix domain socket and drop file to /dev/null
nc -lU /tmp/zero_copy.sock >/dev/null && rm /tmp/zero_copy.sock
```

**Copy 1GB file from SSD to local Unix domain socket**

-   Scenario: Copy 1GB file from SSD to local Unix domain socket
-   File size: 1GB
-   Unix Domain Socket Server: nc -lU /tmp/zero_copy.sock >/dev/null

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

> [!NOTE] API splice/pipe use a pipe to connect filefd and sockfd, according to `man 2 spclie`, the splice function requires one of file descriptor to be pipe, result in:splice(filefd, pipefd[1]) and splice(pipefd[1], sockfd).

**Copy 8GB file from tmpfs to local Unix domain socket**

-   Scenario: Copy 8GB file from tmpfs to local Unix domain socket
-   File size: 8GB
-   Unix Domain Socket Server: nc -lU /tmp/zero_copy.sock >/dev/null

| API                                 | Time   | Diff  |
| ----------------------------------- | ------ | ----- |
| Rust read&write with buffer(4KB)    | 7432ms | 100%  |
| Rust read&write with buffer(8KB)    | 4688ms | 63.1% |
| Rust std::io::copy                  | 4654ms | 62.6% |
| Rust libc::sendfile64               | 4059ms | 54.6% |
| Rust nix::sys::sendfile::sendfile64 | 3937ms | 53.0% |

**Copy 20GB file from tmpfs to local Unix domain socket**

-   Scenario: Copy 20GB file from tmpfs to local Unix domain socket
-   File size: 20GB
-   Unix Domain Socket Server: nc -lU /tmp/zero_copy.sock >/dev/null

| API                                 | Time    | Diff  | Time Perf(command `time`)                       |
| ----------------------------------- | ------- | ----- | ----------------------------------------------- |
| Rust read&write with buffer(4KB)    | 18094ms | 100%  | 3.82s user 14.36s system 96% cpu 18.755 total   |
| Rust read&write with buffer(8KB)    | 11515ms | 63.6% | 1.99s user 9.54s system 94% cpu 12.206 total    |
| Rust std::io::copy                  | 11457ms | 63.3% | 2.07s user 9.44s system 95% cpu 12.114 total    |
| Rust libc::sendfile64               | 9960ms  | 55.0% | 0.12s user 2.56s system 25% cpu 10.617 total    |
| Rust nix::sys::sendfile::sendfile64 | 9930ms  | 54.9% | 0.11s user 2.83s system 27% cpu 10.588 total    |
| Rust tokio::io::copy(async io)      | 50578ms | 280%  | 16.36s user 37.61s system 105% cpu 51.271 total |

> [!NOTE] 从 Time Perf 可以看到，libc 和 nix 库直接使用零拷贝 API，CPU 占用率显著低于其它方式。

## Rust Zero-Copy [Source Code](<(https://github.com/rust-lang/rust/blob/8e37e151835d96d6a7415e93e6876561485a3354/library/std/src/sys/pal/unix/kernel_copy.rs)>)

### Copy Disk file to Unix Domain Socket

```rust
use std::{
    env,
    fs::File,
    io::{self, Read, Result, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, net::UnixStream},
    },
    time::Instant,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <method> <file_path> <socket_path>", args[0]);
        std::process::exit(1);
    }

    let method = &args[1];
    let file_path = &args[2];
    let socket_path = &args[3];

    if method != "tokio_io_copy" {
        let now = Instant::now();
        let file = File::open(file_path)?;
        let socket = UnixStream::connect(socket_path)?;
        match method.as_str() {
            "read_write" => read_write(file, socket)?,
            "std_io_copy" => copy_file_to_unix_domain_socket(file, socket)?,
            "libc_sendfile" => libc_sendfile(file, socket)?,
            "nix_sendfile" => nix_sendfile(file, socket)?,
            _ => panic!("unsupported method {}", method),
        }
        let elapsed = now.elapsed();
        println!("***Metrics: time elapsed: {}ms", elapsed.as_millis());
    } else {
        let current_thread = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Create tokio runtime failed");
        current_thread.block_on(async move {
            let now = tokio::time::Instant::now();
            let mut file = tokio::fs::File::open(file_path)
                .await
                .expect("Open file failed");
            let mut socket = tokio::net::UnixStream::connect(socket_path)
                .await
                .expect("Connect unix domain socket failed");
            let file_len = file
                .metadata()
                .await
                .expect("Get file metadata filed")
                .len();
            let copied_len = tokio::io::copy(&mut file, &mut socket)
                .await
                .expect("Copy file to socket failed");
            assert_eq!(copied_len, file_len);
            let elapsed = now.elapsed();
            println!("***Metrics: time elapsed: {}ms", elapsed.as_millis());
        });
    }
    Ok(())
}

fn read_write(file: File, socket: UnixStream) -> Result<()> {
    let mut buf: [u8; 8192] = [0; 8192];
    let mut bytes_left = file.metadata().unwrap().size() as usize;
    loop {
        let bytes_read = (&file).read(&mut buf[..])?;
        if bytes_read == 0 {
            break;
        }
        (&socket).write_all(&buf[..bytes_read])?;
        bytes_left -= bytes_read;
    }
    assert_eq!(bytes_left, 0);
    Ok(())
}

fn copy_file_to_unix_domain_socket(mut file: File, mut socket: UnixStream) -> Result<()> {
    let copied_len = io::copy(&mut file, &mut socket)?;
    assert_eq!(copied_len, file.metadata().unwrap().len());
    Ok(())
}

fn nix_sendfile(file: File, socket: UnixStream) -> Result<()> {
    let mut len_left = file.metadata().unwrap().len() as usize;
    while len_left > 0 {
        let chunk_size = std::cmp::min(len_left, 0x7ffff000);
        let copied_len = nix::sys::sendfile::sendfile64(&socket, &file, None, chunk_size)?;
        len_left -= copied_len;
    }
    assert_eq!(len_left, 0);
    Ok(())
}

fn libc_sendfile(file: File, socket: UnixStream) -> Result<()> {
    let mut len_written = 0_u64;
    let len_file = file.metadata().unwrap().size();
    while len_written < len_file {
        let chunk_size = std::cmp::min(len_file - len_written, 0x7ffff000_u64) as usize;
        match unsafe {
            libc::sendfile64(
                socket.as_raw_fd(),
                file.as_raw_fd(),
                std::ptr::null_mut(),
                chunk_size,
            )
        } {
            -1 => return Err(std::io::Error::last_os_error()),
            len_sent => len_written += len_sent as u64,
        }
    }
    assert_eq!(len_written, len_file);
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

> [!NOTE] 由于在执行拷贝时，是按顺序尝试 copy_file_range, sendfile, splice，尝试过程可能会改变文件描述符，因此对 sendfile, splice 设置了 safe_kernel_copy 检查，要求 output 是 Pipe/Socket,或 input 是 File，但是 sendfile 要求 output 是 File，导到 File -> Pipe, File -> Socket 不能用到 sendfile。

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

// 那么 copy 函数的实现又是如何根据 reader/writer 的类型进行优化调用不同的 zero-copy API 的呢？
// 需要用到 super trait 对特定 reader / writer 扩展 Read / Write trait
// std::io::copy 调用 linux 平台的实现
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
