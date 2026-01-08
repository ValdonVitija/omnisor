<p align="center">
    <img alt="Omnisor Logo" src="logo.png">
</p>

<h1 align="center">Omnisor - High Level Rust SSH Client For Network Devices</h1>

# About

> [!WARNING]
> **This library is not stable yet!**

Omnisor is an asynchronous high-level SSH client library for Rust, with specialized support for network devices.
Built on top of [async-ssh2-tokio]( https://github.com/Miyoshi-Ryota/async-ssh2-tokio) & [russh](https://github.com/warp-tech/russh)

> [!NOTE]
> **I will try to keep omnisor in sync with async-ssh2-tokio. Will also try to add potential features and improvements library wide**

## Features

* **Standard SSH Client** - Connect, authenticate, and execute commands on network devices.
* **Vendor Presets** - Built-in support for Cisco, Juniper and more soon enough
* **Legacy Device Support** - Configurable SSH algorithms for older network equipment


## Install

Add Omnisor and Tokio to your Cargo.toml:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
omnisor = "0.1"
```

Or manually add both of them through cargo 
```bash
cargo add tokio --features full
cargo add omnisor
```

## Usage

### Quick Start - Standard SSH

For simple command execution on Linux/Unix servers, you can either use omnisor or async-ssh2-tokio. I will try to keep omnisor in sync with async-ssh2-tokio by add potential features and improvements not only on the networking side of omnisor.

### Quick Start - Network Devices

For interactive sessions with network devices (routers, switches, firewalls):

```rust
use omnisor::{DeviceSession, CiscoVariant};

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::connect(
        ("192.168.1.1", 22),
        "admin",
        "password",
        CiscoVariant::Ios,
    ).await?;

    let result = session.send_command("show version").await?;
    println!("{}", result.output);

    let result = session.send_command("show ip route").await?;
    println!("{}", result.output);

    session.close().await?;
    Ok(())
}
```

### Device Session Builder

For more control over device connections:

```rust
use omnisor::{DeviceSession, CiscoVariant, AuthMethod};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::builder()
        .address("192.168.1.1")
        .port(22)
        .username("admin")
        .vendor(CiscoVariant::Ios)
        .command_timeout(Duration::from_secs(60))
        .connect()
        .await?;

    let result = session.send_command("show version").await?;
    println!("{}", result.output);

    session.close().await?;
    Ok(())
}
```

### Legacy Device Support

For older devices requiring legacy SSH algorithms (for example older Cisco IOS):

```rust
use omnisor::{DeviceSession, CiscoVariant};

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    // Use IosLegacy variant for older Cisco devices
    let mut session = DeviceSession::connect(
        ("192.168.1.1", 22),
        "admin",
        "password",
        CiscoVariant::IosLegacy,
    ).await?;

    let result = session.send_command("show version").await?;
    println!("{}", result.output);

    session.close().await?;
    Ok(())
}
```

### Custom SSH Algorithms

For control over SSH algorithms you can specify whatever you like that is supported under https://github.com/Eugeny/russh

```rust
use omnisor::{DeviceSession, CiscoVariant, SshAlgorithms, kex, cipher, mac};

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::builder()
        .address("192.168.1.1")
        .username("admin")
        .password("password")
        .vendor(CiscoVariant::Ios)
        .ssh_algorithms(
            SshAlgorithms::new()
                .kex(vec![kex::DH_G14_SHA1, kex::DH_G1_SHA1])
                .cipher(vec![cipher::AES_256_CBC, cipher::AES_128_CBC])
                .mac(vec![mac::HMAC_SHA1])
        )
        .connect()
        .await?;

    let result = session.send_command("show version").await?;
    println!("{}", result.output);

    session.close().await?;
    Ok(())
}
```

### Enable and Config Mode Support


Omnisor offers ready to use methods to change between router modes (user/enable/config)
> [!IMPORTANT]
> **Don't expect complete support for every device vendor and version. This has been massively influenced by cisco devices.**

```rust
#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::connect(
        ("192.168.142.130", 22),
        "cisco",
        "StrongPassword123",
        CiscoVariant::IosLegacy,
    )
    .await?;

    //Be careful with the chronology of steps for now. 
    //In the future I plan to offer the possibility
    //of going into any mode from every other mode
    //without having to follow the normal chronology of steps.
    let _ = session.enter_enable_mode("enable").await?;
    let _ = session.enter_config_mode("config t").await?;
    let _ = session.exit_config_mode("exit").await?;
    let _ = session.exit_enable_mode("disable").await?;
}
```

# Contribution

To contribute to this project all you need is to enjoy working on open source projects and absolutely nothing else. Also be respectful!
So... fork the repo, fix bugs, potentially optimize, improve docs. Whatever you think this project needs and all will be carefully reviewd/considerd