# Version Checker
A platform agnostic version checking utility for your cargo crates.

Reads your Cargo.toml and parses out the dependencies, processing their versions and comparing them to a list of known security advisories, as well as their most recent version on [crates.io](https://crates.io)

# Installation

```cargo install version-checker```


# Usage 
## Help
```
version-checker --help
```
```
Version Checker 0.1.12
Thomas B. <tom.b.2k2@gmail.com>
Combs your Cargo.toml for dependencies, and checks their versions whilst also looking for potential security advisories

USAGE:
    version-checker [FLAGS] [OPTIONS]

FLAGS:
    -h, --help         Prints help information
    -N, --no-update    Disables the "Update Available" message until next use
    -V, --version      Prints version information

OPTIONS:
    -m, --manifest <manifest>    The path to a Cargo.toml file, if missing, the program will attempt to auto-locate the
                                 Cargo.toml

```

## No Update
```
version-checker --no-update
```
Hides the "Update Available" message from being printed to the terminal

## Manifest
```
version-checker --manifest ./path/to/Cargo.toml
```
Processes the indicated manifest file instead of trying to find the default one automatically

