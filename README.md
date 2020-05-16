# 👧 gurl

A [Gemini](https://gemini.circumlunar.space/) command line interface similar to [curl](https://curl.haxx.se/) written in [Zig](https://ziglang.org/).

## Project State

- [x] Successful TLS 1.2 handshake
- [x] Successful GET request header exchange
- [x] Successful body download
- [x] header parsing
- [x] URL parser
- [x] DNS resolving
- [ ] MIME parsing
- [ ] All of the correct heading handling
  - [ ] Following redirects
  - [ ] …

## Dependencies

- [Zig 0.6.0](https://ziglang.org/download/#release-0.6.0) or newer
- [BearSSL](https://bearssl.org/) (provided as submodule)
- [zig-network](https://github.com/MasterQ32/zig-network) (provided as submodule)

## Build Instructions

1. Refresh submodules (`git submodule init`, `git submodule update`)
2. Build bearssl (just run `make`)
3. Build gurl (`zig build`)