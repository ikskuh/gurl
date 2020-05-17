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
- [x] TOFU (trust on first use) for SSL connections
- [ ] Client certificates
  - [ ] temporary cert
  - [ ] permanent cert
- [x] Use [XDG directories](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
- [ ] Implement windows port
  - [ ] Port `zig-network` to windows
  - [ ] Implement correct config directory locating for windows

## Dependencies

- [Zig 0.6.0](https://ziglang.org/download/#release-0.6.0) or newer
- [BearSSL](https://bearssl.org/) (provided as submodule)
- [zig-network](https://github.com/MasterQ32/zig-network) (provided as submodule)

## Build Instructions

1. Refresh submodules (`git submodule init`, `git submodule update`)
2. Build gurl (`zig build`)
3. Run `./zig-cache/bin/gurl` 

## Design Considerations

Give the user control over their system and make configuration easy.

### Certificate Trust

- accept any certificate
- auto-accept the cert on first use (TOFU)
- use CAs or ask user on first sight (TOFU+CA)
- always ask on first sight (interactive TOFU)
- auto-accept when first seen in a session (TOFU, no disk usage)
- always ask when first seen in a session (interactive TOFU, no disk usage)

### Future Plans

Correctly adhere to XDG standards and use `xdg-open`

## Tools

Connect with OpenSSL:
```
openssl s_client --connect domain.name -quiet -verify_quiet
```

Dump DER certificate information:
```
openssl x509 -in trust-store/mozz.us/cert-1.der -inform der -text
``` 

Convert DER to PEM:
```
openssl x509 -inform der -in trust-store/gemini.conman.org/cert-0.der -out conman.pem
```