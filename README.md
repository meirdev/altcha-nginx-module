# ngx-http-altcha-module

A dynamic NGINX module written in Rust that exposes
[ALTCHA](https://altcha.org) proof-of-work challenges as request variables.

## Directives

All directives are valid in `http`, `server`, and `location` contexts and merge
top-down (`http` → `server` → `location`).

| Directive                                       | Maps to `CreateChallengeOptions` field | Default             |
| ----------------------------------------------- | -------------------------------------- | ------------------- |
| `altcha_hmac_signature_secret <secret>;`        | `hmac_signature_secret`                | **required**        |
| `altcha_hmac_key_signature_secret <secret>;`    | `hmac_key_signature_secret`            | required for verify |
| `altcha_algorithm <name>;`                      | `algorithm`                            | `PBKDF2/SHA-256`    |
| `altcha_cost <n>;`                              | `cost`                                 | `100000`            |
| `altcha_hmac_algorithm sha256\|sha384\|sha512;` | `hmac_algorithm`                       | `sha256`            |
| `altcha_key_length <n>;`                        | `key_length` (1..=64)                  | `32`                |
| `altcha_key_prefix <hex>;`                      | `key_prefix`                           | `00`                |
| `altcha_expires <duration>;`                    | computed `expires_at = now + ttl`      | `5m`                |
| `altcha_verify_input <variable>;`               | runtime input source for verify        | required for verify |

`altcha_expires` accepts `Ns`, `Nm`, `Nh`, `Nd`, or a bare integer (seconds).

`altcha_verify_input` accepts any nginx variable expression — typical values
are `$arg_altcha` (query string `?altcha=…`), `$http_x_altcha` (custom header),
or any value populated by another module. The expected payload format is the
standard ALTCHA client payload: base64-encoded JSON of `{challenge, solution}`.
Both standard and URL-safe base64 are accepted.

## Building

```bash
cargo build --release
```

The resulting cdylib is at `target/release/libngx_http_altcha_module.so`. By
default the build vendors and compiles nginx itself (via `ngx/vendored`); to
build against a system nginx, see the [ngx-rust documentation](https://github.com/nginx/ngx-rust).

## Example

See [example/nginx.conf](example/nginx.conf) for a complete working config.
