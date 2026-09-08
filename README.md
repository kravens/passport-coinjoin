# Coinjoin Signer — Passport Prime app

A KeyOS SDK app that makes a Passport Prime an unattended WabiSabi coinjoin
signer for Wasabi Wallet. **Everything on the key side is real**: the seed is the
app-scoped seed `os/security` hands the app (one consent on the trusted display,
at authorization), the session derives and caches the account keys, and every
round produces a real SLIP-0019 ownership proof or BIP-341 signature from them,
checked against the policy the user slid to approve. The engine is
[`crates/wallet-rpc-core`](crates/wallet-rpc-core) (46 unit tests), the same code
as the `os/wallet-rpc` service on the
[KeyOS branch](https://github.com/kravens/KeyOS/tree/feature/passport-coinjoin).

**The transport is written, and KeyOS will not grant it.** `src/transport.rs`
serves wallet-rpc v2 over a vendor HID interface the app registers with
`os/usbdev`, the interface Wasabi's Passport client looks for. KeyOS 1.4 reserves
those messages for Foundation-signed apps, and the SDK refuses to build an app
that declares them, so on a retail Prime the home screen says so and a local
demo request stands in for the host. The request to Foundation, with what was
measured, is [docs/keyos-usbdev-request.md](docs/keyos-usbdev-request.md).

## Screens

| Home | Authorize | Session | Complete |
|---|---|---|---|
| ![Home](screenshots/home.png) | ![Authorize](screenshots/authorize.png) | ![Session](screenshots/session.png) | ![Complete](screenshots/complete.png) |

1. **Home** — idle, "Waiting for Wasabi".
2. **Authorize** — the one human approval: coordinator, account, per-round fee
   cap, round budget, 12-hour expiry, then slide-to-authorize.
3. **Session active** — live round counter; each "Simulate round" runs the real
   engine (SLIP-0019 proof for the next index, coordinator-bound commitment) and
   shows the result; revoke closes the session.
4. **Complete** — session summary.

Screenshots captured with the KeyOS simulator's own screenshot button while the
signed app runs on it — official Prime bezel, KeyOS status bar, live engine
output (the Session screen shows a real SLIP-19 proof result). A short demo
recording from the simulator's record button:
[`screenshots/demo.mp4`](screenshots/demo.mp4).

The buttons use a small local `ui/cjbutton.slint` instead of the SDK `Button`:
the lightweight preview viewer doesn't populate the theme's button style/size
structs, so the stock `Button` renders invisible there — the local one paints
in the viewer and on-device alike (it uses `palette-*`, which have literal
defaults).

## Build & run (Foundation SDK 1.0.0)

Needs the Foundation SDK 1.0.0 (`~/.foundation/sdk/current`) and Nix. The app
reaches the SDK through the `.foundation-sdk/current` link `foundation` maintains.

```sh
foundation cert gen coinjoin.nl \                  # one-time publisher cert
  --publisher-name coinjoin.nl --contact-email you@example.com
foundation build      # signed bundle for armv7a-unknown-xous-elf
foundation pack       # one .app to install from Settings > Apps (no Developer Mode)
foundation sideload   # or straight onto a connected Prime over usb-debug
```

Run them inside the SDK's Nix shell, naming the SDK root (the shell otherwise
takes the current directory for it):

```sh
FOUNDATION_SDK_ROOT=$(readlink -f ~/.foundation/sdk/current) \
  nix develop ~/.foundation/sdk/current --command bash -c \
  '"$FOUNDATION_SDK_ROOT/bin/foundation" build'
```

Two flavours:

- **retail** (`foundation build`, `app-config.toml`): what a retail Prime runs
  today. No `os/usbdev` grant, the transport is compiled out, the home screen
  says why, and the demo request drives the real engine.
- **usb** (`scripts/build-usb.sh`, `app-config.usb.toml`, cargo feature `usb`):
  the HID transport compiled in. The SDK refuses the grants it needs ("no server
  manifest shipped with the SDK declares ... os/usbdev"), so this flavour builds
  only where that check is satisfied: a Foundation build, or an SDK that ships
  the `usb` API manifest with the interface messages grouped. Nothing in it has
  met hardware yet.

To iterate on the UI headlessly (no device, no GUI simulator), render individual
components with the preview viewer under Xvfb — see `ui/_preview.slint` for the
480×800 window harness (one wrapper per screen).

Build notes for the `wallet-rpc-core` link: the app patches `getrandom` with a
Xous-backend copy (`vendor/getrandom`, its `xous` dep pointed at the SDK's
`xous-rs` — the KeyOS repo's copy would drag a second `keyos` package into the
graph and collide), and `.cargo/config.toml` sets
`CC_armv7a_unknown_xous_elf=arm-none-eabi-gcc` for `secp256k1-sys`.

## Status

v0.4.0, SDK 1.0.0, KeyOS 1.4. The retail flavour installs and runs on a retail
Passport Prime with a self-generated publisher cert (Allowed Publishers). Not for
real funds until a host can reach it: the USB transport waits on Foundation, see
[docs/keyos-usbdev-request.md](docs/keyos-usbdev-request.md) and
[docs/foundation-email.md](docs/foundation-email.md).

What a host will find once it can: the wallet-rpc v2 interface on the Prime's
own USB identity (`1307:0165`), report descriptor usage page `0xFF00`, 64-byte
reports; an authorization request opens the Authorize page and is answered when
the user slides (or denied after 110 s, before Wasabi gives up); every other
command is answered from the engine at once. Wasabi Preview 4 and later speak
it (`WalletWasabi/Hwi/Passport`).

## License

This app is [MIT](LICENSE.md), matching Wasabi Wallet — so the Wasabi-facing
integration and this app share one permissive license.

The signing engine it links,
[`wallet-rpc-core`](https://github.com/kravens/KeyOS/tree/feature/passport-coinjoin),
is dual-licensed **`MIT OR GPL-3.0-or-later`** — so the whole app is usable under
MIT, while the engine still merges cleanly into the GPLv3 KeyOS tree when
contributed upstream.
