# Let a third-party app own one USB device interface

*Draft of a feature request for [Foundation-Devices/KeyOS](https://github.com/Foundation-Devices/KeyOS/issues).
If issue creation is restricted, post it in the [developers category](https://community.foundation.xyz/c/developers)
and link it from an email to hello@foundation.xyz.*

---

**Title:** Let a third-party app own one USB device interface (grouped permission for `os/usbdev`)

## What

A permission group on the `os/usbdev` messages an app needs to register one interface and move data on
its endpoints, so a sideloaded app can declare them and the user can grant them:

| message | today (`api/usb/manifest.toml`, main) | proposed |
|---|---|---|
| `RegisterInterface`, `RegisterSetupResponder`, `WaitForConnection`, `ReadEndpoint`, `WriteEndpoint`, `SetEndpointStalled`, `NumInterfaces` | no `permissionGroup` → Foundation-signed only | `permissionGroup = "device-connectivity.usb-device-interface"`, `approval = "grantOnFirstUse"` |
| `IsCableConnected`, `IsDeviceMode`, `IsDeviceEmulationEnabled`, `IsDeviceEmulationConnected` | `device-connectivity.usb-device-status`, `autoAllow` | unchanged |
| `SetVidPid`, `ResetController`, `SetDeviceEmulationEnabled`, `RegisterCapability` | Foundation-signed only | unchanged |

Semantics that keep it safe: one interface per app (a second `RegisterInterface` from the same process is
refused), endpoints are owned by the registering process and torn down when it exits, the device's VID/PID
stay Foundation's, and the interface is one more function of the existing composite device. A host sees an
extra HID or vendor interface with the app's descriptors, nothing else changes.

## Why

- The [capabilities matrix](https://docs.foundation.xyz/developers/capabilities/) lists *USB HID / HWI /
  keyboard driver — `os/usb` — 🚧 Coming*. The gadget side already exists and works; what is missing is a
  way for an app to be granted it.
- SDK `MIGRATIONS.md` §14 names "the USB vendor-interface transport (`usb` crate / `os/usbdev` server)" as
  the canonical missing surface and tells app authors to ship a mock and report it. This is that report.
- The app showcase's [Spark Signer](https://foundation.xyz/app-showcase/spark-signer) describes "USB
  CDC-ACM on hardware"; our [Coinjoin Signer](https://foundation.xyz/app-showcase/coinjoin-signer) needs
  the same for unattended WabiSabi rounds, whose phases run on deadlines of seconds, so QR and Airlock
  file exchange cannot carry them. Issue #19 asks for the same generality for the Envoy relay.

## What we have, and what we measured

- Engine and app: [kravens/passport-coinjoin](https://github.com/kravens/passport-coinjoin) (SDK 1.0.0,
  KeyOS 1.4). The HID transport is written against `api/usb` (`src/transport.rs`, a vendored `os/usbdev`
  client in `vendor/usbdev`) and behind a cargo feature, with a runtime probe instead of an `unwrap`.
- Host: Wasabi Wallet [Preview 4](https://github.com/kravens/WalletWasabi/releases/tag/v2.8.2.4) speaks the
  protocol over HID (`WalletWasabi/Hwi/Passport`), matching the interface by its vendor usage page 0xFF00 on
  the Prime's `1307:0165`.
- Measured with SDK 1.0.0 (`foundation` 1.0.0, workspace 039881500da0): the toolchain refuses the grants
  before anything reaches a device, since no server manifest for `os/usbdev` ships with the SDK.

  ```
  $ foundation build      # with "os/usbdev" = [...] in app-config.toml
  Error: Failed to resolve permissions for .../coinjoin-signer: app-config.toml declares messages that no
  server manifest shipped with the SDK declares (check the server and message names): os/usbdev:IsCableConnected,
  os/usbdev:NumInterfaces, os/usbdev:ReadEndpoint, os/usbdev:RegisterInterface, os/usbdev:RegisterSetupResponder,
  os/usbdev:WaitForConnection, os/usbdev:WriteEndpoint
  ```

  With a copy of that manifest dropped into the SDK's `lib/keyos/api/` and the interface messages given the
  proposed group, the same `foundation build` accepts the grants and produces a signed bundle: the toolchain
  needs nothing else. With the upstream manifest as it is (no `permissionGroup`) it would report them as
  Foundation-only, and KeyOS 1.4 enforces the same at connect time. So the ask is two small things in one
  place: ship the `usb` API manifest with the SDK, and group these messages.

## Alternatives already written

- The same transport as a Foundation-signed system service, `os/wallet-rpc`, on
  [kravens/KeyOS `feature/passport-coinjoin`](https://github.com/kravens/KeyOS/tree/feature/passport-coinjoin),
  if a vendor interface for apps is not on the roadmap. It is the origin of the app's transport code.
- If `os/fido` (✅ Stable) could route CTAP-HID vendor commands (0x40–0x7F) to an app, that would carry the
  same 64-byte frames over an interface every OS already has a driver for. Is that a direction you would
  consider?
- The earlier QuantumLink proposal (`AuthorizeCoinjoin` + `GetOwnershipProof` messages) still stands, but
  routes rounds through a phone, which is a poor fit for an unattended desktop signer, and the wallet-sync
  messages are `requiredSignature = "foundation"` anyway.

## Questions

1. Is a grouped `os/usbdev` permission something you would accept a PR for, and is
   `device-connectivity.usb-device-interface` / `grantOnFirstUse` the shape you would want?
2. Until then, is Foundation-signing a reviewed third-party app a path, and what does the wallet-app
   security review the docs mention involve?
3. Does a dev unit behave differently here, or is the gate the app signature alone?
