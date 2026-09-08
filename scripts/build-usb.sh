#!/bin/sh
# Builds the USB flavour: the transport compiled in, and the os/usbdev grants it needs in the
# manifest. app-config.toml is static, so it is swapped for the build and put back afterwards.
# Run inside the SDK shell, with the SDK root named (the shell otherwise takes the current directory):
#   FOUNDATION_SDK_ROOT=$(readlink -f ~/.foundation/sdk/current) nix develop ~/.foundation/sdk/current --command sh scripts/build-usb.sh [pack|sideload]
set -e
cd "$(dirname "$0")/.."
cp app-config.toml .app-config.retail.toml
cp app-config.usb.toml app-config.toml
sed -i 's/^usb = \["dep:usbdev"\]$/&\ndefault = ["usb"]/' Cargo.toml
trap 'mv .app-config.retail.toml app-config.toml; sed -i "/^default = \[\"usb\"\]$/d" Cargo.toml' EXIT
"${FOUNDATION_SDK_ROOT:?set FOUNDATION_SDK_ROOT to the SDK directory}/bin/foundation" "${1:-build}"
