# Email to Foundation

*To hello@foundation.xyz, after the KeyOS request is posted. Replace the link and the version.*

---

Subject: Coinjoin Signer for Passport Prime: USB interface for third-party apps, security review, dev unit

Hi,

I run the coinjoin.nl WabiSabi coordinator and maintain the Coinjoin Signer app in your app showcase, which
lets a Passport Prime sign coinjoin rounds for Wasabi Wallet unattended under a policy the user approves on
the device. The engine, the app (SDK 1.0.0, KeyOS 1.4, verified on a retail Prime) and the Wasabi client are
done: https://github.com/kravens/passport-coinjoin and https://github.com/kravens/WalletWasabi/releases/tag/v2.8.2.4.

What stops it from working is transport. KeyOS reserves the `os/usbdev` interface messages for Foundation-signed
apps, so the HID transport the app carries cannot be granted on a retail unit. I have filed the request with
a concrete proposal (a grouped, user-grantable permission on those messages) and what we measured:
<link to the KeyOS issue or forum post>.

Three things I would like to ask:

1. Whether you would take that permission group, or prefer another route (the same transport exists as a
   system service on my KeyOS branch, and CTAP-HID vendor commands via `os/fido` would also carry it).
2. The wallet-app security review your developer docs mention. The app touches the app-scoped seed and signs
   with it; I would rather have it reviewed before anyone funds it.
3. Whether a dev unit or a Foundation signature of a reviewed build is a way to run the transport while the
   permission model catches up.

Thanks,
Kevin Ravensberg
coinjoin.nl
