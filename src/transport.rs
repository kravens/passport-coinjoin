// SPDX-FileCopyrightText: 2026 Kevin Ravensberg <kevinravensberg@proton.me>
// SPDX-License-Identifier: MIT

//! wallet-rpc v2 over a vendor HID interface the app registers with `os/usbdev`.
//!
//! Ported from the `os/wallet-rpc` system service on the KeyOS
//! `feature/passport-coinjoin` branch; the host side is Wasabi's `Hwi/Passport`
//! client, which finds the interface by its vendor usage page. The engine stays
//! with the UI thread that owns it: every complete frame crosses the event loop
//! and its reply is awaited here, so an authorization is answered only once the
//! user has slid, and everything else at once.
//!
//! On a retail Prime, KeyOS reserves the interface messages for Foundation-signed
//! apps (docs/keyos-usbdev-request.md). The app measures that instead of assuming
//! it, and the home screen says what it found.

use std::{cell::RefCell, sync::mpsc};
#[cfg(feature = "usb")]
use std::time::Duration;

#[cfg(feature = "usb")]
use slint_keyos_platform::slint;
#[cfg(feature = "usb")]
use wallet_rpc_core::protocol::{response, STATUS_ERR_DENIED, STATUS_ERR_INTERNAL};

/// What the transport found when it started.
pub enum Status {
    /// The interface is registered; rounds arrive over it.
    #[cfg(feature = "usb")]
    Serving { interface: usize },
    /// `os/usbdev` did not admit this app within the timeout: the simulator runs none, and a KeyOS that
    /// grants the app nothing on it refuses the connection outright.
    #[cfg(feature = "usb")]
    Unreachable,
    /// `os/usbdev` answered but would not give this app an interface.
    #[cfg(feature = "usb")]
    Refused(String),
    /// Built without the `usb` feature: the retail flavour, since the SDK refuses the grants it needs.
    #[cfg(not(feature = "usb"))]
    NotBuilt,
}

impl Status {
    pub fn is_serving(&self) -> bool {
        #[cfg(feature = "usb")]
        {
            matches!(self, Status::Serving { .. })
        }
        #[cfg(not(feature = "usb"))]
        {
            false
        }
    }

    pub fn line(&self) -> String {
        match self {
            #[cfg(feature = "usb")]
            Status::Serving { interface } => format!("USB interface {interface} up. Waiting for Wasabi."),
            #[cfg(feature = "usb")]
            Status::Unreachable => "No USB server reachable from this app (simulator, or KeyOS refused the connection).".into(),
            #[cfg(feature = "usb")]
            Status::Refused(why) => format!("KeyOS refused this app a USB interface: {why}. See docs/keyos-usbdev-request.md."),
            #[cfg(not(feature = "usb"))]
            Status::NotBuilt => "KeyOS does not let a third-party app own a USB interface yet (docs/keyos-usbdev-request.md), so rounds cannot reach the device. The request below is local; everything after it is the real engine.".into(),
        }
    }
}

/// A frame from the host, and where its reply goes.
pub type HostFrame = (Vec<u8>, mpsc::Sender<Vec<u8>>);

thread_local! {
    static HANDLER: RefCell<Option<Box<dyn FnMut(HostFrame)>>> = const { RefCell::new(None) };
}

/// Registers, on the UI thread, what answers host frames. An empty frame means the host gave up
/// waiting for the user, and whatever is pending should leave the screen.
pub fn on_host_frame(handler: Box<dyn FnMut(HostFrame)>) {
    HANDLER.with(|h| *h.borrow_mut() = Some(handler));
}

#[cfg(feature = "usb")]
pub use interface::start;

#[cfg(not(feature = "usb"))]
pub fn start() -> Status {
    Status::NotBuilt
}

/// How long a host is kept waiting for the user to decide; Wasabi gives up at 120 s.
#[cfg(feature = "usb")]
const APPROVAL_WAIT: Duration = Duration::from_secs(110);

/// Hands one frame to the UI thread and waits for its reply.
#[cfg(feature = "usb")]
fn answer(frame: Vec<u8>) -> Vec<u8> {
    let command = frame.get(1).copied().unwrap_or(0);
    let (reply, replies) = mpsc::channel();
    if dispatch(frame, reply).is_err() {
        return response(command, STATUS_ERR_INTERNAL, &[]);
    }
    replies.recv_timeout(APPROVAL_WAIT).unwrap_or_else(|_| {
        // The user did not decide before the host gave up: take the request off the screen.
        let _ = dispatch(Vec::new(), mpsc::channel().0);
        response(command, STATUS_ERR_DENIED, &[])
    })
}

#[cfg(feature = "usb")]
fn dispatch(frame: Vec<u8>, reply: mpsc::Sender<Vec<u8>>) -> Result<(), slint::EventLoopError> {
    slint::invoke_from_event_loop(move || {
        HANDLER.with(|h| {
            if let Some(handler) = h.borrow_mut().as_mut() {
                handler((frame, reply));
            }
        })
    })
}

#[cfg(feature = "usb")]
mod interface {
    use super::*;
    use usbdev::messages::*;
    use wallet_rpc_core::frames::{split_frame, Reassembler, REPORT_LEN};

    usbdev::use_api!();

    pub fn start() -> Status {
        let Some(usb) = UsbDevice::try_connect(Duration::from_secs(2)) else {
            return Status::Unreachable;
        };
        match serve(usb) {
            Ok(interface) => Status::Serving { interface },
            Err(why) => Status::Refused(why),
        }
    }

    const IFCE_CLASS: u8 = 0x03; // Human Interface Device
    const IFCE_SUBCLASS: u8 = 0x00;
    const IFCE_PROTOCOL: u8 = 0x00;
    const ENDPOINTS: [EndpointProperties; 2] = [
        EndpointProperties {
            ep_type: EndpointType::Interrupt,
            ep_direction: EndpointDirection::Out,
            max_packet_len: REPORT_LEN as u16,
            interval: 5,
        },
        EndpointProperties {
            ep_type: EndpointType::Interrupt,
            ep_direction: EndpointDirection::In,
            max_packet_len: REPORT_LEN as u16,
            interval: 5,
        },
    ];
    const FUNC_DESCRIPTOR: [u8; 9] = [
        0x09, // bLength
        0x21, // bDescriptorType: HID
        0x11, 0x01, // bcdHID 1.11
        0x21, // bCountryCode: US
        0x01, // bNumDescriptors
        0x22, // bDescriptorType: Report
        REPORT_DESCRIPTOR.len() as u8, 0, // wDescriptorLength
    ];
    /// Vendor usage page 0xFF00, one 64-byte input and one 64-byte output report; Wasabi matches on the page.
    const REPORT_DESCRIPTOR: [u8; 34] = [
        0x06, 0x00, 0xFF, // Usage Page: Vendor Defined 0xFF00
        0x09, 0x01, // Usage: Vendor Usage 1
        0xA1, 0x01, // Collection: Application
        0x09, 0x20, // Usage: Input Report Data
        0x15, 0x00, // Logical Minimum: 0
        0x26, 0xFF, 0x00, // Logical Maximum: 255
        0x75, 0x08, // Report Size: 8 bits
        0x95, REPORT_LEN as u8, // Report Count
        0x81, 0x02, // Input: Data | Variable | Absolute
        0x09, 0x21, // Usage: Output Report Data
        0x15, 0x00, // Logical Minimum: 0
        0x26, 0xFF, 0x00, // Logical Maximum: 255
        0x75, 0x08, // Report Size: 8 bits
        0x95, REPORT_LEN as u8, // Report Count
        0x91, 0x02, // Output: Data | Variable | Absolute
        0xC0, // End Collection
    ];

    /// Answers the host's HID class requests for our interface; anything else is the OS's.
    struct SetupResponder {
        interface_num: u16,
    }

    impl server::ServerMessages for SetupResponder {
        const NAME: &'static str = "";

        fn messages() -> &'static [server::MessageDef<Self>] {
            use server::MessageId;
            &[(SetupPacketCallback::ID, server::handle_blocking_archive_message::<SetupPacketCallback, _>)]
        }
    }

    impl server::Server for SetupResponder {}

    impl server::BlockingArchiveHandler<SetupPacketCallback> for SetupResponder {
        fn handle(
            &mut self,
            SetupPacketCallback(msg): SetupPacketCallback,
            _sender: xous::PID,
            _context: &mut server::ServerContext<Self>,
        ) -> Option<Vec<u8>> {
            if msg.index != self.interface_num {
                return None;
            }
            match (msg.request_type, msg.request, msg.value) {
                (0x81, 0x06, 0x2200) => Some(REPORT_DESCRIPTOR.to_vec()), // GET_DESCRIPTOR: report
                (0x81, 0x06, 0x2100) => Some(FUNC_DESCRIPTOR.to_vec()),   // GET_DESCRIPTOR: HID
                (0x21, 0x0a, _) => Some(Vec::new()),                       // SET_IDLE
                _ => None,
            }
        }
    }

    /// The Prime keeps its own vendor and product ids; this becomes one more interface of that device.
    fn serve(usb: UsbDevice) -> Result<usize, String> {
        let interface = usb.registered_interfaces().map_err(|e| format!("NumInterfaces {e:?}"))?;
        usb.register_setup_responder(SetupResponder { interface_num: interface as u16 })
            .map_err(|e| format!("RegisterSetupResponder {e:?}"))?;
        let [ep_out, ep_in] = usb
            .register_interface(IFCE_CLASS, IFCE_SUBCLASS, IFCE_PROTOCOL, &ENDPOINTS, &FUNC_DESCRIPTOR)
            .map_err(|e| format!("RegisterInterface {e:?}"))?;
        std::thread::spawn(move || pump(usb, ep_out, ep_in));
        Ok(interface)
    }

    /// Reassembles request frames from reports, answers them, and splits the replies back into reports.
    fn pump(usb: UsbDevice, mut ep_out: UsbEndpoint, mut ep_in: UsbEndpoint) {
        let flags = xous::MemoryFlags::W | xous::MemoryFlags::POPULATE;
        let (Ok(read_buffer), Ok(mut write_buffer)) =
            (xous::map_memory(None, None, 0x1000, flags), xous::map_memory(None, None, 0x1000, flags))
        else {
            log::error!("usb: no report buffers");
            return;
        };
        let mut reassembler = Reassembler::default();

        loop {
            match ep_out.read_buf(read_buffer, REPORT_LEN as u16) {
                Ok(len) => {
                    let Some(frame) = reassembler.push_report(&read_buffer.as_slice::<u8>()[..len]) else {
                        continue;
                    };
                    for report in split_frame(&answer(frame)) {
                        write_buffer.as_slice_mut()[..report.len()].copy_from_slice(&report);
                        if let Err(e) = ep_in.write_buf(write_buffer, report.len() as u16) {
                            log::error!("usb write: {e:?}");
                            break;
                        }
                    }
                }
                Err(UsbError::HostDisconnected) => {
                    if let Err(e) = usb.wait_for_connection() {
                        log::warn!("usb: {e:?}");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                Err(e) => {
                    log::error!("usb read: {e:?}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}
