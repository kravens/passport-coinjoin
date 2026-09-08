// SPDX-FileCopyrightText: 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-FileCopyrightText: 2026 Kevin Ravensberg <kevinravensberg@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

//! The device role of KeyOS's `os/usbdev` server: register one interface with
//! its endpoints, answer the host's setup packets for it, and move reports.
//!
//! Adapted from `api/usb/src/device` in KeyOS. The two endpoint enums and the
//! error type come from hardware crates there; they are repeated here in the same
//! declaration order, which is what rkyv's archived form depends on, so the bytes
//! on the wire are the ones `os/usbdev` expects.

use std::time::Duration;

use server::{CheckedConn, CheckedPermissions, MessageAllowed, MessageId as _};

pub use messages::*;

pub mod messages {
    use server::{AsScalar, FromScalar};

    /// `atsama5d27::udphs::EndpointType`, same order.
    #[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub enum EndpointType {
        Control = 0,
        Isochronous = 1,
        Bulk = 2,
        Interrupt = 3,
    }

    /// `atsama5d27::udphs::EndpointDirection`, same order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub enum EndpointDirection {
        Out = 0,
        In = 1,
    }

    #[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub struct EndpointProperties {
        pub ep_type: EndpointType,
        pub ep_direction: EndpointDirection,
        pub max_packet_len: u16,
        pub interval: u8,
    }

    /// `ehci::EhciError`, same order.
    #[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub enum EhciError {
        InvalidCapsLen,
        EndpointNotOpen,
        InvalidAddress,
        Disconnected,
        DescriptorError,
        OutOfPoolItems,
        SetupUnsuccessful,
        Stalled,
        ControllerDisabled,
    }

    #[derive(Debug, Clone, Copy, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub enum UsbError {
        XousError(usize),
        EhciError(EhciError),
        Other,
        NotFound,
        NotClaimed,
        DataTooLarge,
        AlreadyRegistered,
        WrongDirection,
        Busy,
        HostDisconnected,
        InvalidParameter,
    }

    impl From<xous::Error> for UsbError {
        fn from(value: xous::Error) -> Self { UsbError::XousError(value.to_usize()) }
    }

    impl AsScalar<2> for UsbError {
        fn as_scalar(&self) -> [u32; 2] {
            match self {
                UsbError::XousError(e) => [1, *e as u32],
                UsbError::EhciError(e) => [2, *e as u32 + 1],
                UsbError::Other => [3, 0],
                UsbError::NotFound => [4, 0],
                UsbError::NotClaimed => [5, 0],
                UsbError::DataTooLarge => [6, 0],
                UsbError::AlreadyRegistered => [7, 0],
                UsbError::WrongDirection => [8, 0],
                UsbError::Busy => [9, 0],
                UsbError::HostDisconnected => [10, 0],
                UsbError::InvalidParameter => [11, 0],
            }
        }
    }

    impl FromScalar<2> for UsbError {
        fn from_scalar(value: [u32; 2]) -> Self {
            match value[0] {
                1 => UsbError::XousError(value[1] as usize),
                2 => UsbError::EhciError(match value[1] {
                    1 => EhciError::InvalidCapsLen,
                    2 => EhciError::EndpointNotOpen,
                    3 => EhciError::InvalidAddress,
                    4 => EhciError::Disconnected,
                    5 => EhciError::DescriptorError,
                    6 => EhciError::OutOfPoolItems,
                    7 => EhciError::SetupUnsuccessful,
                    8 => EhciError::Stalled,
                    9 => EhciError::ControllerDisabled,
                    _ => EhciError::Disconnected,
                }),
                3 => UsbError::Other,
                4 => UsbError::NotFound,
                5 => UsbError::NotClaimed,
                6 => UsbError::DataTooLarge,
                7 => UsbError::AlreadyRegistered,
                8 => UsbError::WrongDirection,
                9 => UsbError::Busy,
                10 => UsbError::HostDisconnected,
                11 => UsbError::InvalidParameter,
                _ => UsbError::Other,
            }
        }
    }

    impl From<usize> for UsbError {
        fn from(value: usize) -> Self { Self::from_scalar([value as u32, 0]) }
    }

    impl From<UsbError> for usize {
        fn from(value: UsbError) -> Self { AsScalar::<2>::as_scalar(&value)[0] as usize }
    }

    /// A control request from the host, as `os/usbdev` hands it to the setup responder.
    #[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub struct SetupPacket {
        pub request_type: u8,
        pub request: u8,
        pub value: u16,
        pub index: u16,
        pub length: u16,
    }

    /// Sent by `os/usbdev` to the responder registered with `RegisterSetupResponder`; the reply is the
    /// descriptor to return, an empty vector for an acknowledged request, or `None` to let the OS stall it.
    #[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    pub struct SetupPacketCallback(pub SetupPacket);

    impl server::BlockingArchive for SetupPacketCallback {
        type Response = Option<Vec<u8>>;
    }

    impl server::MessageId for SetupPacketCallback {
        const ID: xous::MessageId = 0;
        const SERVER: &str = "";
    }

    #[derive(Debug, Clone, server::Message, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    #[response(Result<Vec<u8>, UsbError>)]
    pub struct RegisterInterface {
        pub if_class: u8,
        pub if_subclass: u8,
        pub if_protocol: u8,
        pub endpoints: Vec<EndpointProperties>,
        pub interface_functional_descriptors: Vec<u8>,
        pub associated_interface_count: u8,
    }

    #[derive(Debug, server::Message)]
    #[response(())]
    pub struct WaitForConnection;

    #[derive(Debug, server::Message)]
    #[response(Result<usize, UsbError>)]
    pub struct ReadEndpoint {
        pub buf: xous::MemoryRange,
        pub endpoint: u8,
        pub length: u16,
    }

    impl From<server::SimpleMemoryMessage> for ReadEndpoint {
        fn from(msg: server::SimpleMemoryMessage) -> Self {
            Self { buf: msg.buf, endpoint: msg.arg1 as u8, length: msg.arg2 as u16 }
        }
    }

    impl From<ReadEndpoint> for server::SimpleMemoryMessage {
        fn from(read: ReadEndpoint) -> Self {
            Self { buf: read.buf, arg1: read.endpoint as usize, arg2: read.length as usize }
        }
    }

    #[derive(Debug, server::Message)]
    #[response(Result<usize, UsbError>)]
    pub struct WriteEndpoint {
        pub buf: xous::MemoryRange,
        pub endpoint: u8,
        pub length: u16,
    }

    impl From<server::SimpleMemoryMessage> for WriteEndpoint {
        fn from(msg: server::SimpleMemoryMessage) -> Self {
            Self { buf: msg.buf, endpoint: msg.arg1 as u8, length: msg.arg2 as u16 }
        }
    }

    impl From<WriteEndpoint> for server::SimpleMemoryMessage {
        fn from(write: WriteEndpoint) -> Self {
            Self { buf: write.buf, arg1: write.endpoint as usize, arg2: write.length as usize }
        }
    }

    #[derive(Debug, server::Message, Clone)]
    #[response(usize)]
    pub struct NumInterfaces;

    #[derive(Debug, server::Message, Clone)]
    #[response(Result<(), UsbError>)]
    pub struct RegisterSetupResponder(pub xous::CID);

    #[derive(Debug, server::Message, Clone)]
    #[response(bool)]
    pub struct IsCableConnected;
}

/// Declares the app's permissions on `os/usbdev` (the ones its manifest grants) and names the client types.
#[macro_export]
macro_rules! use_api {
    () => {
        mod usbdev_permissions {
            use usbdev::messages::*;
            #[derive(Clone, Default, server::Permissions)]
            #[server_name = "os/usbdev"]
            pub struct UsbDevPermissions;
        }
        type UsbDevice = usbdev::UsbDevice<usbdev_permissions::UsbDevPermissions>;
        type UsbEndpoint = usbdev::UsbEndpoint<usbdev_permissions::UsbDevPermissions>;
    };
}

pub struct UsbDevice<P: CheckedPermissions>(CheckedConn<P>);

impl<P: CheckedPermissions> UsbDevice<P> {
    /// Connects only if the server exists and admits this app, giving up after `timeout`: the
    /// simulator runs no `os/usbdev`, and the blocking default would wait in the name server forever.
    pub fn try_connect(timeout: Duration) -> Option<Self> {
        CheckedConn::try_connect_with_timeout(timeout).map(Self)
    }

    /// Whether a host is plugged in (VBUS has power).
    pub fn is_cable_connected(&self) -> Result<bool, UsbError>
    where
        P: MessageAllowed<IsCableConnected>,
    {
        Ok(self.0.try_send_blocking_scalar(IsCableConnected)?)
    }

    /// How many interfaces the device already exposes; ours becomes the next one.
    pub fn registered_interfaces(&self) -> Result<usize, UsbError>
    where
        P: MessageAllowed<NumInterfaces>,
    {
        Ok(self.0.try_send_blocking_scalar(NumInterfaces)?)
    }

    /// Runs `responder` as a server of its own and has `os/usbdev` send it the host's setup packets.
    pub fn register_setup_responder<S>(&self, responder: S) -> Result<(), UsbError>
    where
        S: server::Server + server::BlockingArchiveHandler<SetupPacketCallback> + Send + 'static,
        P: MessageAllowed<RegisterSetupResponder>,
    {
        let pid = self.0.get_remote_pid();
        let cid = server::listen_and_connect(responder, pid);
        xous::allow_messages_on_connection(pid, cid, SetupPacketCallback::ID..(SetupPacketCallback::ID + 1))?;
        self.0.try_send_blocking_scalar(RegisterSetupResponder(cid))?
    }

    /// Registers one interface and returns its endpoints in the order given.
    pub fn register_interface<const N: usize>(
        &self,
        if_class: u8,
        if_subclass: u8,
        if_protocol: u8,
        endpoints: &[EndpointProperties; N],
        interface_functional_descriptors: &[u8],
    ) -> Result<[UsbEndpoint<P>; N], UsbError>
    where
        P: MessageAllowed<RegisterInterface>,
    {
        let numbers = self.0.try_send_blocking_archive(RegisterInterface {
            if_class,
            if_subclass,
            if_protocol,
            endpoints: endpoints.to_vec(),
            interface_functional_descriptors: interface_functional_descriptors.to_vec(),
            associated_interface_count: 0,
        })??;
        if numbers.len() < N {
            return Err(UsbError::Other);
        }
        Ok(core::array::from_fn(|i| UsbEndpoint { connection: self.0.clone(), endpoint_number: numbers[i] }))
    }

    /// Blocks until the host has configured the device.
    pub fn wait_for_connection(&self) -> Result<(), UsbError>
    where
        P: MessageAllowed<WaitForConnection>,
    {
        Ok(self.0.try_send_blocking_scalar(WaitForConnection)?)
    }
}

pub struct UsbEndpoint<P: CheckedPermissions> {
    connection: CheckedConn<P>,
    endpoint_number: u8,
}

impl<P: CheckedPermissions> UsbEndpoint<P> {
    /// One report from the host into `buf`; returns how many bytes arrived.
    pub fn read_buf(&mut self, buf: xous::MemoryRange, length: u16) -> Result<usize, UsbError>
    where
        P: MessageAllowed<ReadEndpoint>,
    {
        self.connection.try_lend_mut(ReadEndpoint { buf, endpoint: self.endpoint_number, length })?
    }

    /// One report from `buf` to the host; returns how many bytes went.
    pub fn write_buf(&mut self, buf: xous::MemoryRange, length: u16) -> Result<usize, UsbError>
    where
        P: MessageAllowed<WriteEndpoint>,
    {
        self.connection.try_lend_mut(WriteEndpoint { buf, endpoint: self.endpoint_number, length })?
    }
}
