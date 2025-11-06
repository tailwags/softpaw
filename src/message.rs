use std::{fmt::Display, string::FromUtf8Error};

use crate::tracing::debug;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid name-list encoding")]
    InvalidNameList(#[from] FromUtf8Error),
    #[error("Invalid message length")]
    InvalidLength,
    #[error("Unsupported message: {0}")]
    UnsupportedMessage(MessageType),
    #[error("Unknown message type: {0}")]
    UnknownMessageType(u8),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    Kexinit = 20,
    Newkeys = 21,
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthBanner = 53,
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

impl TryFrom<u8> for MessageType {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Disconnect),
            20 => Ok(MessageType::Kexinit),
            _ => Err(ParseError::UnknownMessageType(value)),
        }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Disconnect => write!(f, "SSH_MSG_DISCONNECT"),
            MessageType::Ignore => write!(f, "SSH_MSG_IGNORE"),
            MessageType::Unimplemented => write!(f, "SSH_MSG_UNIMPLEMENTED"),
            MessageType::Debug => write!(f, "SSH_MSG_DEBUG"),
            MessageType::ServiceRequest => write!(f, "SSH_MSG_SERVICE_REQUEST"),
            MessageType::ServiceAccept => write!(f, "SSH_MSG_SERVICE_ACCEPT"),
            MessageType::Kexinit => write!(f, "SSH_MSG_KEXINIT"),
            MessageType::Newkeys => write!(f, "SSH_MSG_NEWKEYS"),
            MessageType::UserauthRequest => write!(f, "SSH_MSG_USERAUTH_REQUEST"),
            MessageType::UserauthFailure => write!(f, "SSH_MSG_USERAUTH_FAILURE"),
            MessageType::UserauthSuccess => write!(f, "SSH_MSG_USERAUTH_SUCCESS"),
            MessageType::UserauthBanner => write!(f, "SSH_MSG_USERAUTH_BANNER"),
            MessageType::GlobalRequest => write!(f, "SSH_MSG_GLOBAL_REQUEST"),
            MessageType::RequestSuccess => write!(f, "SSH_MSG_REQUEST_SUCCESS"),
            MessageType::RequestFailure => write!(f, "SSH_MSG_REQUEST_FAILURE"),
            MessageType::ChannelOpen => write!(f, "SSH_MSG_CHANNEL_OPEN"),
            MessageType::ChannelOpenConfirmation => write!(f, "SSH_MSG_CHANNEL_OPEN_CONFIRMATION"),
            MessageType::ChannelOpenFailure => write!(f, "SSH_MSG_CHANNEL_OPEN_FAILURE"),
            MessageType::ChannelWindowAdjust => write!(f, "SSH_MSG_CHANNEL_WINDOW_ADJUST"),
            MessageType::ChannelData => write!(f, "SSH_MSG_CHANNEL_DATA"),
            MessageType::ChannelExtendedData => write!(f, "SSH_MSG_CHANNEL_EXTENDED_DATA"),
            MessageType::ChannelEof => write!(f, "SSH_MSG_CHANNEL_EOF"),
            MessageType::ChannelClose => write!(f, "SSH_MSG_CHANNEL_CLOSE"),
            MessageType::ChannelRequest => write!(f, "SSH_MSG_CHANNEL_REQUEST"),
            MessageType::ChannelSuccess => write!(f, "SSH_MSG_CHANNEL_SUCCESS"),
            MessageType::ChannelFailure => write!(f, "SSH_MSG_CHANNEL_FAILURE"),
        }
    }
}

#[derive(Debug)]
pub enum Message {
    Disconnect(Disconnect),
    Kexinit(Kexinit),
}

#[derive(Debug)]
pub struct Disconnect {
    pub reason_code: ReasonCode,
    pub description: String,
    pub language_tag: String,
}

#[repr(u32)]
#[derive(Debug)]
pub enum ReasonCode {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

#[derive(Debug)]
pub struct Kexinit {
    pub cookie: [u8; 16],
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
    pub languages_client_to_server: Vec<String>,
    pub languages_server_to_client: Vec<String>,
    pub first_kex_packet_follows: bool,
    __reserved: u32,
}

impl Message {
    pub fn parse<B: Buf>(src: &mut B) -> Result<Self, ParseError> {
        let message_type: MessageType = src.get_u8().try_into()?;

        debug!("Received message {message_type}");

        match message_type {
            MessageType::Kexinit => {
                let mut cookie = [0u8; 16];
                src.copy_to_slice(&mut cookie);

                let kex_init = Kexinit {
                    cookie,
                    kex_algorithms: parse_name_list(src)?,
                    server_host_key_algorithms: parse_name_list(src)?,
                    encryption_algorithms_client_to_server: parse_name_list(src)?,
                    encryption_algorithms_server_to_client: parse_name_list(src)?,
                    mac_algorithms_client_to_server: parse_name_list(src)?,
                    mac_algorithms_server_to_client: parse_name_list(src)?,
                    compression_algorithms_client_to_server: parse_name_list(src)?,
                    compression_algorithms_server_to_client: parse_name_list(src)?,
                    languages_client_to_server: parse_name_list(src)?,
                    languages_server_to_client: parse_name_list(src)?,
                    first_kex_packet_follows: src.get_u8() != 0,
                    __reserved: src.get_u32(),
                };

                if src.has_remaining() {
                    return Err(ParseError::InvalidLength);
                }

                Ok(Message::Kexinit(kex_init))
            }

            ty => Err(ParseError::UnsupportedMessage(ty)),
        }
    }

    pub fn into_payload(self) -> Bytes {
        match self {
            Message::Disconnect(disconnect) => disconnect.into_payload(),
            Message::Kexinit(kex_init) => kex_init.into_payload(),
        }
    }
}

impl Disconnect {
    pub fn into_payload(self) -> Bytes {
        let Disconnect {
            reason_code,
            description,
            language_tag,
        } = self;

        let mut payload = BytesMut::new();

        payload.put_u8(MessageType::Disconnect as u8);
        payload.put_u32(reason_code as u32);

        put_string(&mut payload, &description);
        put_string(&mut payload, &language_tag);

        payload.freeze()
    }
}

impl Kexinit {
    pub fn into_payload(self) -> Bytes {
        let Kexinit {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server,
            mac_algorithms_server_to_client,
            compression_algorithms_client_to_server,
            compression_algorithms_server_to_client,
            languages_client_to_server,
            languages_server_to_client,
            first_kex_packet_follows,
            __reserved,
        } = self;

        let mut payload = BytesMut::new();

        payload.put_u8(MessageType::Kexinit as u8);
        payload.put_slice(&cookie);

        put_name_list(&mut payload, kex_algorithms);
        put_name_list(&mut payload, server_host_key_algorithms);
        put_name_list(&mut payload, encryption_algorithms_client_to_server);
        put_name_list(&mut payload, encryption_algorithms_server_to_client);
        put_name_list(&mut payload, mac_algorithms_client_to_server);
        put_name_list(&mut payload, mac_algorithms_server_to_client);
        put_name_list(&mut payload, compression_algorithms_client_to_server);
        put_name_list(&mut payload, compression_algorithms_server_to_client);
        put_name_list(&mut payload, languages_client_to_server);
        put_name_list(&mut payload, languages_server_to_client);

        payload.put_u8(first_kex_packet_follows as u8);
        payload.put_u32(__reserved);

        payload.freeze()
    }
}

fn parse_name_list<B: Buf>(src: &mut B) -> Result<Vec<String>, ParseError> {
    let len = src.get_u32();
    let content = src.copy_to_bytes(len as usize);

    String::from_utf8(content.to_vec())
        .map_err(ParseError::InvalidNameList)
        .map(|s| s.split(',').map(str::to_string).collect())
}

fn put_name_list(src: &mut BytesMut, list: Vec<String>) {
    let list = list.join(",");
    src.put_u32(list.len() as u32);

    src.put_slice(list.as_bytes());
}

fn put_string<S: AsRef<[u8]>>(src: &mut BytesMut, string: S) {
    let string = string.as_ref();

    src.put_u32(string.len() as u32);
    src.put_slice(string);
}
