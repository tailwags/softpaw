use std::{fmt::Display, string::FromUtf8Error};

use crate::{codec::Packet, tracing::debug};
use bytes::{Buf, BufMut, BytesMut};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid name-list encoding")]
    InvalidNameList(#[from] FromUtf8Error),
    #[error("Invalid message length")]
    InvalidLength,
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
            20 => Ok(MessageType::Kexinit),
            _ => Err(ParseError::UnknownMessageType(value)),
        }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Kexinit => write!(f, "SSH_MSG_KEXINIT"),
            _ => todo!(),
        }
    }
}

#[derive(Debug)]
pub enum Message {
    Kexinit(Kexinit),
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

            _ => todo!(),
        }
    }

    pub fn into_packet(self) -> Packet {
        match self {
            Message::Kexinit(kex_init) => kex_init.into_packet(),
        }
    }
}

impl Kexinit {
    pub fn into_packet(self) -> Packet {
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

        todo!()
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
