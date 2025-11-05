use std::{fmt::Display, string::FromUtf8Error};

use crate::tracing::debug;
use bytes::Buf;

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
    KexInit = 20,
}

impl TryFrom<u8> for MessageType {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            20 => Ok(MessageType::KexInit),
            _ => Err(ParseError::UnknownMessageType(value)),
        }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::KexInit => write!(f, "SSH_MSG_KEXINIT"),
        }
    }
}

#[derive(Debug)]
pub enum Message {
    KexInit(KexInit),
}

#[derive(Debug)]
pub struct KexInit {
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
            MessageType::KexInit => {
                let mut cookie = [0u8; 16];
                src.copy_to_slice(&mut cookie);

                let kex_init = KexInit {
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

                Ok(Message::KexInit(kex_init))
            }
        }
    }
}

fn parse_name_list<B: Buf>(src: &mut B) -> Result<Vec<String>, ParseError> {
    let len = src.get_u32();
    let content = src.copy_to_bytes(len as usize);

    String::from_utf8(content.to_vec())
        .map_err(ParseError::InvalidNameList)
        .map(|s| s.split(',').map(str::to_string).collect())
}
