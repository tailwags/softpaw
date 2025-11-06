use std::io::{self, Cursor};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub struct Packet {
    pub payload: Bytes,
    pub mac: Option<Bytes>,
}

#[derive(Debug, Clone)]
pub struct PacketCodec {
    /// Decode state machine
    state: DecodeState,
    /// Maximum allowed packet size
    max_packet_size: usize,
    /// Length of MAC field
    mac_length: usize,
    /// Cipher block size: 0 = no encryption, otherwise the cipher's block size
    cipher_block_size: usize,
    // Used for generating random padding
    rng_provider: SystemRandom,
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Head,
    Data(usize),
}

impl PacketCodec {
    const HEAD_SIZE: usize = 4;
    const MIN_BLOCK_SIZE: usize = 8;

    pub fn new(max_packet_size: usize, mac_length: usize) -> Self {
        Self {
            state: DecodeState::Head,
            max_packet_size,
            mac_length,
            cipher_block_size: 0,
            rng_provider: SystemRandom::new(),
        }
    }

    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    pub fn mac_length(&self) -> usize {
        self.mac_length
    }

    pub fn cipher_block_size(&self) -> usize {
        self.cipher_block_size
    }

    pub fn set_max_packet_size(&mut self, val: usize) {
        self.max_packet_size = val;
    }

    pub fn set_mac_length(&mut self, mac_length: usize) {
        self.mac_length = mac_length;
    }

    pub fn set_cipher_block_size(&mut self, block_size: usize) {
        self.cipher_block_size = block_size;
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<usize>> {
        if src.len() < Self::HEAD_SIZE {
            // Not enough data
            return Ok(None);
        }

        // Use Cursor to peek at the length without advancing the buffer
        // This is more efficient than manual indexing
        let packet_length = {
            let mut cursor = Cursor::new(&src[..]);
            cursor.get_u32()
        } as usize;

        // Calculate total frame size
        // SSH format: [4-byte length][packet_length bytes][mac_length bytes]
        let total_frame_size = 4 + packet_length + self.mac_length;

        // Check against max packet size (SSH spec: 35000 bytes)
        if total_frame_size > self.max_packet_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SSH packet too large: {} bytes", total_frame_size),
            ));
        }

        // Check minimum packet size (must have at least padding_length byte)
        if packet_length < 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSH packet too small",
            ));
        }

        // Ensure that the buffer has enough space to read the incoming
        // payload
        src.reserve(total_frame_size.saturating_sub(src.len()));

        Ok(Some(total_frame_size))
    }

    fn decode_data(&self, n: usize, src: &mut BytesMut) -> Option<BytesMut> {
        // At this point, the buffer has already had the required capacity
        // reserved. All there is to do is read.
        if src.len() < n {
            return None;
        }

        Some(src.split_to(n))
    }

    fn calculate_padding_length(&self, payload_len: usize) -> u8 {
        // Determine effective block size
        let block_size = if self.cipher_block_size == 0 {
            Self::MIN_BLOCK_SIZE // No encryption: use RFC minimum of 8
        } else {
            self.cipher_block_size.max(Self::MIN_BLOCK_SIZE)
        };

        let block_size = block_size.max(8);

        // Current length: 4 bytes (packet_length) + 1 byte (padding_length) + payload
        let current_len = 4 + 1 + payload_len;

        // Calculate padding needed to reach next block boundary
        let mut padding_len = block_size - (current_len % block_size);

        // Ensure minimum padding of 4 bytes
        if padding_len < 4 {
            padding_len += block_size;
        }

        padding_len as u8
    }
}

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Packet>> {
        let n = match self.state {
            DecodeState::Head => match self.decode_head(src)? {
                Some(n) => {
                    self.state = DecodeState::Data(n);
                    n
                }
                None => return Ok(None),
            },
            DecodeState::Data(n) => n,
        };

        match self.decode_data(n, src) {
            Some(mut packet) => {
                // Update the decode state
                self.state = DecodeState::Head;

                // Make sure the buffer has enough space to read the next head
                src.reserve(Self::HEAD_SIZE.saturating_sub(src.len()));

                let packet_length = packet.get_u32();
                let padding_length = packet.get_u8();

                let n1 = packet_length - (padding_length as u32) - 1;

                let payload = packet.copy_to_bytes(n1 as usize);

                packet.advance(padding_length as usize); // Skip random padding

                let mac = if self.mac_length > 0 {
                    Some(packet.copy_to_bytes(self.mac_length))
                } else {
                    None
                };

                let packet = Packet { payload, mac };

                Ok(Some(packet))
            }
            None => Ok(None),
        }
    }
}
impl Encoder<Packet> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> Result<(), io::Error> {
        let Packet { payload, mac: _mac } = packet;

        let padding_length = self.calculate_padding_length(payload.len());
        let packet_length = 1 + payload.len() + padding_length as usize;
        let total_size = 4 + packet_length + self.mac_length;

        if total_size > self.max_packet_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("SSH packet too large: {} bytes", total_size),
            ));
        }

        dst.reserve(total_size);
        dst.put_u32(packet_length as u32);
        dst.put_u8(padding_length);
        dst.extend_from_slice(&payload[..]);

        // Write padding: random if encrypted, zeros before encryption
        if self.cipher_block_size == 0 {
            // No encryption: zero padding (like OpenSSH)
            dst.put_bytes(0, padding_length as usize);
        } else {
            let mut padding = vec![0u8; padding_length as usize];

            self.rng_provider
                .fill(&mut padding)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("RNG error: {:?}", e)))?;

            dst.extend_from_slice(&padding);
        }

        Ok(())
    }
}
