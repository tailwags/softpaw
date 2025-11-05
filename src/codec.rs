use std::io::{self, Cursor};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug)]
pub struct Packet {
    pub payload: Bytes,
    pub random_padding: Bytes,
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
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Head,
    Data(usize),
}

impl PacketCodec {
    const HEAD_SIZE: usize = 4;

    pub fn new(max_packet_size: usize, mac_length: usize) -> Self {
        Self {
            state: DecodeState::Head,
            max_packet_size,
            mac_length,
        }
    }

    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    pub fn mac_length(&self) -> usize {
        self.mac_length
    }

    pub fn set_max_packet_size(&mut self, val: usize) {
        self.max_packet_size = val;
    }

    pub fn set_mac_length(&mut self, mac_length: usize) {
        self.mac_length = mac_length;
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
                let random_padding = packet.copy_to_bytes(padding_length as usize);

                let mac = if self.mac_length > 0 {
                    Some(packet.copy_to_bytes(self.mac_length))
                } else {
                    None
                };

                let packet = Packet {
                    payload,
                    random_padding,
                    mac,
                };

                Ok(Some(packet))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<Bytes> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, dst: &mut BytesMut) -> Result<(), io::Error> {
        let data_len = data.len();

        let total_size = 4 + data_len + self.mac_length;

        if total_size > self.max_packet_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("SSH packet too large: {} bytes", total_size),
            ));
        }

        dst.reserve(8);

        dst.put_u32(data_len as u32);

        dst.extend_from_slice(&data[..]);

        Ok(())
    }
}
