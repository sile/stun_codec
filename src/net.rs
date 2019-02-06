//! Socket address related components.
//!
//! # Binary Format of Socket Address
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |0 0 0 0 0 0 0 0|    Family     |           Port                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                 Address (32 bits or 128 bits)                 |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Family: IPv4=1, IPv6=2
//! ```
use crate::constants::MAGIC_COOKIE;
use crate::TransactionId;
use bytecodec::bytes::{BytesDecoder, BytesEncoder};
use bytecodec::combinator::Peekable;
use bytecodec::fixnum::{U16beDecoder, U16beEncoder, U8Decoder, U8Encoder};
use bytecodec::{ByteCount, Decode, Encode, Eos, ErrorKind, Result, SizedEncode};
use std::net::{IpAddr, SocketAddr};

const FAMILY_IPV4: u8 = 1;
const FAMILY_IPV6: u8 = 2;

/// Applies XOR operation on the given socket address.
pub fn socket_addr_xor(addr: SocketAddr, transaction_id: TransactionId) -> SocketAddr {
    let xor_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    match addr.ip() {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            for (i, b) in octets.iter_mut().enumerate() {
                *b ^= (MAGIC_COOKIE >> (24 - i * 8)) as u8;
            }
            let xor_ip = From::from(octets);
            SocketAddr::new(IpAddr::V4(xor_ip), xor_port)
        }
        IpAddr::V6(ip) => {
            let mut octets = ip.octets();
            for (i, b) in octets.iter_mut().enumerate().take(4) {
                *b ^= (MAGIC_COOKIE >> (24 - i * 8)) as u8;
            }
            for (i, b) in octets.iter_mut().enumerate().take(16).skip(4) {
                *b ^= transaction_id.as_bytes()[i - 4];
            }
            let xor_ip = From::from(octets);
            SocketAddr::new(IpAddr::V6(xor_ip), xor_port)
        }
    }
}

/// Socket address decoder.
#[derive(Debug, Default)]
pub struct SocketAddrDecoder {
    unused: U8Decoder,
    family: Peekable<U8Decoder>,
    port: U16beDecoder,
    ip: BytesDecoder<IpBytes>,
}
impl SocketAddrDecoder {
    /// Makes a new `SocketAddrDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Decode for SocketAddrDecoder {
    type Item = SocketAddr;

    fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        if !self.family.is_idle() {
            bytecodec_try_decode!(self.unused, offset, buf, eos);
            bytecodec_try_decode!(self.family, offset, buf, eos);

            let family = self.family.peek().expect("never fails");
            match *family {
                FAMILY_IPV4 => self.ip.set_bytes(IpBytes::V4([0; 4])),
                FAMILY_IPV6 => self.ip.set_bytes(IpBytes::V6([0; 16])),
                _ => track_panic!(
                    ErrorKind::InvalidInput,
                    "Unknown address family: {}",
                    family
                ),
            }
        }
        bytecodec_try_decode!(self.port, offset, buf, eos);
        bytecodec_try_decode!(self.ip, offset, buf, eos);
        Ok(offset)
    }

    fn finish_decoding(&mut self) -> Result<Self::Item> {
        let _ = track!(self.unused.finish_decoding())?;
        let _ = track!(self.family.finish_decoding())?;
        let port = track!(self.port.finish_decoding())?;
        let ip = match track!(self.ip.finish_decoding())? {
            IpBytes::V4(b) => IpAddr::V4(b.into()),
            IpBytes::V6(b) => IpAddr::V6(b.into()),
        };
        Ok(SocketAddr::new(ip, port))
    }

    fn requiring_bytes(&self) -> ByteCount {
        self.unused
            .requiring_bytes()
            .add_for_decoding(self.family.requiring_bytes())
            .add_for_decoding(self.port.requiring_bytes())
            .add_for_decoding(self.ip.requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.port.is_idle() && self.ip.is_idle()
    }
}

/// Socket address encoder.
#[derive(Debug, Default)]
pub struct SocketAddrEncoder {
    unused: U8Encoder,
    family: U8Encoder,
    port: U16beEncoder,
    ip: BytesEncoder<IpBytes>,
}
impl SocketAddrEncoder {
    /// Makes a new `SocketAddrEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Encode for SocketAddrEncoder {
    type Item = SocketAddr;

    fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
        let mut offset = 0;
        bytecodec_try_encode!(self.unused, offset, buf, eos);
        bytecodec_try_encode!(self.family, offset, buf, eos);
        bytecodec_try_encode!(self.port, offset, buf, eos);
        bytecodec_try_encode!(self.ip, offset, buf, eos);
        Ok(offset)
    }

    fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
        track!(self.unused.start_encoding(0))?;
        if item.ip().is_ipv4() {
            track!(self.family.start_encoding(FAMILY_IPV4))?;
        } else {
            track!(self.family.start_encoding(FAMILY_IPV6))?;
        }
        track!(self.port.start_encoding(item.port()))?;
        track!(self.ip.start_encoding(IpBytes::new(item.ip())))?;
        Ok(())
    }

    fn requiring_bytes(&self) -> ByteCount {
        ByteCount::Finite(self.exact_requiring_bytes())
    }

    fn is_idle(&self) -> bool {
        self.ip.is_idle()
    }
}
impl SizedEncode for SocketAddrEncoder {
    fn exact_requiring_bytes(&self) -> u64 {
        self.unused.exact_requiring_bytes()
            + self.family.exact_requiring_bytes()
            + self.port.exact_requiring_bytes()
            + self.ip.exact_requiring_bytes()
    }
}

#[derive(Debug)]
enum IpBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}
impl IpBytes {
    fn new(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => IpBytes::V4(ip.octets()),
            IpAddr::V6(ip) => IpBytes::V6(ip.octets()),
        }
    }
}
impl AsRef<[u8]> for IpBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            IpBytes::V4(bytes) => bytes,
            IpBytes::V6(bytes) => bytes,
        }
    }
}
impl AsMut<[u8]> for IpBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            IpBytes::V4(bytes) => bytes,
            IpBytes::V6(bytes) => bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytecodec::{DecodeExt, EncodeExt};

    use super::*;

    #[test]
    fn socket_addr_xor_works() {
        let transaction_id = TransactionId::new([
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ]);

        // IPv4
        let addr: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        assert_eq!(
            socket_addr_xor(addr, transaction_id),
            "225.18.166.67:41287".parse().unwrap()
        );

        // IPv6
        let addr: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
            .parse()
            .unwrap();
        assert_eq!(
            socket_addr_xor(addr, transaction_id),
            "[113:a9fa:a5d3:f179:bc25:f4b5:bed2:b9d9]:41287"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn socket_addr_encoder_works() {
        let mut encoder = SocketAddrEncoder::new();

        let v4addr = "127.0.0.1:80".parse().unwrap();
        let bytes = encoder.encode_into_bytes(v4addr).unwrap();
        assert_eq!(bytes, [0, 1, 0, 80, 127, 0, 0, 1]);

        let v6addr = "[::]:90".parse().unwrap();
        let bytes = encoder.encode_into_bytes(v6addr).unwrap();
        assert_eq!(
            bytes,
            [0, 2, 0, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn socket_addr_decoder_works() {
        let mut decoder = SocketAddrDecoder::new();

        let v4addr = decoder
            .decode_from_bytes(&[0, 1, 0, 80, 127, 0, 0, 1])
            .unwrap();
        assert_eq!(v4addr.to_string(), "127.0.0.1:80");

        let v6addr = decoder
            .decode_from_bytes(&[0, 2, 0, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(v6addr.to_string(), "[::]:90");
    }
}
