//! Retain only the peer's unidirectional stream type, including split, sparse
//! and non-minimal varint encodings. The advertised stream limit bounds storage.

use super::*;
use crate::quic::wire::Reader;

#[derive(Clone, Copy, Default)]
pub(super) struct UniType {
    bytes: [u8; 8],
    present: u8,
}

impl UniType {
    pub(super) fn receive(&mut self, offset: u64, data: &[u8]) {
        if offset >= 8 {
            return;
        }
        for (i, &byte) in data.iter().take(8 - offset as usize).enumerate() {
            let at = offset as usize + i;
            // Overlaps/retransmissions cannot replace an already observed type.
            if self.present & (1 << at) == 0 {
                self.bytes[at] = byte;
                self.present |= 1 << at;
            }
        }
    }

    fn critical(&self) -> bool {
        if self.present & 1 == 0 {
            return false;
        }
        let len = 1 << (self.bytes[0] >> 6);
        let required = (1u16 << len) - 1;
        if u16::from(self.present) & required != required {
            return false;
        }
        matches!(Reader::new(&self.bytes[..len]).varint(), Ok(0 | 2 | 3))
    }
}

impl Connection {
    pub(super) fn check_uni_closed(&mut self, id: u64) -> Result<()> {
        let n = id >> 2;
        if n < self.uni_types.len() as u64
            && self.uni_final & (1 << n) != 0
            && self.uni_types[n as usize].critical()
        {
            // A validated final size and known critical type suffice even if
            // other bytes are missing. FIN/reset cannot legally end this stream.
            // Reset-before-type is remembered by uni_final; later type bytes
            // still undergo all the usual final-size/credit checks first.
            self.prepare_application_close(0x104)?;
            return Err(Error);
        }
        Ok(())
    }
}
