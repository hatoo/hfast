//! Constant HTTP/3 response and control frames for the QUIC transport.

/// A HEADERS frame carrying the field section, then a DATA frame carrying the
/// body. Every length fits in a one-byte varint, so the whole reply is a
/// constant. The field section is QPACK against the static table only, which is
/// all a client offering a zero-capacity dynamic table will accept (RFC 9204
/// Section 4.5):
///
/// `0x01 0x08` HEADERS frame, eight bytes of field section
/// `0x00 0x00` field section prefix: no dynamic entries required, base zero
/// `0xd9`      indexed static 25, `:status: 200`
/// `0xf5`      indexed static 53, `content-type: text/plain`
/// `0x54 ..`   literal with static name 4 (content-length), value `13`
/// `0x00 0x0d` DATA frame, thirteen bytes of body
pub(crate) const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";

/// Stream type 0 (control), then an empty SETTINGS frame. RFC 9114 Section 6.2
/// requires the control stream, and Section 7.2.4 requires SETTINGS to be the
/// first thing on it; this server has nothing to say in it.
pub(crate) const CONTROL_PRELUDE: &[u8] = b"\x00\x04\x00";

#[cfg(test)]
mod tests {
    use super::*;

    /// What `RESPONSE` is supposed to be carrying, spelt out separately so the
    /// hand-assembled bytes are checked against something rather than restated
    const FIELD_SECTION: &[u8] = b"\x00\x00\xd9\xf5\x54\x02\x31\x33";
    const BODY: &[u8] = b"Hello, World!";

    /// The bytes are hand-assembled, so the frame lengths have to be checked
    /// against what they are supposed to be carrying
    #[test]
    fn the_response_frames_say_how_long_they_are() {
        assert_eq!(RESPONSE[0], 0x01, "HEADERS frame");
        assert_eq!(RESPONSE[1] as usize, FIELD_SECTION.len());
        let data = 2 + FIELD_SECTION.len();
        assert_eq!(&RESPONSE[2..data], FIELD_SECTION);
        assert_eq!(RESPONSE[data], 0x00, "DATA frame");
        assert_eq!(RESPONSE[data + 1] as usize, BODY.len());
        assert_eq!(&RESPONSE[data + 2..], BODY);
    }

    /// RFC 9204 Section 4.5.2: an indexed field line is `1` `T` and a 6-bit
    /// index, with T set for the static table
    #[test]
    fn the_field_section_references_only_the_static_table() {
        assert_eq!(FIELD_SECTION[0..2], [0, 0], "no dynamic entries needed");
        assert_eq!(FIELD_SECTION[2] & 0xc0, 0xc0, "indexed, static");
        assert_eq!(FIELD_SECTION[2] & 0x3f, 25, ":status: 200");
        assert_eq!(FIELD_SECTION[3] & 0xc0, 0xc0, "indexed, static");
        assert_eq!(FIELD_SECTION[3] & 0x3f, 53, "content-type: text/plain");
        // Section 4.5.4: `01` `N` `T` and a 4-bit name index
        assert_eq!(FIELD_SECTION[4] & 0xf0, 0x50, "literal, static name");
        assert_eq!(FIELD_SECTION[4] & 0x0f, 4, "content-length");
        assert_eq!(FIELD_SECTION[5], 2, "two bytes of value, unhuffmanned");
        assert_eq!(&FIELD_SECTION[6..], b"13");
    }
}
