use crate::HiveMemoError;

// I don't exactly have any idea how these two works.
pub fn encode_varint32(mut value: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8; 
        value >>= 7;
        if value != 0 {
            byte |= 0x80; 
            buf.push(byte);
        } else {
            buf.push(byte); 
            break;
        }
    }
    buf
}

pub fn decode_varint32(buffer: &[u8]) -> Result<(u32, usize), HiveMemoError> {
    let mut value = 0u32;
    let mut shift = 0;
    let mut bytes_read = 0;

    for byte in buffer.iter() {
        let byte_val = *byte;
        value |= ((byte_val & 0x7F) as u32) << shift;
        bytes_read += 1;

        if (byte_val & 0x80) == 0 {
            return Ok((value, bytes_read));
        }

        shift += 7;

        if shift >= 35 {
            return Err(HiveMemoError::VarintDecodingError(
                "Varint32 is too long".into(),
            ));
        }
    }

    Err(HiveMemoError::VarintDecodingError(
        "Unexpected end of buffer while decoding Varint32".into(),
    ))
}
