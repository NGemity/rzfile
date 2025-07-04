use crate::error::RZError;

/// ## Table used for encryption
const ENC_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x67, 0x20, 0x00, 0x26, 0x77, 0x2C, 0x6C, 0x4E, 0x58, 0x4F, 0x00, 0x37, 0x2E, 0x25, 0x65, 0x00,
    0x38, 0x5F, 0x5D, 0x23, 0x50, 0x31, 0x2D, 0x24, 0x56, 0x5B, 0x00, 0x59, 0x00, 0x5E, 0x00, 0x00,
    0x4B, 0x7D, 0x6A, 0x30, 0x40, 0x47, 0x53, 0x29, 0x41, 0x78, 0x79, 0x36, 0x39, 0x45, 0x46, 0x7B,
    0x57, 0x62, 0x3D, 0x52, 0x76, 0x74, 0x68, 0x32, 0x34, 0x4D, 0x28, 0x6B, 0x00, 0x6D, 0x61, 0x2B,
    0x7E, 0x44, 0x27, 0x43, 0x21, 0x4A, 0x49, 0x64, 0x42, 0x55, 0x60, 0x71, 0x66, 0x70, 0x48, 0x51,
    0x33, 0x4C, 0x6E, 0x6F, 0x5A, 0x69, 0x72, 0x73, 0x75, 0x3B, 0x7A, 0x63, 0x00, 0x54, 0x35, 0x00,
];

/// ## Table used for decryption
const DEC_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x64, 0x00, 0x33, 0x37, 0x2D, 0x23, 0x62, 0x5A, 0x47, 0x00, 0x5F, 0x25, 0x36, 0x2C, 0x00,
    0x43, 0x35, 0x57, 0x70, 0x58, 0x7E, 0x4B, 0x2B, 0x30, 0x4C, 0x00, 0x79, 0x00, 0x52, 0x00, 0x00,
    0x44, 0x48, 0x68, 0x63, 0x61, 0x4D, 0x4E, 0x45, 0x6E, 0x66, 0x65, 0x40, 0x71, 0x59, 0x27, 0x29,
    0x34, 0x6F, 0x53, 0x46, 0x7D, 0x69, 0x38, 0x50, 0x28, 0x3B, 0x74, 0x39, 0x00, 0x32, 0x3D, 0x31,
    0x6A, 0x5E, 0x51, 0x7B, 0x67, 0x2E, 0x6C, 0x20, 0x56, 0x75, 0x42, 0x5B, 0x26, 0x5D, 0x72, 0x73,
    0x6D, 0x6B, 0x76, 0x77, 0x55, 0x78, 0x54, 0x24, 0x49, 0x4A, 0x7A, 0x4F, 0x00, 0x41, 0x60, 0x00,
];

/// ## Reference Table
const REF_TABLE: &[u8] =
    b"^&T_Nsd{xo5v`rOYV+,iIU#kCJq8$'~L0P]FeBn-Au(pXHZhwDy2}agWG7K=bQ;SRt)46l@jE%9!c1[3fmMz";

/// ## Returns a character for encrypting or decrypting, depending on passed table
///
/// May error in the following cases:
/// - `depth` is <= 0
/// - `c` is 0
fn get_char(mut c: u8, depth: i32, table: &[u8; 128]) -> Result<u8, RZError> {
    if depth <= 0 {
        return Err(RZError::InvalidDepth);
    }
    if c == 0 {
        return Err(RZError::InvalidCharacter);
    }

    for _ in 0..depth {
        c = table[c as usize];
    }
    Ok(c)
}

/// ## Gets the starting depth.
/// should only be used in association with the encryption/decryption functions.
fn get_start_depth(hash: &[u8]) -> i32 {
    let mut key: i32 = 0;
    for b in hash {
        key = key
            .wrapping_add(17i32.wrapping_mul(*b as i32))
            .wrapping_add(1);
    }
    key = key.wrapping_add(hash.len() as i32);
    let mut ret = key.wrapping_rem(32);
    if ret == 0 {
        ret = 32;
    }
    ret
}

/// ## Gets a parity character based on the REF_TABLE
/// should only be used in association with the encryption/decryption functions.
fn get_parity_char(name: &[u8]) -> u8 {
    let mut key: usize = name
        .iter()
        .map(|b| *b as usize)
        .fold(0, |acc, x| acc.wrapping_add(x));
    key %= REF_TABLE.len();
    REF_TABLE[key]
}

/// ## swaps two characters in the provided string..
/// should only be used in association with the encryption/decryption functions.
/// Will panic if less than 2 bytes.
fn reverse_string(s: &mut [u8]) {
    let len = s.len();
    s.swap(0, (len as f32 * 0.66) as usize);
    s.swap(1, (len as f32 * 0.33) as usize);
}

/// ## checks for encoded file name
fn is_encoded_name(file_name: &str) -> bool {
    if file_name.len() < 4 || file_name.ends_with(".ogg") {
        return false;
    }

    let str_as_bytes = file_name.as_bytes();

    let mut middle = str_as_bytes[1..file_name.len() - 1].to_vec();

    reverse_string(&mut middle);

    let expected_first = get_parity_char(&middle);
    str_as_bytes[0] == expected_first
}

/// ## Returns an encoded filename.
///
/// May error in the following cases:
/// - length of `name` is <= 3 characters
/// - `name` is empty
pub fn encode_file_name(
    name: &str,
    cust_ref: Option<&[u8]>,
    cust_enc: Option<&[u8; 128]>,
) -> Result<String, RZError> {
    if name.is_empty() {
        return Err(RZError::NoHashProvided);
    }
    if name.len() <= 3 {
        return Err(RZError::InvalidLength);
    }

    let actual_ref = cust_ref.unwrap_or(REF_TABLE);
    let actual_enc = cust_enc.unwrap_or(&ENC_TABLE);

    let mut hash: Vec<u8> = name.to_lowercase().into_bytes();
    let mut depth = get_start_depth(&hash);
    let start_depth = depth;

    for c in hash.iter_mut() {
        let mut compute_var = *c;
        compute_var = get_char(compute_var, depth, actual_enc)?;
        depth = depth
            .wrapping_add((*c as i32).wrapping_mul(17))
            .wrapping_rem(32)
            .wrapping_add(1);

        *c = compute_var;
    }

    reverse_string(&mut hash);

    let mut result = Vec::new();
    result.push(get_parity_char(&hash));
    result.extend_from_slice(&hash);
    result.push(actual_ref[start_depth as usize]);

    Ok(String::from_utf8(result).unwrap())
}

/// ## Returns a decoded filename.
///
/// May error in the following cases:
/// - length of `name` is <= 3 characters
/// - `name` is empty
/// - `depth` based on the REF_TABLE returns 0 (invalid state)
///
pub fn decode_file_name(
    name: &str,
    cust_ref: Option<&[u8]>,
    cust_dec: Option<&[u8; 128]>,
    check_encoded: bool,
) -> Result<String, RZError> {
    if name.is_empty() {
        return Err(RZError::NoHashProvided);
    }

    if name.len() <= 3 {
        return Err(RZError::InvalidLength);
    }

    if check_encoded && !is_encoded_name(name) {
        return Ok(name.to_owned());
    }

    let actual_ref = cust_ref.unwrap_or(REF_TABLE);
    let actual_dec = cust_dec.unwrap_or(&DEC_TABLE);

    let bytes = name.as_bytes();
    let mut depth = 0;
    for (i, &c) in actual_ref.iter().enumerate() {
        if c == bytes[bytes.len() - 1] {
            depth = i as i32;
            break;
        }
    }
    if depth == 0 {
        return Err(RZError::InvalidDepth);
    }

    let mut str_string = bytes[1..bytes.len() - 1].to_vec();
    reverse_string(&mut str_string);

    for c in str_string.iter_mut() {
        *c = get_char(*c, depth, actual_dec)?;
        depth = depth
            .wrapping_add((*c as i32).wrapping_mul(17))
            .wrapping_rem(32)
            .wrapping_add(1);
        if depth == 0 {
            depth = 32;
        }
    }

    Ok(String::from_utf8(str_string).unwrap())
}

/// ## Returns the file number associated to the hash.
///
/// Should not run into an error.
pub fn get_file_no(hash: &str) -> u8 {
    let lower = hash.to_lowercase();
    let lower_bytes = lower.as_bytes();
    let mut checksum = 0i32;
    for n in lower_bytes.iter() {
        checksum = checksum.wrapping_mul(31).wrapping_add(*n as i32);
    }

    if checksum < 0 {
        checksum *= -1
    }

    ((checksum & 0x7) + 1) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_filename() {
        let tests = [
            ("sdXwe'vmvdeHga$", "db_string.rdb"),
            ("U{W.Y(_ZdT!JV", "db_item.rdb"),
            (
                "j%r)XZooNaixS2-NOXC0Z1XpBqYWof17;EsEJWAdC",
                "static_common_selectclick_type01_01.png",
            ),
            (
                "4sqD.(SdDTc7,0`9+r+a-;Wa6`Qyrx",
                "beast_dark_sacker_cast_c.wav",
            ),
            (
                "6]IXXKr;Dw}YPuecve!6@HstO4hTXxl=UC,xgq",
                "button_scrollbar_down_titanium03.jpg",
            ),
            ("8M,r!GM7pLIPuo!b]!Q`}fZN", "window_skill_gauge.nui"),
        ];

        for test in tests {
            let file = decode_file_name(test.0, None, None, false);
            assert_eq!(file.unwrap(), test.1);
        }
    }

    #[test]
    fn test_encode_filename() {
        let tests = [
            ("sdXwe'vmvdeHga$", "db_string.rdb"),
            ("U{W.Y(_ZdT!JV", "db_item.rdb"),
            (
                "j%r)XZooNaixS2-NOXC0Z1XpBqYWof17;EsEJWAdC",
                "static_common_selectclick_type01_01.png",
            ),
            (
                "4sqD.(SdDTc7,0`9+r+a-;Wa6`Qyrx",
                "beast_dark_sacker_cast_c.wav",
            ),
            (
                "6]IXXKr;Dw}YPuecve!6@HstO4hTXxl=UC,xgq",
                "button_scrollbar_down_titanium03.jpg",
            ),
            ("8M,r!GM7pLIPuo!b]!Q`}fZN", "window_skill_gauge.nui"),
        ];

        for test in tests {
            let file = encode_file_name(test.1, None, None);
            assert_eq!(file.unwrap(), test.0);
        }
    }

    #[test]
    fn test_get_file_no() {
        let tests = [
            ("sdXwe'vmvdeHga$", 1),
            ("U{W.Y(_ZdT!JV", 3),
            ("j%r)XZooNaixS2-NOXC0Z1XpBqYWof17;EsEJWAdC", 7),
            ("4sqD.(SdDTc7,0`9+r+a-;Wa6`Qyrx", 6),
            ("6]IXXKr;Dw}YPuecve!6@HstO4hTXxl=UC,xgq", 8),
            ("8M,r!GM7pLIPuo!b]!Q`}fZN", 2),
        ];

        for test in tests {
            let file_no = get_file_no(test.0);
            assert_eq!(file_no, test.1);
        }
    }
}
