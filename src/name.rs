use crate::error::RZError;

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

const REF_TABLE: &[u8] =
    b"^&T_Nsd{xo5v`rOYV+,iIU#kCJq8$'~L0P]FeBn-Au(pXHZhwDy2}agWG7K=bQ;SRt)46l@jE%9!c1[3fmMz";

/// ## Returns a character for encrypting.
///
/// May error in the following cases:
/// - `depth` is <= 0
/// - `c` is 0
fn get_enc_char(mut c: u8, depth: i32) -> Result<u8, RZError> {
    if depth <= 0 {
        return Err(RZError::InvalidDepth);
    }
    if c == 0 {
        return Err(RZError::InvalidCharacter);
    }

    for _ in 0..depth {
        c = ENC_TABLE[c as usize];
    }
    Ok(c)
}

/// ## Returns a character for decrypting.
///
/// May error in the following cases:
/// - `depth` is <= 0
/// - `c` is 0
fn get_dec_char(mut c: u8, depth: i32) -> Result<u8, RZError> {
    if depth <= 0 {
        return Err(RZError::InvalidDepth);
    }
    if c == 0 {
        return Err(RZError::InvalidCharacter);
    }

    for _ in 0..depth {
        c = DEC_TABLE[c as usize];
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
/// Will error if less than 2 bytes at least.
fn reverse_string(s: &mut [u8]) {
    let len = s.len();
    s.swap(0, (len as f32 * 0.66) as usize);
    s.swap(1, (len as f32 * 0.33) as usize);
}

/// ## Returns an encoded filename.
///
/// May error in the following cases:
/// - length of `name` is <= 3 characters
/// - `name` is empty
pub fn encode_file_name(name: &str) -> Result<String, RZError> {
    if name.is_empty() {
        return Err(RZError::NoHashProvided);
    }
    if name.len() <= 3 {
        return Err(RZError::InvalidLength);
    }

    let mut hash: Vec<u8> = name.to_lowercase().into_bytes();
    let mut depth = get_start_depth(&hash);
    let start_depth = depth;

    for c in hash.iter_mut() {
        let mut compute_var = *c;
        compute_var = get_enc_char(compute_var, depth)?;
        depth = depth
            .wrapping_add(17 * *c as i32)
            .wrapping_rem(32)
            .wrapping_add(1);

        *c = compute_var;
    }

    reverse_string(&mut hash);

    let mut result = Vec::new();
    result.push(get_parity_char(&hash));
    result.extend_from_slice(&hash);
    result.push(REF_TABLE[start_depth as usize]);

    Ok(String::from_utf8(result).unwrap())
}

/// ## Returns a decoded filename.
///
/// May error in the following cases:
/// - length of `name` is <= 3 characters
/// - `name` is empty
/// - `depth` based on the REF_TABLE returns 0 (invalid state)
///
pub fn decode_file_name(name: &str) -> Result<String, RZError> {
    if name.is_empty() {
        return Err(RZError::NoHashProvided);
    }

    if name.len() <= 3 {
        return Err(RZError::InvalidLength);
    }

    let bytes = name.as_bytes();
    let mut depth = 0;
    for (i, &c) in REF_TABLE.iter().enumerate() {
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
        *c = get_dec_char(*c, depth)?;
        depth = depth
            .wrapping_add((*c as i32).wrapping_mul(17))
            .wrapping_add(1)
            .wrapping_rem(32);
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

    struct Test {
        pub file_name: String,
        pub real_name: String,
        pub file_no: u8,
        pub fail: bool,
    }

    fn get_vec() -> Vec<Test> {
        vec![
            Test {
                file_name: "sdXwe'vmvdeHga$".to_owned(),
                real_name: "db_string.rdb".to_owned(),
                file_no: 1,
                fail: false,
            },
            Test {
                file_name: "U{W.Y(_ZdT!JV".to_owned(),
                real_name: "db_item.rdb".to_owned(),
                file_no: 3,
                fail: false,
            },
            Test {
                file_name: "6]IXXKr;Dw}YPuecve!6@HstO4hTXxl=UC,xgq".to_owned(),
                real_name: "button_scrollbar_down_titanium03.jpg".to_owned(),
                file_no: 8,
                fail: false,
            },
            Test {
                file_name: "4sqD.(SdDTc7,0`9+r+a-;Wa6`Qyrx".to_owned(),
                real_name: "beast_dark_sacker_cast_c.wav".to_owned(),
                file_no: 6,
                fail: false,
            },
            Test {
                file_name: "j%r)XZooNaixS2-NOXC0Z1XpBqYWof17;EsEJWAdC".to_owned(),
                real_name: "static_common_selectclick_type01_01.png".to_owned(),
                file_no: 7,
                fail: false,
            },
            Test {
                file_name: "8M,r!GM7pLIPuo!b]!Q`}fZN".to_owned(),
                real_name: "window_skill_gauge.nui".to_owned(),
                file_no: 2,
                fail: false,
            },
            Test {
                file_name: "123".to_owned(),
                real_name: "123".to_owned(),
                file_no: 2,
                fail: true,
            },
        ]
    }

    #[test]
    fn test_encode_filename() {
        let tests = get_vec();
        for test in tests {
            let file = decode_file_name(&test.file_name);
            if test.fail {
                assert!(file.is_err());
            } else {
                assert_eq!(file.unwrap(), test.real_name);
            }
        }
    }

    #[test]
    fn test_decode_filename() {
        let tests = get_vec();
        for test in tests {
            let file = encode_file_name(&test.real_name);
            if test.fail {
                assert!(file.is_err());
            } else {
                assert_eq!(file.unwrap(), test.file_name);
            }
        }
    }

    #[test]
    fn test_get_file_no() {
        let tests = get_vec();
        for test in tests {
            let file_no = get_file_no(&test.file_name);
            if test.fail {
                assert_ne!(file_no, test.file_no)
            } else {
                assert_eq!(file_no, test.file_no);
            }
        }
    }
}
