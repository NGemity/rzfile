use crate::error::RZError;

/// Byte mapping table used for encrypting obfuscated file names.
///
/// This table defines a one-way substitution mapping from base characters
/// (e.g., ASCII values) to encrypted bytes. The index into this table is
/// typically a character code (`u8`) from a plain-text name.
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

/// Byte mapping table used for decrypting obfuscated file names.
///
/// This is the inverse mapping of [`ENC_TABLE`], allowing decryption
/// of encrypted file name bytes back into readable ASCII-compatible characters.
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

/// Returns a transformed byte from the given table, applied recursively by depth.
///
/// This function takes a byte `c`, looks it up in the provided substitution `table`,
/// and repeats this lookup `depth` times. It's typically used for encrypting or decrypting
/// obfuscated file names using predefined substitution tables.
///
/// # Arguments
///
/// - `c`: The input byte to transform. Must be non-zero and a valid index in `table`.
/// - `depth`: Number of times to recursively apply the substitution. Must be greater than zero.
/// - `table`: The substitution table to use. Must have at least 256 entries.
///
/// # Errors
///
/// - [`RZError::InvalidDepth`] if `depth <= 0`
/// - [`RZError::InvalidCharacter`] if `c == 0` or `c` is out of bounds for the `table`
fn get_char(mut c: u8, depth: i32, table: &[u8]) -> Result<u8, RZError> {
    if depth <= 0 {
        return Err(RZError::InvalidDepth);
    }
    if c == 0 || (c as usize) >= table.len() {
        return Err(RZError::InvalidCharacter);
    }

    for _ in 0..depth {
        let idx = c as usize;
        if idx >= table.len() {
            return Err(RZError::InvalidLength);
        }
        c = table[idx];
    }

    Ok(c)
}

/// Computes the starting depth value used in encryption or decryption functions.
///
/// This function calculates a deterministic "depth" value based on the input `hash`,
/// which influences how often a character should be transformed via a substitution table
/// (see [`get_char`]).
///
/// The formula is:
/// - For each byte `b` in `hash`: `key += 17 * b + 1` (with wrapping arithmetic)
/// - After all bytes: `key += hash.len()`
/// - Then: `depth = key % 32` (with wraparound), unless `depth == 0`, in which case it returns 32
///
/// # Arguments
///
/// * `hash` – A byte slice (typically a hashed filename) that serves as the basis for computing depth.
///
/// # Returns
///
/// An integer between 1 and 32, inclusive.  
/// This value is designed to vary per `hash` and ensures that every input yields at least depth 1.
fn get_start_depth(hash: &[u8]) -> i32 {
    let mut key: i32 = 0;
    for b in hash {
        key = key
            .wrapping_add(17i32.wrapping_mul(*b as i32))
            .wrapping_add(1);
    }
    key = key.wrapping_add(hash.len() as i32);
    let mut ret = key.rem_euclid(32);
    if ret == 0 {
        ret = 32;
    }
    ret
}

/// Calculates a parity character from a given name slice using the [`REF_TABLE`].
///
/// This function computes a simple checksum by summing the byte values of `name`
/// and using the result (modulo the length of [`REF_TABLE`]) as an index to select a character.
/// It's used to append or validate a parity byte in file name encryption/decryption.
///
/// # Arguments
///
/// * `name` – A byte slice representing the (possibly hashed or transformed) file name.
///
/// # Returns
///
/// A single byte from [`REF_TABLE`] that acts as the parity character for this name.
///
/// # Note
///
/// This function is deterministic: the same input will always yield the same output.
/// It does **not** offer cryptographic guarantees — it's intended only for simple parity tagging.
fn get_parity_char(name: &[u8]) -> u8 {
    let mut key: usize = name
        .iter()
        .map(|b| *b as usize)
        .fold(0, |acc, x| acc.wrapping_add(x));
    key %= REF_TABLE.len();
    REF_TABLE[key]
}

/// Swaps two characters in a byte slice using fixed percentage positions.
///
/// If the input slice is too short or the calculated indices would be invalid,
/// the function does nothing.
///
/// # Arguments
///
/// * `s` – A mutable byte slice (e.g., from a file name).
///
/// # Behavior
///
/// - Swaps `s[0]` with `s[66%]`
/// - Swaps `s[1]` with `s[33%]`
/// - Does **nothing** if the slice has fewer than 2 bytes
fn reverse_string(s: &mut [u8]) {
    if s.len() < 2 {
        return;
    }

    let len = s.len();
    let i1 = (len as f32 * 0.66) as usize;
    let i2 = (len as f32 * 0.33) as usize;

    // safety check: skip if calculated indices would be out of bounds
    if i1 < len {
        s.swap(0, i1);
    }
    if i2 < len {
        s.swap(1, i2);
    }
}

/// Checks whether a given file name appears to be in encoded form.
///
/// This function performs a heuristic check based on the following rules:
///
/// - File name must be at least 4 characters long
/// - File name must **not** end with `.ogg` (treated as unencoded/ignored)
/// - The first character is compared against the calculated "parity character"
///   from the reversed middle section of the file name
///
/// This function is typically used to differentiate between encrypted/obfuscated
/// file names and plain-text or known-format files.
///
/// # Arguments
///
/// * `file_name` – The file name (as `&str`) to check.
///
/// # Returns
///
/// `true` if the name matches the expected encoded structure, `false` otherwise.
///
/// # Caveats
///
/// This function does **not** validate the full decryption structure; it only checks
/// whether the name *looks like* an encoded one based on parity rules.
/// False positives/negatives are possible with short or malformed inputs.
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

/// Encodes a file name into an obfuscated format using XOR-based table encryption.
///
/// This function takes an input file name, applies a position-dependent character substitution
/// via `ENC_TABLE` (or a custom table), wraps the encoded bytes with a parity character at the start
/// and a depth marker at the end, and returns the result as a UTF-8 `String`.
///
/// # Arguments
///
/// * `name` – The input file name to encode (must be longer than 3 characters).
/// * `cust_ref` – Optional reference table used to select the trailing marker character.
///   If `None`, `REF_TABLE` is used.
/// * `cust_enc` – Optional encryption table used to encode each byte.  
///   If `None`, the default `ENC_TABLE` is used.
///
/// # Returns
///
/// A newly encoded `String` representing the obfuscated file name.
///
/// # Errors
///
/// Returns:
/// - [`RZError::NoHashProvided`] if `name` is empty.
/// - [`RZError::InvalidLength`] if `name.len() <= 3`.
/// - [`RZError::InvalidCharacter`] or [`RZError::InvalidDepth`] from inner helpers if input is invalid.
///
/// # Encoding Process
///
/// 1. Lowercase the input string
/// 2. Compute a starting depth via `get_start_depth`
/// 3. For each character:
///     - Substitute via `get_char` with increasing depth
///     - Update depth via `depth = (depth + c * 17) % 32 + 1`
/// 4. Reverse the resulting buffer (`reverse_string`)
/// 5. Prepend parity character via `get_parity_char`
/// 6. Append trailing marker from `REF_TABLE` based on initial depth
///
/// # Example
///
/// ```rust
/// use rzfile::{name::encode_file_name, error::RZError};
///
/// let encoded = encode_file_name("soundfile.dat", None, None)?;
/// println!("Encoded: {encoded}");
/// # Ok::<(), RZError>(())
/// ```
///
/// # Panics
///
/// This function panics if the encoded byte sequence is not valid UTF-8.
/// (This should never happen if the encoding tables are valid.)
///
/// # See Also
///
/// - [`decode_file_name`]
pub fn encode_file_name(
    name: &str,
    cust_ref: Option<&[u8]>,
    cust_enc: Option<&[u8]>,
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

/// Decodes an obfuscated file name back into its original form.
///
/// This function performs the inverse of [`encode_file_name`] using a substitution-based
/// decryption table (e.g. `DEC_TABLE`) and metadata encoded into the name itself.
/// The function optionally checks whether the input is in encoded form before attempting decryption.
///
/// # Arguments
///
/// * `name` – The encoded file name string.
/// * `cust_ref` – Optional reference table (`REF_TABLE`) used to look up the ending character
///   to determine the initial depth. If `None`, the default `REF_TABLE` is used.
/// * `cust_dec` – Optional decryption table (`DEC_TABLE`) used to reverse the character substitutions.
///   If `None`, the default `DEC_TABLE` is used.
/// * `check_encoded` – If `true`, the function first checks with [`is_encoded_name`] whether decoding
///   is necessary. If the name is not encoded, it is returned unchanged.
///
/// # Returns
///
/// The original, decoded file name as a `String`, if successful.
///
/// # Errors
///
/// Returns an [`RZError`] in any of the following cases:
///
/// - [`RZError::NoHashProvided`] if `name` is empty.
/// - [`RZError::InvalidLength`] if the name has 3 characters or fewer.
/// - [`RZError::InvalidDepth`] if the last character is not found in the reference table.
/// - [`RZError::InvalidCharacter`] if decoding fails.
///
/// # Example
///
/// ```rust
/// use rzfile::{name::{decode_file_name, encode_file_name}, error::RZError};
///
/// let encoded = encode_file_name("map_file.dat", None, None)?;
/// let decoded = decode_file_name(&encoded, None, None, true)?;
/// assert_eq!(decoded, "map_file.dat");
/// # Ok::<(), RZError>(())
/// ```
///
/// # Panics
///
/// Panics if the final decoded byte sequence is not valid UTF-8.
/// This should never happen if the tables are correct and the input was encoded via [`encode_file_name`].
///
/// # See Also
///
/// - [`encode_file_name`]
/// - [`is_encoded_name`]
pub fn decode_file_name(
    name: &str,
    cust_ref: Option<&[u8]>,
    cust_dec: Option<&[u8]>,
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
    }

    Ok(String::from_utf8(str_string).unwrap())
}

/// Computes the file number associated with a given hashed file name.
///
/// This function performs a deterministic checksum-based calculation to assign
/// a file number (1 through 8) to a given file hash or name.
///
/// The logic is based on a variant of Java's string hash algorithm:
/// - For each byte in the lowercased input: `checksum = checksum * 31 + byte` (with wrapping)
/// - The final file number is derived as `(checksum & 0x7) + 1`
///
/// # Arguments
///
/// * `hash` – The file hash or file name as a string.  
///   Will be converted to lowercase before computation.
///
/// # Returns
///
/// A number in the range `1..=8`, corresponding to the logical data segment
/// (e.g., `data.001`, `data.002`, ..., `data.008`).
///
/// # Example
///
/// ```rust
/// use rzfile::name::get_file_no;
///
/// let file_no = get_file_no("abc123");
/// assert!(file_no >= 1 && file_no <= 8);
/// ```
///
/// # Guarantees
///
/// This function never returns 0 and never panics.
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
    fn test_get_char_valid() {
        let result = get_char(b'a', 1, &ENC_TABLE);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_char_invalid_depth() {
        let result = get_char(b'a', 0, &ENC_TABLE);
        assert_eq!(result.unwrap_err(), RZError::InvalidDepth);
    }

    #[test]
    fn test_get_char_invalid_index() {
        let result = get_char(0, 1, &ENC_TABLE);
        assert_eq!(result.unwrap_err(), RZError::InvalidCharacter);
    }

    #[test]
    fn test_get_start_depth() {
        assert!(1 <= get_start_depth(b"abc") && get_start_depth(b"abc") <= 32);
    }

    #[test]
    fn test_get_parity_char_deterministic() {
        let p1 = get_parity_char(b"abc");
        let p2 = get_parity_char(b"abc");
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_reverse_string_no_panic() {
        let mut s = vec![1];
        reverse_string(&mut s); // should do nothing
        assert_eq!(s, vec![1]);

        let mut s = b"abcdef".to_vec();
        let expected = {
            let mut t = s.clone();
            t.swap(0, (s.len() as f32 * 0.66) as usize);
            t.swap(1, (s.len() as f32 * 0.33) as usize);
            t
        };
        reverse_string(&mut s);
        assert_eq!(s, expected);
    }

    #[test]
    fn test_is_encoded_name() {
        // too short
        assert!(!is_encoded_name("a"));
        // ends with .ogg
        assert!(!is_encoded_name("music.ogg"));
        // actual parity mismatch
        assert!(!is_encoded_name("ZabcZ"));
        // valid encoded
        let encoded = encode_file_name("testfile.txt", None, None).unwrap();
        assert!(is_encoded_name(&encoded));
    }

    #[test]
    fn test_encode_errors() {
        assert_eq!(
            encode_file_name("", None, None).unwrap_err(),
            RZError::NoHashProvided
        );
        assert_eq!(
            encode_file_name("abc", None, None).unwrap_err(),
            RZError::InvalidLength
        );
    }

    #[test]
    fn test_decode_errors() {
        assert_eq!(
            decode_file_name("", None, None, true).unwrap_err(),
            RZError::NoHashProvided
        );
        assert_eq!(
            decode_file_name("abc", None, None, true).unwrap_err(),
            RZError::InvalidLength
        );
        assert_eq!(
            decode_file_name("ZabcdZ", Some(&[b'X'; 128]), None, false).unwrap_err(),
            RZError::InvalidDepth
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = "test_sound.ogg";
        let encoded = encode_file_name(original, None, None).unwrap();
        let decoded = decode_file_name(&encoded, None, None, false).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_get_file_no_range() {
        for name in ["abc", "xyz", "testfile.dat", "AnotherTest123"] {
            let n = get_file_no(name);
            assert!((1..=8).contains(&n));
        }
    }

    #[test]
    fn test_get_char_invalid_character_zero() {
        let table = &[1u8; 128];
        let err = get_char(0, 1, table).unwrap_err();
        assert_eq!(err, RZError::InvalidCharacter);
    }

    #[test]
    fn test_get_char_becomes_invalid_during_iteration() {
        let mut table = vec![0u8; 128];
        table[100] = 200;

        let result = get_char(100, 2, &table);
        assert_eq!(result.unwrap_err(), RZError::InvalidLength);
    }

    #[test]
    fn test_get_start_depth_wraps_to_32() {
        let hash = [30u8];
        let depth = get_start_depth(&hash);
        assert_eq!(depth, 32);
    }

    #[test]
    fn test_decode_file_name_invalid_depth() {
        let encoded = encode_file_name("somefile.txt", None, None).unwrap();

        let mut corrupted = encoded.chars().collect::<Vec<_>>();
        let corr_len = corrupted.len();
        corrupted[corr_len - 1] = '"';

        let corrupted_str: String = corrupted.into_iter().collect();
        let result = decode_file_name(&corrupted_str, None, None, false);

        assert_eq!(result.unwrap_err(), RZError::InvalidDepth);
    }

    #[test]
    fn test_decode_file_name_depth_wraps_to_32_inside_loop() {
        let name = "example.txt";
        let encoded = encode_file_name(name, None, None).unwrap();

        let decoded = decode_file_name(&encoded, None, None, false);
        assert_eq!(decoded.unwrap(), name);
    }

    #[test]
    fn test_decode_file_name_skips_decoding_if_not_encoded() {
        let plain = "soundtrack.ogg";
        let decoded = decode_file_name(plain, None, None, true).unwrap();
        assert_eq!(decoded, plain);
    }
}
