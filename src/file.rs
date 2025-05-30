use crate::error::RZError;

const RESOURCE_ENCRYPTION_KEY: [u8; 256] = [
    0x77, 0xe8, 0x5e, 0xec, 0xb7, 0x4e, 0xc1, 0x87, 0x4f, 0xe6, 0xf5, 0x3c, 0x1f, 0xb3, 0x15, 0x43,
    0x6a, 0x49, 0x30, 0xa6, 0xbf, 0x53, 0xa8, 0x35, 0x5b, 0xe5, 0x9e, 0x0e, 0x41, 0xec, 0x22, 0xb8,
    0xd4, 0x80, 0xa4, 0x8c, 0xce, 0x65, 0x13, 0x1d, 0x4b, 0x08, 0x5a, 0x6a, 0xbb, 0x6f, 0xad, 0x25,
    0xb8, 0xdd, 0xcc, 0x77, 0x30, 0x74, 0xac, 0x8c, 0x5a, 0x4a, 0x9a, 0x9b, 0x36, 0xbc, 0x53, 0x0a,
    0x3c, 0xf8, 0x96, 0x0b, 0x5d, 0xaa, 0x28, 0xa9, 0xb2, 0x82, 0x13, 0x6e, 0xf1, 0xc1, 0x93, 0xa9,
    0x9e, 0x5f, 0x20, 0xcf, 0xd4, 0xcc, 0x5b, 0x2e, 0x16, 0xf5, 0xc9, 0x4c, 0xb2, 0x1c, 0x57, 0xee,
    0x14, 0xed, 0xf9, 0x72, 0x97, 0x22, 0x1b, 0x4a, 0xa4, 0x2e, 0xb8, 0x96, 0xef, 0x4b, 0x3f, 0x8e,
    0xab, 0x60, 0x5d, 0x7f, 0x2c, 0xb8, 0xad, 0x43, 0xad, 0x76, 0x8f, 0x5f, 0x92, 0xe6, 0x4e, 0xa7,
    0xd4, 0x47, 0x19, 0x6b, 0x69, 0x34, 0xb5, 0x0e, 0x62, 0x6d, 0xa4, 0x52, 0xb9, 0xe3, 0xe0, 0x64,
    0x43, 0x3d, 0xe3, 0x70, 0xf5, 0x90, 0xb3, 0xa2, 0x06, 0x42, 0x02, 0x98, 0x29, 0x50, 0x3f, 0xfd,
    0x97, 0x58, 0x68, 0x01, 0x8c, 0x1e, 0x0f, 0xef, 0x8b, 0xb3, 0x41, 0x44, 0x96, 0x21, 0xa8, 0xda,
    0x5e, 0x8b, 0x4a, 0x53, 0x1b, 0xfd, 0xf5, 0x21, 0x3f, 0xf7, 0xba, 0x68, 0x47, 0xf9, 0x65, 0xdf,
    0x52, 0xce, 0xe0, 0xde, 0xec, 0xef, 0xcd, 0x77, 0xa2, 0x0e, 0xbc, 0x38, 0x2f, 0x64, 0x12, 0x8d,
    0xf0, 0x5c, 0xe0, 0x0b, 0x59, 0xd6, 0x2d, 0x99, 0xcd, 0xe7, 0x01, 0x15, 0xe0, 0x67, 0xf4, 0x32,
    0x35, 0xd4, 0x11, 0x21, 0xc3, 0xde, 0x98, 0x65, 0xed, 0x54, 0x9d, 0x1c, 0xb9, 0xb0, 0xaa, 0xa9,
    0x0c, 0x8a, 0xb4, 0x66, 0x60, 0xe1, 0xff, 0x2e, 0xc8, 0x00, 0x43, 0xa9, 0x67, 0x37, 0xdb, 0x9c,
];

const ENCRYPTED_EXTENSIONS: [&str; 6] = ["dds", "cob", "naf", "nx3", "nfm", "tga"];

#[derive(Default, Debug)]
/// Structure of the data.000 file
pub struct IndexFile {
    /// len of the following hash
    pub str_len: u8,
    /// hash filename (contains file_no: data.00x)
    pub hash: Vec<u8>,
    /// offset in file data.00x
    pub offset: u32,
    /// size of file in data.00x
    pub size: u32,
}

/// ## is_encrypted
/// Check if a filename ends with an extension which is encrypted by default.
///
/// Alternatively, pass extensions yourself. If you want to use the default ones, pass `None`
pub fn is_encrypted(file_name: &str, extensions: Option<&[&str]>) -> bool {
    let ext_to_test = extensions.unwrap_or(&ENCRYPTED_EXTENSIONS);
    ext_to_test.iter().any(|ext| file_name.ends_with(ext))
}

/// ## cipher
/// ### Decrypt client data
/// Pass a buffer as reference to decrypt the file.
/// If you have a custom resource encoding key, you can pass it as well - if not, pass `None`
pub fn cipher(buffer: &mut [u8], resource_encode_key: Option<&[u8; 256]>) {
    let mut index = 0u8;
    let key = resource_encode_key.unwrap_or(&RESOURCE_ENCRYPTION_KEY);
    for n in buffer.iter_mut() {
        *n ^= *key.get(index as usize).unwrap();
        index = index.wrapping_add(1);
    }
}

/// ## parse_index
/// ### Reads a buffer of the content of data.000
/// If you have a custom resource encoding key, you can pass it as well - if not, pass `None`
/// Result is a vector containing all data as struct
pub fn parse_index(
    buffer: &mut [u8],
    resource_encode_key: Option<&[u8; 256]>,
) -> Result<Vec<IndexFile>, RZError> {
    if buffer.is_empty() {
        return Err(RZError::InvalidLength);
    }

    cipher(buffer, resource_encode_key);
    let mut result: Vec<IndexFile> = Vec::new();

    let mut curr_pos = 0usize;
    while curr_pos < buffer.len() {
        let hash_len = buffer.get(curr_pos).unwrap();
        let full_block_size = *hash_len as usize + 9usize;
        if (curr_pos + full_block_size) > buffer.len() {
            return Err(RZError::Unknown);
        }

        let index_file = IndexFile {
            str_len: *hash_len,
            hash: buffer[(curr_pos + 1)..(curr_pos + *hash_len as usize + 1)].into(),
            offset: u32::from_le_bytes(
                buffer[(curr_pos + *hash_len as usize + 1)..(curr_pos + *hash_len as usize + 5)]
                    .try_into()
                    .unwrap(),
            ),
            size: u32::from_le_bytes(
                buffer[(curr_pos + *hash_len as usize + 5)..(curr_pos + *hash_len as usize + 9)]
                    .try_into()
                    .unwrap(),
            ),
        };
        curr_pos += full_block_size;
        result.push(index_file);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cipher() {
        let mut buffer: [u8; 4] = [0, 0, 0, 0];
        cipher(&mut buffer, None);
        assert_ne!(buffer, [0, 0, 0, 0]);
        cipher(&mut buffer, None);
        assert_eq!(buffer, [0, 0, 0, 0]);
    }

    #[test]
    fn test_file() {
        let mut buffer: [u8; 25] = [
            3, 97, 98, 99, 5, 0, 0, 0, 6, 0, 0, 0, 4, 97, 98, 99, 100, 7, 0, 0, 0, 8, 0, 0, 0,
        ];
        cipher(&mut buffer, None);
        let vec_result = parse_index(&mut buffer, None).unwrap();
        assert_eq!(vec_result.len(), 2);
        assert_eq!(vec_result[0].hash, [97, 98, 99]);
        assert_eq!(vec_result[0].str_len, 3);
        assert_eq!(vec_result[0].offset, 5);
        assert_eq!(vec_result[0].size, 6);
        assert_eq!(vec_result[1].hash, [97, 98, 99, 100]);
        assert_eq!(vec_result[1].str_len, 4);
        assert_eq!(vec_result[1].offset, 7);
        assert_eq!(vec_result[1].size, 8);

        let mut buffer: [u8; 0] = [];
        let result = parse_index(&mut buffer, None).unwrap_err();
        assert_eq!(result, RZError::InvalidLength);
    }
}
