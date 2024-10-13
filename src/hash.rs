pub fn fnv1a_32(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C9DC5;
    const FNV_PRIME: u32 = 0x01000193;

    let mut hash = FNV_OFFSET_BASIS;
    for ele in data {
        hash ^= u32::from(*ele);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
