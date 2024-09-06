/// Trait defining a structure as being hashable
pub trait Hashable {
    
    /// Hash function
    fn hash(&self) -> [u8;32];
}
