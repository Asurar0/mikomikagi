//! ## LMDB
//! 
//! Keyring implementation over LMDB.
//! 

// ---------------------------------- Imports --------------------------------------

use std::{borrow::Cow, marker::PhantomData, ops::Deref, path::PathBuf};

use borsh::{BorshDeserialize, BorshSerialize};
use heed::{types::{Bytes, Str}, BytesDecode, BytesEncode, DatabaseFlags, EnvFlags, EnvOpenOptions};
use mikomikagi_core::{identity::AttachedIdentity, keys::{DecapsulationKey, EncapsulationKey, Fingerprint, SignaturePrivateKey, SignaturePublicKey}};

use crate::{error::{KeyringError as Error, ParsingError}, Keyring, KeyringWrite, KeyStorageStatistics};

// ---------------------------------- Definitions --------------------------------------

const _LMDB_SCHEMA_VERSION: usize = 1;
const LMDB_MAX_KEYRING_SIZE: usize = 2*1024usize.pow(3); // 2GB
const LMDB_MAX_READERS: usize = 16;
const LMDB_MAX_DATABASE: usize = 8;

const TABLE_ATTACHED_IDENTITY: &str = "attached_identity";
const TABLE_SIGNATURE_PUBLIC_KEY: &str = "signature_public_key";
const TABLE_SIGNATURE_PRIVATE_KEY: &str = "signature_private_key";
const TABLE_ENCRYPTION_PUBLIC_KEY: &str = "encryption_public_key";
const TABLE_ENCRYPTION_PRIVATE_KEY: &str = "encryption_private_key";
const TABLE_ATTACHED_IDENTITY_SIGNATURE: &str = "attached_identity_signature";
const TABLE_NAME_FINGERPRINT: &str = "name_fingerprint_correlation";
const TABLE_IDENTITY_KEY_STORAGE_STATISTICS: &str = "identity_key_storage_statistics";

/// Implementation wrapper around LMDB shared handle.
pub struct LMDBKeyring {
    /// LMDB handle
    lmdb: heed::Env
}

/// OpenOptions structure of LMDBKeyring
pub struct LMDBKeyringOptions {
    // Directory path towards LMDB environment
    pub path: PathBuf
}

// ---------------------------------- Parsing --------------------------------------

pub struct Borsh<T>(PhantomData<T>);

impl<'a,T: BorshSerialize + 'a> BytesEncode<'a> for Borsh<T> {
    type EItem = T;

    fn bytes_encode(item: &'a Self::EItem) -> Result<Cow<'a, [u8]>, heed::BoxedError> {
        
        let bytes = borsh::to_vec(&item)?;
        Ok(Cow::Owned(bytes))
    }
}

impl<'a,T: BorshDeserialize + 'a> BytesDecode<'a> for Borsh<T> {
    type DItem = T;

    fn bytes_decode(bytes: &'a [u8]) -> Result<Self::DItem, heed::BoxedError> {
        
        Ok(borsh::from_slice::<T>(bytes).map(Into::into)?)
    }
}

pub struct Pod<T>(PhantomData<T>);

// ---------------------------------- Implementation --------------------------------------

impl Deref for LMDBKeyring {
    type Target = heed::Env;

    fn deref(&self) -> &Self::Target {
        &self.lmdb
    }
}

#[inline]
/// Return LMDB environment config in read-only or read-write mode
pub fn env_config(write: bool) -> EnvOpenOptions {
    let mut env_config = heed::EnvOpenOptions::new();
    env_config
        .map_size(LMDB_MAX_KEYRING_SIZE)
        .max_readers(LMDB_MAX_READERS as u32)
        .max_dbs(LMDB_MAX_DATABASE as u32);
    
    // Read-Only?
    if !write {
        unsafe { let _ = env_config.flags(EnvFlags::READ_ONLY); }
    }
    env_config
}

impl Keyring for LMDBKeyring {
    
    type OpenOptions = LMDBKeyringOptions;

    #[cold]
    fn open(options: Self::OpenOptions) -> Result<Self, Error> {
        #[allow(unsafe_code)]
        let lmdb = unsafe { env_config(false).open(options.path)? };
        
        Ok(Self { lmdb })
    }
    
    #[cold]
    fn close(self) {
        let event = self.lmdb.prepare_for_closing();
        event.wait();
    }

    fn collect(
        &self
    ) -> Result<Vec<([u8; 32],u32,KeyStorageStatistics,AttachedIdentity)>,Error> {
        
        let ro_tx = self.read_txn()?;
        let mut list = Vec::new();
        
        let database = self.open_database::<Bytes, Borsh<AttachedIdentity>>(&ro_tx, Some(TABLE_ATTACHED_IDENTITY))?
            .ok_or(Error::NoTable(TABLE_ATTACHED_IDENTITY))?;
        
        let pk_db = self.open_database::<Bytes, Borsh<SignaturePublicKey>>(&ro_tx, Some(TABLE_SIGNATURE_PUBLIC_KEY))?
            .ok_or(Error::NoTable(TABLE_SIGNATURE_PUBLIC_KEY))?;
        
        let kss_db = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&ro_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?
            .ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        
        for resource in database.iter(&ro_tx)? {
            let (fingerprint, identity) = resource?;
            
            let pk = pk_db.get(&ro_tx, fingerprint)?.ok_or(Error::NoResource)?;
            let stats = kss_db.get(&ro_tx, fingerprint)?.ok_or(Error::NoResource)?;
            
            list.push(
                (
                    fingerprint.try_into().map_err(ParsingError::TryInto)?,
                    pk.scheme(),
                    stats,
                    identity
                )
            )
        }
        
        Ok(list)
    }

    fn get_fingerprint(
        &self,
        name: &str,
    ) -> Result<Vec<Fingerprint>,Error> {
        
        let ro_tx = self.read_txn()?;
        let mut list = Vec::new();
        
        let database = self.database_options().types::<Str, Bytes>().flags(DatabaseFlags::DUP_SORT).name(TABLE_NAME_FINGERPRINT).open(&ro_tx)?
            .ok_or(Error::NoTable(TABLE_NAME_FINGERPRINT))?;
        
        for item in database.iter(&ro_tx)? {
            let (info_name,fingerprint) = item?;
            
            if info_name == name {
                
                let f: [u8;32] = fingerprint.try_into().map_err(ParsingError::TryInto)?;
                list.push(f.into())
            }
        }
        
        Ok(list)
    }

    fn get_attached_identity(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<AttachedIdentity,Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Borsh<AttachedIdentity>>(&ro_tx, Some(TABLE_ATTACHED_IDENTITY))?.ok_or(Error::NoTable(TABLE_ATTACHED_IDENTITY))?;
        let attached_identity = database.get(&ro_tx, fingerprint.as_ref())?.ok_or(Error::NoResource)?;
        
        ro_tx.commit()?;
        
        Ok(attached_identity)
    }

    fn get_signature_public_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<SignaturePublicKey,Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Borsh<SignaturePublicKey>>(&ro_tx, Some(TABLE_SIGNATURE_PUBLIC_KEY))?.ok_or(Error::NoTable(TABLE_SIGNATURE_PUBLIC_KEY))?;
        let signature_public_key = database.get(&ro_tx, fingerprint.as_ref())?.ok_or(Error::NoResource)?;
        
        ro_tx.commit()?;
        
        Ok(signature_public_key)
    }

    fn get_signature_private_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<SignaturePrivateKey,Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Borsh<SignaturePrivateKey>>(&ro_tx, Some(TABLE_SIGNATURE_PRIVATE_KEY))?.ok_or(Error::NoTable(TABLE_SIGNATURE_PRIVATE_KEY))?;
        let signature_private_key = database.get(&ro_tx, fingerprint.as_ref())?.ok_or(Error::NoResource)?;
        
        ro_tx.commit()?;
        
        Ok(signature_private_key)
    }

    fn get_attached_identity_signature(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<Vec<u8>, Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Bytes>(&ro_tx, Some(TABLE_ATTACHED_IDENTITY_SIGNATURE))?.ok_or(Error::NoTable(TABLE_ATTACHED_IDENTITY_SIGNATURE))?;
        let attached_identity_signature = database.get(&ro_tx, fingerprint.as_ref())?.ok_or(Error::NoResource)?.to_vec();
        
        ro_tx.commit()?;
        
        Ok(attached_identity_signature)
    }

    fn get_key_statistics(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<KeyStorageStatistics,Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&ro_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        let key_statistics = database.get(&ro_tx, fingerprint.as_ref())?.ok_or(Error::NoResource)?;
        
        ro_tx.commit()?;
        
        Ok(key_statistics)
    }

    fn get_encryption_public_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<Option<EncapsulationKey>,Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Borsh<EncapsulationKey>>(&ro_tx, Some(TABLE_ENCRYPTION_PUBLIC_KEY))?.ok_or(Error::NoTable(TABLE_ENCRYPTION_PUBLIC_KEY))?;
        let public_key = database.get(&ro_tx, fingerprint.as_ref())?;
        
        ro_tx.commit()?;
        
        Ok(public_key)
    }

    fn get_encryption_private_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<Option<DecapsulationKey>,Error> {
        
        let ro_tx = self.read_txn()?;
        
        let database = self.open_database::<Bytes, Borsh<DecapsulationKey>>(&ro_tx, Some(TABLE_ENCRYPTION_PRIVATE_KEY))?.ok_or(Error::NoTable(TABLE_ENCRYPTION_PRIVATE_KEY))?;
        let private_key = database.get(&ro_tx, fingerprint.as_ref())?;
        
        ro_tx.commit()?;
        
        Ok(private_key)
    }
}

impl KeyringWrite for LMDBKeyring {
    
    #[cold]
    fn init(
        options: Self::OpenOptions
    ) -> Result<(), Error> {
        #[allow(unsafe_code)]
        let lmdb = unsafe { env_config(true).open(options.path)? };
        
        let mut rw_tx = lmdb.write_txn()?;
        
        lmdb.create_database::<Bytes, Borsh<AttachedIdentity>>(&mut rw_tx, Some(TABLE_ATTACHED_IDENTITY))?;
        lmdb.create_database::<Bytes, Bytes>(&mut rw_tx, Some(TABLE_ATTACHED_IDENTITY_SIGNATURE))?;
        lmdb.database_options().types::<Str, Bytes>().flags(DatabaseFlags::DUP_SORT).name(TABLE_NAME_FINGERPRINT).create(&mut rw_tx)?;
        lmdb.create_database::<Bytes, Borsh<SignaturePublicKey>>(&mut rw_tx, Some(TABLE_SIGNATURE_PUBLIC_KEY))?;
        lmdb.create_database::<Bytes, Borsh<SignaturePrivateKey>>(&mut rw_tx, Some(TABLE_SIGNATURE_PRIVATE_KEY))?;
        lmdb.create_database::<Bytes, Borsh<EncapsulationKey>>(&mut rw_tx, Some(TABLE_ENCRYPTION_PUBLIC_KEY))?;
        lmdb.create_database::<Bytes, Borsh<DecapsulationKey>>(&mut rw_tx, Some(TABLE_ENCRYPTION_PRIVATE_KEY))?;
        lmdb.create_database::<Bytes, Borsh<KeyStorageStatistics>>(&mut rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        
        rw_tx.commit()?;
        
        let event = lmdb.prepare_for_closing();
        event.wait();
        
        Ok(())
    }
    
    #[cold]
    fn open_write( options: Self::OpenOptions) -> Result<Self, Error> {
        #[allow(unsafe_code)]
        let lmdb = unsafe { env_config(true).open(options.path)? };
        
        Ok(Self { lmdb })
    }
    
    fn remove_keys(
        &self,
        fingerprint: &Fingerprint,
    ) -> Result<AttachedIdentity, Error> {
        
        let mut rw_tx = self.write_txn()?;
        
        // Delete attached identity
        let database = self.open_database::<Bytes, Borsh<AttachedIdentity>>(&rw_tx, Some(TABLE_ATTACHED_IDENTITY))?.ok_or(Error::NoTable(TABLE_ATTACHED_IDENTITY))?;
        let attached_identity = database.get(&rw_tx, fingerprint.as_ref())?.ok_or(Error::NoResource)?;
        database.delete(&mut rw_tx, fingerprint.as_ref())?;
        
        // Delete name fingerprint correlation
        let database = self.database_options().types::<Str, Bytes>().flags(DatabaseFlags::DUP_SORT).name(TABLE_NAME_FINGERPRINT).open(&rw_tx)?.ok_or(Error::NoTable(TABLE_NAME_FINGERPRINT))?;
        database.delete(&mut rw_tx, &attached_identity.owner_name)?;
        
        // Delete signature public key
        let database = self.open_database::<Bytes, Borsh<SignaturePublicKey>>(&rw_tx, Some(TABLE_SIGNATURE_PUBLIC_KEY))?.ok_or(Error::NoTable(TABLE_SIGNATURE_PUBLIC_KEY))?;
        database.delete(&mut rw_tx, fingerprint.as_ref())?;
        
        // Delete signature private key
        let database = self.open_database::<Bytes, Borsh<SignaturePrivateKey>>(&rw_tx, Some(TABLE_SIGNATURE_PRIVATE_KEY))?.ok_or(Error::NoTable(TABLE_SIGNATURE_PRIVATE_KEY))?;
        database.delete(&mut rw_tx, fingerprint.as_ref())?;
        
        // Delete encryption public key
        let database = self.open_database::<Bytes, Borsh<EncapsulationKey>>(&rw_tx, Some(TABLE_ENCRYPTION_PUBLIC_KEY))?.ok_or(Error::NoTable(TABLE_ENCRYPTION_PUBLIC_KEY))?;
        database.delete(&mut rw_tx, fingerprint.as_ref())?;
        
        // Delete encryption private key
        let database = self.open_database::<Bytes, Borsh<DecapsulationKey>>(&rw_tx, Some(TABLE_ENCRYPTION_PRIVATE_KEY))?.ok_or(Error::NoTable(TABLE_ENCRYPTION_PRIVATE_KEY))?;
        database.delete(&mut rw_tx, fingerprint.as_ref())?;
        
        // Delete storage statistics
        let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        database.delete(&mut rw_tx, fingerprint.as_ref())?;
        
        rw_tx.commit()?;
        
        Ok(attached_identity)
    }

    fn insert_signature_public_key(
        &self, 
        public_key: &SignaturePublicKey,
        signature: &[u8],
        informations: &AttachedIdentity
    ) -> Result<(),Error> {
        
        let mut rw_tx = self.write_txn()?;
        
        // Insert attached identity
        let database = self.open_database::<Bytes, Borsh<AttachedIdentity>>(&rw_tx, Some(TABLE_ATTACHED_IDENTITY))?.ok_or(Error::NoTable(TABLE_ATTACHED_IDENTITY))?;
        database.put(&mut rw_tx, public_key.fingerprint().as_ref(), informations)?;
        
        // Insert attached identity signature
        let database = self.open_database::<Bytes, Bytes>(&rw_tx, Some(TABLE_ATTACHED_IDENTITY_SIGNATURE))?.ok_or(Error::NoTable(TABLE_ATTACHED_IDENTITY_SIGNATURE))?;
        database.put(&mut rw_tx, public_key.fingerprint().as_ref(), signature)?;
        
        // Insert fingerprint name correlation
        let database = self.database_options().types::<Str, Bytes>().flags(DatabaseFlags::DUP_SORT).name(TABLE_NAME_FINGERPRINT).open(&rw_tx)?.ok_or(Error::NoTable(TABLE_NAME_FINGERPRINT))?;
        database.put(&mut rw_tx, &informations.owner_name, public_key.fingerprint().as_ref())?;
        
        // Insert public key
        let database = self.open_database::<Bytes, Borsh<SignaturePublicKey>>(&rw_tx, Some(TABLE_SIGNATURE_PUBLIC_KEY))?.ok_or(Error::NoTable(TABLE_SIGNATURE_PUBLIC_KEY))?;
        database.put(&mut rw_tx, public_key.fingerprint().as_ref(), public_key)?;
        
        // Generate storage statistics
        let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        if database.get(&rw_tx, public_key.fingerprint().as_ref())?.is_none() {
            let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
            database.put(&mut rw_tx, public_key.fingerprint().as_ref(), &KeyStorageStatistics { signature_private_key: false, encryption_public_subkey: false, encryption_private_subkey: false })?;
        }
        
        rw_tx.commit()?;
        
        Ok(())
    }

    fn insert_signature_private_key(
        &self, 
        private_key: &SignaturePrivateKey,
    ) -> Result<(),Error> {
        
        let mut rw_tx = self.write_txn()?;
        
        // Insert private key into database
        let database = self.open_database::<Bytes, Borsh<SignaturePrivateKey>>(&rw_tx, Some(TABLE_SIGNATURE_PRIVATE_KEY))?.ok_or(Error::NoTable(TABLE_SIGNATURE_PRIVATE_KEY))?;
        database.put(&mut rw_tx, private_key.fingerprint().as_ref(), private_key)?;
        
        // Update database statistics
        let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        let mut stats = database.get(&rw_tx, private_key.fingerprint().as_ref())?.ok_or(Error::NoResource)?;
        stats.signature_private_key = true;
        database.put(&mut rw_tx, private_key.fingerprint().as_ref(), &stats)?;
        
        rw_tx.commit()?;
        
        Ok(())
    }

    fn insert_encryption_public_key(
        &self, 
        public_key: &EncapsulationKey,
    ) -> Result<(),Error> {
        
        let mut rw_tx = self.write_txn()?;
        
        // Insert private key into database
        let database = self.open_database::<Bytes, Borsh<EncapsulationKey>>(&rw_tx, Some(TABLE_ENCRYPTION_PUBLIC_KEY))?.ok_or(Error::NoTable(TABLE_ENCRYPTION_PUBLIC_KEY))?;
        database.put(&mut rw_tx, public_key.fingerprint().as_ref(), public_key)?;
        
        // Update database statistics
        let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        if let Some(mut stats) = database.get(&rw_tx, public_key.fingerprint().as_ref())? {
            stats.encryption_public_subkey = true;
            database.put(&mut rw_tx, public_key.fingerprint().as_ref(), &stats)?;
        } else {
            let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
            database.put(&mut rw_tx, public_key.fingerprint().as_ref(), &KeyStorageStatistics { signature_private_key: false, encryption_public_subkey: true, encryption_private_subkey: false })?;
        }
        
        rw_tx.commit()?;
        
        Ok(())
    }

    fn insert_encryption_private_key(
        &self, 
        private_key: &DecapsulationKey,
    ) -> Result<(),Error> {
        
        let mut rw_tx = self.write_txn()?;
        
        // Insert private key into database
        let database = self.open_database::<Bytes, Borsh<DecapsulationKey>>(&rw_tx, Some(TABLE_ENCRYPTION_PRIVATE_KEY))?.ok_or(Error::NoTable(TABLE_ENCRYPTION_PRIVATE_KEY))?;
        database.put(&mut rw_tx, private_key.fingerprint().as_ref(), private_key)?;
        
        // Update database statistics
        let database = self.open_database::<Bytes, Borsh<KeyStorageStatistics>>(&rw_tx, Some(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?.ok_or(Error::NoTable(TABLE_IDENTITY_KEY_STORAGE_STATISTICS))?;
        let mut stats = database.get(&rw_tx, private_key.fingerprint().as_ref())?.ok_or(Error::NoResource)?;
        stats.encryption_private_subkey = true;
        database.put(&mut rw_tx, private_key.fingerprint().as_ref(), &stats)?;
        
        rw_tx.commit()?;
        
        Ok(())
    }
}
