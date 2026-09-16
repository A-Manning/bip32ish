//! BIP32 and Ed25519-Bip32 compatible scheme for arbitrary prime-order groups.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use std::ops::Add;

use ::{
    digest::{
        FixedOutput, KeyInit, Update,
        array::{Array, ArraySize},
    },
    educe::Educe,
    group::{Group, ff::PrimeField, prime::PrimeGroup},
    thiserror::Error,
};

pub use digest;
pub use group;

mod util;

/// Derivation index is a 32 bits number representing
/// a type of derivation and a 31 bits number.
///
/// The highest bit set represent a hard derivation,
/// whereas the highest bit cleared represents soft derivation.
pub type DerivationIndex = u32;

pub mod u31 {
    use std::convert::TryFrom;

    use thiserror::Error;

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct U31(pub(crate) u32);

    impl U31 {
        pub fn new(value: u32) -> Option<Self> {
            if value >> 31 == 0 {
                Some(Self(value))
            } else {
                None
            }
        }

        pub fn value(&self) -> u32 {
            self.0
        }
    }

    #[derive(Debug, Error)]
    #[error("Invalid u31 value")]
    pub struct FromU32Error;

    impl TryFrom<u32> for U31 {
        type Error = FromU32Error;

        #[inline(always)]
        fn try_from(value: u32) -> Result<Self, Self::Error> {
            Self::new(value).ok_or(FromU32Error)
        }
    }
}
pub use u31::U31;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ChildIndex {
    NonHardened { index: U31 },
    Hardened { index: U31 },
}

impl From<DerivationIndex> for ChildIndex {
    fn from(idx: u32) -> Self {
        const HIGH_BIT_ONLY: u32 = 1 << 31;
        if idx & HIGH_BIT_ONLY == 0 {
            ChildIndex::NonHardened { index: U31(idx) }
        } else {
            ChildIndex::Hardened {
                index: U31(idx ^ HIGH_BIT_ONLY),
            }
        }
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Fingerprint(pub [u8; 4]);

impl Fingerprint {
    const MASTER_PARENT: Self = Self([0u8; 4]);
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#08x}", u32::from_be_bytes(self.0))
    }
}

#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct XKeyIdentifier(pub [u8; 20]);

impl XKeyIdentifier {
    pub const fn fingerprint(&self) -> Fingerprint {
        Fingerprint([self.0[0], self.0[1], self.0[2], self.0[3]])
    }
}

/// Traits that express an encoding to/from bytes
pub mod codec {
    use group::ff;

    pub trait Codec<T> {
        type DecodeError;

        type EncodeError;

        fn decode<R>(reader: R) -> Result<T, Self::DecodeError>
        where
            R: std::io::Read;

        fn encode<W>(value: &T, writer: W) -> Result<(), Self::EncodeError>
        where
            W: std::io::Write;
    }

    /// Big-endian codec
    pub struct BigEndian;

    impl Codec<u32> for BigEndian {
        type DecodeError = std::io::Error;

        type EncodeError = std::io::Error;

        fn decode<R>(mut reader: R) -> Result<u32, Self::DecodeError>
        where
            R: std::io::Read,
        {
            let mut bytes = [0u8; 4];
            reader.read_exact(bytes.as_mut_slice())?;
            Ok(u32::from_be_bytes(bytes))
        }

        #[inline(always)]
        fn encode<W>(
            value: &u32,
            mut writer: W,
        ) -> Result<(), Self::EncodeError>
        where
            W: std::io::Write,
        {
            writer.write_all(value.to_be_bytes().as_slice())
        }
    }

    /// Little-endian codec
    pub struct LittleEndian;

    impl Codec<u32> for LittleEndian {
        type DecodeError = std::io::Error;

        type EncodeError = std::io::Error;

        fn decode<R>(mut reader: R) -> Result<u32, Self::DecodeError>
        where
            R: std::io::Read,
        {
            let mut bytes = [0u8; 4];
            reader.read_exact(bytes.as_mut_slice())?;
            Ok(u32::from_le_bytes(bytes))
        }

        #[inline(always)]
        fn encode<W>(
            value: &u32,
            mut writer: W,
        ) -> Result<(), Self::EncodeError>
        where
            W: std::io::Write,
        {
            writer.write_all(value.to_le_bytes().as_slice())
        }
    }

    /// Group encoding from [`group::GroupEncoding`]
    pub struct GroupEncoding;

    impl<G> Codec<G> for GroupEncoding
    where
        G: group::GroupEncoding,
    {
        type DecodeError = std::io::Error;

        type EncodeError = std::io::Error;

        fn decode<R>(mut reader: R) -> Result<G, Self::DecodeError>
        where
            R: std::io::Read,
        {
            let mut repr = <G as group::GroupEncoding>::Repr::default();
            reader.read_exact(repr.as_mut())?;
            G::from_bytes(&repr)
                .into_option()
                .ok_or(std::io::Error::other(
                    "Failed to decode from group encoding repr",
                ))
        }

        fn encode<W>(value: &G, mut writer: W) -> Result<(), Self::EncodeError>
        where
            W: std::io::Write,
        {
            let repr: <G as group::GroupEncoding>::Repr = value.to_bytes();
            writer.write_all(repr.as_ref())
        }
    }

    /// Encoding from [`ff::PrimeField`]
    pub struct PrimeField;

    impl<F> Codec<F> for PrimeField
    where
        F: ff::PrimeField,
    {
        type DecodeError = std::io::Error;

        type EncodeError = std::io::Error;

        fn decode<R>(mut reader: R) -> Result<F, Self::DecodeError>
        where
            R: std::io::Read,
        {
            let mut repr = <F as ff::PrimeField>::Repr::default();
            reader.read_exact(repr.as_mut())?;
            F::from_repr(repr)
                .into_option()
                .ok_or(std::io::Error::other(
                    "Failed to decode from prime field repr",
                ))
        }

        fn encode<W>(value: &F, mut writer: W) -> Result<(), Self::EncodeError>
        where
            W: std::io::Write,
        {
            let repr: <F as ff::PrimeField>::Repr = value.to_repr();
            writer.write_all(repr.as_ref())
        }
    }
}
pub use codec::Codec;

/// Traits designed to work with traits from `[digest]`.
pub mod digest_traits {
    use digest::Update;

    /// Trait for hash functions with typed output
    pub trait FixedOutputAs<T>: Update + Sized {
        fn finalize_as(self) -> T;
    }
}
use digest_traits::FixedOutputAs;

pub trait Params {
    type ChaincodeSize: ArraySize;

    type ChildNumberCodec: Codec<u32>;

    type Group: PrimeGroup<Scalar = Self::SecretScalar>;

    type HardenedHasher: FixedOutputAs<(
            Self::SecretScalar,
            Self::SecretExtra,
            Array<u8, Self::ChaincodeSize>,
        )> + KeyInit<KeySize = Self::ChaincodeSize>
        + Update;

    type NonHardenedHasher: FixedOutputAs<(
            Self::SecretScalar,
            Self::SecretExtra,
            Array<u8, Self::ChaincodeSize>,
        )> + KeyInit<KeySize = Self::ChaincodeSize>
        + Update;

    type PubkeyCodec: Codec<Self::Group>;

    type SecretExtra: Add<Output = Self::SecretExtra> + Clone;

    type SecretExtraCodec: Codec<Self::SecretExtra>;

    type SecretScalar: PrimeField;

    type SecretScalarCodec: Codec<Self::SecretScalar>;

    /// Maximum permitted derivation depth
    const MAX_DEPTH: usize;
}

pub type EncodeChildNumberError<P> =
    <<P as Params>::ChildNumberCodec as Codec<u32>>::EncodeError;

pub type EncodePubkeyError<P> =
    <<P as Params>::PubkeyCodec as Codec<<P as Params>::Group>>::EncodeError;

pub type EncodeSecretExtraError<P> = <
    <P as Params>::SecretExtraCodec as Codec<<P as Params>::SecretExtra>
>::EncodeError;

pub type EncodeSecretScalarError<P> =
    <<P as Params>::SecretScalarCodec as Codec<
        <<P as Params>::Group as Group>::Scalar,
    >>::EncodeError;

#[derive(Educe, Error)]
#[educe(Debug)]
pub enum NonHardenedDeriveError<P>
where
    P: Params,
{
    #[error("Derivation would exceed maximum depth")]
    DepthLimit,
    #[error(transparent)]
    EncodeChildNumber(EncodeChildNumberError<P>),
    #[error(transparent)]
    EncodePubkey(EncodePubkeyError<P>),
}

/// Extended public key
#[derive(Educe)]
#[educe(Debug, Eq, PartialEq)]
pub struct Xpub<P>
where
    P: Params,
{
    pub pubkey: P::Group,
    pub chaincode: Array<u8, P::ChaincodeSize>,
    /// How many derivations this key is from the master key (depth 0)
    pub depth: usize,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: u32,
}

impl<P> Xpub<P>
where
    P: Params,
{
    pub const fn new_master(
        pubkey: P::Group,
        chaincode: Array<u8, P::ChaincodeSize>,
    ) -> Self {
        Self {
            pubkey,
            chaincode,
            depth: 0,
            parent_fingerprint: Fingerprint::MASTER_PARENT,
            child_number: 0,
        }
    }

    pub fn identifier(&self) -> Result<XKeyIdentifier, EncodePubkeyError<P>> {
        let sha256_digest = {
            let mut hasher = util::WriteUpdate(sha2::Sha256::default());
            <P::PubkeyCodec as Codec<_>>::encode(&self.pubkey, &mut hasher)?;
            let util::WriteUpdate(hasher) = hasher;
            hasher.finalize_fixed()
        };
        let ripemd160_digest = {
            let mut hasher = ripemd::Ripemd160::default();
            hasher.update(sha256_digest.as_slice());
            hasher.finalize_fixed()
        };
        Ok(XKeyIdentifier(ripemd160_digest.0))
    }

    pub fn derive(&self, idx: U31) -> Result<Self, NonHardenedDeriveError<P>> {
        if self.depth >= P::MAX_DEPTH {
            return Err(NonHardenedDeriveError::DepthLimit);
        }
        let hasher = <P::NonHardenedHasher as KeyInit>::new(&self.chaincode);
        let mut hasher = util::WriteUpdate(hasher);
        <P::PubkeyCodec as Codec<_>>::encode(&self.pubkey, &mut hasher)
            .map_err(NonHardenedDeriveError::EncodePubkey)?;
        <P::ChildNumberCodec as Codec<_>>::encode(&idx.value(), &mut hasher)
            .map_err(NonHardenedDeriveError::EncodeChildNumber)?;
        let util::WriteUpdate(hasher) = hasher;
        let (tweak_scalar, _tweak_extra, chaincode) = hasher.finalize_as();
        let tweak_point = <P::Group as Group>::generator() * tweak_scalar;
        let pubkey = self.pubkey + tweak_point;
        let depth = self.depth + 1;
        let parent_fingerprint = self
            .identifier()
            .map_err(NonHardenedDeriveError::EncodePubkey)?
            .fingerprint();
        let child_number = idx.value();
        Ok(Self {
            pubkey,
            chaincode,
            depth,
            parent_fingerprint,
            child_number,
        })
    }
}

#[derive(Educe, Error)]
#[educe(Debug)]
pub enum HardenedDeriveError<P>
where
    P: Params,
{
    #[error("Derivation would exceed maximum depth")]
    DepthLimit,
    #[error(transparent)]
    EncodeChildNumber(EncodeChildNumberError<P>),
    #[error(transparent)]
    EncodePubkey(EncodePubkeyError<P>),
    #[error(transparent)]
    EncodeSecretExtra(EncodeSecretExtraError<P>),
    #[error(transparent)]
    EncodeSecretScalar(EncodeSecretScalarError<P>),
}

/// Extended secret key
pub struct Xpriv<P>
where
    P: Params,
{
    pub secret_scalar: P::SecretScalar,
    pub secret_extra: P::SecretExtra,
    pub chaincode: Array<u8, P::ChaincodeSize>,
    /// How many derivations this key is from the master key (depth 0)
    pub depth: usize,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: u32,
}

impl<P> Xpriv<P>
where
    P: Params,
{
    pub const fn new_master(
        secret_scalar: P::SecretScalar,
        secret_extra: P::SecretExtra,
        chaincode: Array<u8, P::ChaincodeSize>,
    ) -> Self {
        Self {
            secret_scalar,
            secret_extra,
            chaincode,
            depth: 0,
            parent_fingerprint: Fingerprint::MASTER_PARENT,
            child_number: 0,
        }
    }

    pub fn xpub(&self) -> Xpub<P>
where {
        Xpub {
            pubkey: P::Group::generator() * self.secret_scalar,
            chaincode: self.chaincode.clone(),
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
        }
    }

    pub fn identifier(&self) -> Result<XKeyIdentifier, EncodePubkeyError<P>> {
        let pubkey = P::Group::generator() * self.secret_scalar;
        let sha256_digest = {
            let mut hasher = util::WriteUpdate(sha2::Sha256::default());
            <P::PubkeyCodec as Codec<_>>::encode(&pubkey, &mut hasher)?;
            let util::WriteUpdate(hasher) = hasher;
            hasher.finalize_fixed()
        };
        let ripemd160_digest = {
            let mut hasher = ripemd::Ripemd160::default();
            hasher.update(sha256_digest.as_slice());
            hasher.finalize_fixed()
        };
        Ok(XKeyIdentifier(ripemd160_digest.0))
    }

    pub fn derive_hardened(
        &self,
        idx: U31,
    ) -> Result<Self, HardenedDeriveError<P>> {
        if self.depth >= P::MAX_DEPTH {
            return Err(HardenedDeriveError::DepthLimit);
        }
        let hasher = <P::HardenedHasher as KeyInit>::new(&self.chaincode);
        let mut hasher = util::WriteUpdate(hasher);
        <P::SecretScalarCodec as Codec<_>>::encode(
            &self.secret_scalar,
            &mut hasher,
        )
        .map_err(HardenedDeriveError::EncodeSecretScalar)?;
        <P::SecretExtraCodec as Codec<_>>::encode(
            &self.secret_extra,
            &mut hasher,
        )
        .map_err(HardenedDeriveError::EncodeSecretExtra)?;
        let child_number = idx.value() | (1 << 31);
        <P::ChildNumberCodec as Codec<_>>::encode(&child_number, &mut hasher)
            .map_err(HardenedDeriveError::EncodeChildNumber)?;
        let util::WriteUpdate(hasher) = hasher;
        let (tweak_secret, tweak_secret_extra, chaincode) =
            hasher.finalize_as();
        let secret_scalar = self.secret_scalar + tweak_secret;
        let secret_extra = self.secret_extra.clone() + tweak_secret_extra;
        let depth = self.depth + 1;
        let parent_fingerprint = self
            .identifier()
            .map_err(HardenedDeriveError::EncodePubkey)?
            .fingerprint();
        Ok(Self {
            secret_scalar,
            secret_extra,
            chaincode,
            depth,
            parent_fingerprint,
            child_number,
        })
    }

    pub fn derive_non_hardened(
        &self,
        idx: U31,
    ) -> Result<Self, NonHardenedDeriveError<P>> {
        if self.depth >= P::MAX_DEPTH {
            return Err(NonHardenedDeriveError::DepthLimit);
        }
        let hasher = <P::NonHardenedHasher as KeyInit>::new(&self.chaincode);
        let mut hasher = util::WriteUpdate(hasher);
        let pubkey = <P::Group as Group>::generator() * self.secret_scalar;
        <P::PubkeyCodec as Codec<_>>::encode(&pubkey, &mut hasher)
            .map_err(NonHardenedDeriveError::EncodePubkey)?;
        <P::ChildNumberCodec as Codec<_>>::encode(&idx.value(), &mut hasher)
            .map_err(NonHardenedDeriveError::EncodeChildNumber)?;
        let util::WriteUpdate(hasher) = hasher;
        let (tweak_secret, tweak_secret_extra, chaincode) =
            hasher.finalize_as();
        let secret_scalar = self.secret_scalar + tweak_secret;
        let secret_extra = self.secret_extra.clone() + tweak_secret_extra;
        let depth = self.depth + 1;
        let parent_fingerprint = self
            .identifier()
            .map_err(NonHardenedDeriveError::EncodePubkey)?
            .fingerprint();
        let child_number = idx.value();
        Ok(Self {
            secret_scalar,
            secret_extra,
            chaincode,
            depth,
            parent_fingerprint,
            child_number,
        })
    }
}

#[cfg(test)]
mod test;
