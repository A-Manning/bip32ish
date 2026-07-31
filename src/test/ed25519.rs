//! ed25519_bip32 tests

use std::ops::Add;

use curve25519_dalek::{Scalar, edwards::SubgroupPoint};
use digest::{
    FixedOutput, OutputSizeUser, Update,
    array::{self, Array, ArrayN},
    common::KeySizeUser,
};
use group::{Group, GroupEncoding, ff::PrimeField};
use hmac::{Hmac, KeyInit, Mac};
use num_bigint::BigUint;
use sha2::Sha512;
use thiserror::Error;

use crate::{
    Codec, FixedOutputAs, U31, Xpriv, Xpub,
    codec::{self, LittleEndian},
};

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
struct U256 {
    le_bytes: [u8; 32],
}

impl Add for U256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let this = BigUint::from_bytes_le(self.le_bytes.as_slice());
        let rhs = BigUint::from_bytes_le(rhs.le_bytes.as_slice());
        let res_biguint: BigUint = (this + rhs) % (BigUint::ONE << 256);
        let mut res_le_bytes = [0u8; 32];
        for (idx, byte) in res_biguint.to_bytes_le().into_iter().enumerate() {
            res_le_bytes[idx] = byte;
        }
        Self {
            le_bytes: res_le_bytes,
        }
    }
}

struct U256Codec;

impl Codec<U256> for U256Codec {
    type DecodeError = std::io::Error;
    type EncodeError = std::io::Error;

    #[inline(always)]
    fn decode<R>(mut reader: R) -> Result<U256, Self::DecodeError>
    where
        R: std::io::Read,
    {
        let mut le_bytes = [0u8; 32];
        reader.read_exact(le_bytes.as_mut_slice())?;
        Ok(U256 { le_bytes })
    }

    #[inline(always)]
    fn encode<W>(value: &U256, mut writer: W) -> Result<(), Self::EncodeError>
    where
        W: std::io::Write,
    {
        writer.write_all(value.le_bytes.as_slice())
    }
}

#[repr(transparent)]
struct Imac<const HARDENED: bool>(Hmac<Sha512>);

impl<const HARDENED: bool> KeySizeUser for Imac<HARDENED> {
    type KeySize = array::sizes::U32;
}

impl KeyInit for Imac<false> {
    fn new(key: &digest::Key<Self>) -> Self {
        let mut inner =
            <Hmac<_> as KeyInit>::new_from_slice(key.as_slice()).unwrap();
        <Hmac<_> as Update>::update(&mut inner, &[0x03]);
        Self(inner)
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        <Hmac<_> as KeyInit>::new_from_slice(key).map(|mut inner| {
            <Hmac<_> as Update>::update(&mut inner, &[0x03]);
            Self(inner)
        })
    }
}

impl KeyInit for Imac<true> {
    fn new(key: &digest::Key<Self>) -> Self {
        let mut inner =
            <Hmac<_> as KeyInit>::new_from_slice(key.as_slice()).unwrap();
        <Hmac<_> as Update>::update(&mut inner, &[0x01]);
        Self(inner)
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        <Hmac<_> as KeyInit>::new_from_slice(key).map(|mut inner| {
            <Hmac<_> as Update>::update(&mut inner, &[0x01]);
            Self(inner)
        })
    }
}

impl<const HARDENED: bool> Update for Imac<HARDENED> {
    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        <Hmac<_> as Update>::update(&mut self.0, data)
    }

    #[inline(always)]
    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self(self.0.chain(data))
    }
}

impl<const HARDENED: bool> OutputSizeUser for Imac<HARDENED> {
    type OutputSize = array::sizes::U32;
}

impl<const HARDENED: bool> FixedOutput for Imac<HARDENED> {
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let full_digest: [u8; 64] = self.0.finalize_fixed().0;
        let (_, digest) = full_digest.split_last_chunk::<32>().unwrap();
        out.copy_from_slice(digest);
    }
}

#[repr(transparent)]
struct Zmac<const HARDENED: bool>(Hmac<Sha512>);

impl<const HARDENED: bool> KeySizeUser for Zmac<HARDENED> {
    type KeySize = array::sizes::U32;
}

impl KeyInit for Zmac<false> {
    fn new(key: &digest::Key<Self>) -> Self {
        let mut inner =
            <Hmac<_> as KeyInit>::new_from_slice(key.as_slice()).unwrap();
        <Hmac<_> as Update>::update(&mut inner, &[0x02]);
        Self(inner)
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        <Hmac<_> as KeyInit>::new_from_slice(key).map(|mut inner| {
            <Hmac<_> as Update>::update(&mut inner, &[0x02]);
            Self(inner)
        })
    }
}

impl KeyInit for Zmac<true> {
    fn new(key: &digest::Key<Self>) -> Self {
        let mut inner =
            <Hmac<_> as KeyInit>::new_from_slice(key.as_slice()).unwrap();
        <Hmac<_> as Update>::update(&mut inner, &[0x00]);
        Self(inner)
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        <Hmac<_> as KeyInit>::new_from_slice(key).map(|mut inner| {
            <Hmac<_> as Update>::update(&mut inner, &[0x00]);
            Self(inner)
        })
    }
}

impl<const HARDENED: bool> Update for Zmac<HARDENED> {
    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        <Hmac<_> as Update>::update(&mut self.0, data)
    }

    #[inline(always)]
    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self(self.0.chain(data))
    }
}

impl<const HARDENED: bool> FixedOutputAs<(Scalar, U256)> for Zmac<HARDENED> {
    fn finalize_as(self) -> (Scalar, U256) {
        let digest = self.0.finalize().into_bytes();
        let (l32, zr) = digest.split_last_chunk::<32>().unwrap();
        let (zl, _) = l32.split_first_chunk::<28>().unwrap();
        let zl: [u8; 32] = {
            let mut bytes = [0u8; 32];
            for (idx, byte) in zl.iter().copied().enumerate() {
                bytes[idx] = byte;
            }
            bytes
        };
        let zl = Scalar::from_bytes_mod_order(zl);
        let secret_tweak = zl * Scalar::from(8u8);
        let secret_extra_tweak = U256 { le_bytes: *zr };
        (secret_tweak, secret_extra_tweak)
    }
}

struct Hasher<const HARDENED: bool> {
    imac: Imac<HARDENED>,
    zmac: Zmac<HARDENED>,
}

impl<const HARDENED: bool> KeySizeUser for Hasher<HARDENED> {
    type KeySize = array::sizes::U32;
}

impl<const HARDENED: bool> KeyInit for Hasher<HARDENED>
where
    Imac<HARDENED>: KeyInit<KeySize = Self::KeySize>,
    Zmac<HARDENED>: KeyInit<KeySize = Self::KeySize>,
{
    fn new(key: &digest::Key<Self>) -> Self {
        let imac = Imac::new(key);
        let zmac = Zmac::new(key);
        Self { imac, zmac }
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        let imac = Imac::new_from_slice(key)?;
        let zmac = Zmac::new_from_slice(key)?;
        Ok(Self { imac, zmac })
    }
}

impl<const HARDENED: bool> Update for Hasher<HARDENED> {
    #[inline(always)]
    fn update(&mut self, data: &[u8]) {
        self.imac.update(data);
        self.zmac.update(data);
    }

    #[inline]
    fn chain(self, data: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        let Self { imac, zmac } = self;
        let imac = imac.chain(data.as_ref());
        let zmac = zmac.chain(data);
        Self { imac, zmac }
    }
}

impl<const HARDENED: bool> FixedOutputAs<(Scalar, U256, ArrayN<u8, 32>)>
    for Hasher<HARDENED>
{
    #[inline(always)]
    fn finalize_as(self) -> (Scalar, U256, ArrayN<u8, 32>) {
        let (secret_tweak, secret_extra_tweak) = self.zmac.finalize_as();
        (secret_tweak, secret_extra_tweak, self.imac.finalize_fixed())
    }
}

#[derive(Debug, Error)]
#[error("failed to decode curve25519 subgroup point")]
struct Rfc8032DecodeSubgroupPoint;

fn rfc8032_decode_subgroup_point(
    bytes: &[u8; 32],
) -> Result<SubgroupPoint, Rfc8032DecodeSubgroupPoint> {
    SubgroupPoint::from_bytes(bytes)
        .into_option()
        .ok_or(Rfc8032DecodeSubgroupPoint)
}

fn rfc8032_encode_subgroup_point(point: &SubgroupPoint) -> [u8; 32] {
    point.to_bytes()
}

struct Rfc8032Codec;

impl Codec<SubgroupPoint> for Rfc8032Codec {
    type DecodeError = std::io::Error;

    type EncodeError = std::io::Error;

    fn decode<R>(mut reader: R) -> Result<SubgroupPoint, Self::DecodeError>
    where
        R: std::io::Read,
    {
        let mut bytes = [0u8; 32];
        reader.read_exact(bytes.as_mut_slice())?;
        rfc8032_decode_subgroup_point(&bytes).map_err(std::io::Error::other)
    }

    fn encode<W>(
        point: &SubgroupPoint,
        mut writer: W,
    ) -> Result<(), Self::EncodeError>
    where
        W: std::io::Write,
    {
        writer.write_all(rfc8032_encode_subgroup_point(point).as_slice())
    }
}

struct Params;

impl crate::Params for Params {
    type ChaincodeSize = array::sizes::U32;

    type ChildNumberCodec = LittleEndian;

    type Group = SubgroupPoint;

    type HardenedHasher = Hasher<true>;

    type NonHardenedHasher = Hasher<false>;

    type PubkeyCodec = Rfc8032Codec;

    type SecretExtra = U256;

    type SecretExtraCodec = U256Codec;

    type SecretScalar = Scalar;

    type SecretScalarCodec = codec::PrimeField;

    const MAX_DEPTH: usize = 20;
}

fn test_public_derive_at_idx(
    pubkey: SubgroupPoint,
    chaincode: [u8; 32],
    idx: U31,
) -> anyhow::Result<()> {
    let (derived_pubkey, derived_chaincode) = {
        let xpub = Xpub::<Params>::new_master(pubkey, Array(chaincode));
        let derived_xpub = xpub.derive(idx)?;
        let derived_pubkey =
            rfc8032_encode_subgroup_point(&derived_xpub.pubkey);
        (derived_pubkey, derived_xpub.chaincode.0)
    };

    let expected = {
        let pubkey_bytes = rfc8032_encode_subgroup_point(&pubkey);
        let xpub = ed25519_bip32::XPub::from_pk_and_chaincode(
            &pubkey_bytes,
            &chaincode,
        );
        xpub.derive(ed25519_bip32::DerivationScheme::V2, idx.0)?
    };

    anyhow::ensure!(derived_pubkey == *expected.public_key_bytes());
    anyhow::ensure!(derived_chaincode == *expected.chain_code());
    Ok(())
}

#[test]
fn test_public_derive() -> anyhow::Result<()> {
    for scalar in 1..100u8 {
        let pubkey = SubgroupPoint::generator() * Scalar::from(scalar);
        test_public_derive_at_idx(pubkey, [0x69; 32], U31(420))?
    }
    Ok(())
}

fn test_hardened_derive_at_idx(
    secret_scalar: Scalar,
    secret_extra: U256,
    chaincode: [u8; 32],
    idx: U31,
) -> anyhow::Result<()> {
    let (derived_pubkey, derived_chaincode) = {
        let xpriv = Xpriv::<Params>::new_master(
            secret_scalar,
            secret_extra,
            Array(chaincode),
        );
        let derived_xpriv = xpriv.derive_hardened(idx)?;
        let derived_xpub = derived_xpriv.xpub();
        let derived_pubkey =
            rfc8032_encode_subgroup_point(&derived_xpub.pubkey);
        (derived_pubkey, derived_xpub.chaincode.0)
    };

    let expected = {
        let extended_secret = {
            let mut extended_secret = [0u8; 64];
            for (idx, byte) in secret_scalar.to_repr().into_iter().enumerate() {
                extended_secret[idx] = byte
            }
            <U256Codec as Codec<_>>::encode(
                &secret_extra,
                &mut extended_secret[32..],
            )?;
            extended_secret
        };
        let xpriv = ed25519_bip32::XPrv::from_extended_and_chaincode(
            &extended_secret,
            &chaincode,
        );
        xpriv
            .derive(
                ed25519_bip32::DerivationScheme::V2,
                idx.0 | (u32::MAX << 31),
            )
            .public()
    };
    anyhow::ensure!(derived_pubkey == *expected.public_key_bytes());
    anyhow::ensure!(derived_chaincode == *expected.chain_code());
    Ok(())
}

#[test]
fn test_hardened_derive() -> anyhow::Result<()> {
    for scalar in 1..100u8 {
        let secret_scalar = Scalar::from(scalar);
        let secret_extra = U256 {
            le_bytes: [scalar; 32],
        };
        test_hardened_derive_at_idx(
            secret_scalar,
            secret_extra,
            [0x69; 32],
            U31(420),
        )?
    }
    Ok(())
}
