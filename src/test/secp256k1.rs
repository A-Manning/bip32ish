//! bip32 tests

use std::{ops::Add, sync::LazyLock};

use digest::{
    FixedOutput, Update,
    array::{self, Array, ArrayN},
    common::KeySizeUser,
};
use group::{Group, GroupEncoding, ff::PrimeField};
use hmac::{Hmac, KeyInit};
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::scalar::FromUintUnchecked,
};
use sha2::Sha512;
use thiserror::Error;

use crate::{
    ChildIndex, Codec, FixedOutputAs, U31, Xpriv, Xpub, codec::BigEndian,
};

#[derive(Clone, Debug)]
struct SecretExtra;

impl Add for SecretExtra {
    type Output = Self;

    #[inline(always)]
    fn add(self, _rhs: Self) -> Self::Output {
        Self
    }
}

struct SecretExtraCodec;

impl Codec<SecretExtra> for SecretExtraCodec {
    type DecodeError = std::convert::Infallible;
    type EncodeError = std::convert::Infallible;

    #[inline(always)]
    fn decode<R>(_reader: R) -> Result<SecretExtra, Self::DecodeError>
    where
        R: std::io::Read,
    {
        Ok(SecretExtra)
    }

    #[inline(always)]
    fn encode<W>(_: &SecretExtra, _writer: W) -> Result<(), Self::EncodeError>
    where
        W: std::io::Write,
    {
        Ok(())
    }
}

#[repr(transparent)]
struct Hasher<const PREFIX: bool>(Hmac<Sha512>);

impl<const PREFIX: bool> KeySizeUser for Hasher<PREFIX> {
    type KeySize = array::sizes::U32;
}

impl KeyInit for Hasher<true> {
    fn new(key: &digest::Key<Self>) -> Self {
        let mut inner =
            <Hmac<_> as KeyInit>::new_from_slice(key.as_slice()).unwrap();
        inner.update(&[0x00]);
        Self(inner)
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        let mut inner = <Hmac<_> as KeyInit>::new_from_slice(key)?;
        inner.update(&[0x00]);
        Ok(Self(inner))
    }
}

impl KeyInit for Hasher<false> {
    #[inline(always)]
    fn new(key: &digest::Key<Self>) -> Self {
        Self(<Hmac<_> as KeyInit>::new_from_slice(key.as_slice()).unwrap())
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, digest::InvalidLength> {
        <Hmac<_> as KeyInit>::new_from_slice(key).map(Self)
    }
}

impl<const PREFIX: bool> Update for Hasher<PREFIX> {
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

fn scalar_from_be_bytes(be_bytes: &[u8; 32]) -> Scalar {
    use k256::U256;
    let repr_u256 = U256::from_be_slice(be_bytes.as_slice());
    let fr_modulus = U256::from(Scalar::ONE.negate()) + U256::ONE;
    let res_u256 = repr_u256 % fr_modulus;
    Scalar::from_uint_unchecked(res_u256)
}

impl<const PREFIX: bool> FixedOutputAs<(Scalar, SecretExtra, ArrayN<u8, 32>)>
    for Hasher<PREFIX>
{
    fn finalize_as(self) -> (Scalar, SecretExtra, ArrayN<u8, 32>) {
        let full_digest: [u8; 64] = self.0.finalize_fixed().0;
        let (zl, chaincode) = full_digest.split_first_chunk::<32>().unwrap();
        let zl = scalar_from_be_bytes(zl);
        (zl, SecretExtra, Array::try_from(chaincode).unwrap())
    }
}

#[derive(Debug, Error)]
#[error("failed to decode secp256k1 affine point")]
struct Sec1DecodeAffine;

fn sec1_decode_affine(
    bytes: [u8; 33],
) -> Result<AffinePoint, Sec1DecodeAffine> {
    AffinePoint::from_bytes(&Array(bytes))
        .into_option()
        .ok_or(Sec1DecodeAffine)
}

#[derive(Debug, Error)]
#[error("failed to decode secp256k1 scalar")]
struct Sec1DecodeScalar;

fn sec1_decode_scalar(bytes: [u8; 32]) -> Result<Scalar, Sec1DecodeScalar> {
    Scalar::from_repr(Array(bytes))
        .into_option()
        .ok_or(Sec1DecodeScalar)
}

fn sec1_encode_affine(affine: &AffinePoint) -> [u8; 33] {
    affine.to_bytes().0
}

fn sec1_encode_scalar(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().0
}

struct Sec1CompressedCodec;

impl Codec<AffinePoint> for Sec1CompressedCodec {
    type DecodeError = std::io::Error;

    type EncodeError = std::io::Error;

    fn decode<R>(mut reader: R) -> Result<AffinePoint, Self::DecodeError>
    where
        R: std::io::Read,
    {
        let mut bytes = [0u8; 33];
        reader.read_exact(bytes.as_mut_slice())?;
        sec1_decode_affine(bytes).map_err(std::io::Error::other)
    }

    fn encode<W>(
        point: &AffinePoint,
        mut writer: W,
    ) -> Result<(), Self::EncodeError>
    where
        W: std::io::Write,
    {
        writer.write_all(sec1_encode_affine(point).as_slice())
    }
}

impl Codec<ProjectivePoint> for Sec1CompressedCodec {
    type DecodeError = std::io::Error;

    type EncodeError = std::io::Error;

    fn decode<R>(reader: R) -> Result<ProjectivePoint, Self::DecodeError>
    where
        R: std::io::Read,
    {
        let affine =
            <Sec1CompressedCodec as Codec<AffinePoint>>::decode(reader)?;
        Ok(affine.into())
    }

    fn encode<W>(
        point: &ProjectivePoint,
        writer: W,
    ) -> Result<(), Self::EncodeError>
    where
        W: std::io::Write,
    {
        <Sec1CompressedCodec as Codec<AffinePoint>>::encode(
            &point.to_affine(),
            writer,
        )
    }
}

impl Codec<Scalar> for Sec1CompressedCodec {
    type DecodeError = std::io::Error;

    type EncodeError = std::io::Error;

    fn decode<R>(mut reader: R) -> Result<Scalar, Self::DecodeError>
    where
        R: std::io::Read,
    {
        let mut bytes = [0u8; 32];
        reader.read_exact(bytes.as_mut_slice())?;
        sec1_decode_scalar(bytes).map_err(std::io::Error::other)
    }

    fn encode<W>(value: &Scalar, mut writer: W) -> Result<(), Self::EncodeError>
    where
        W: std::io::Write,
    {
        writer.write_all(sec1_encode_scalar(value).as_slice())
    }
}

struct Params;

impl crate::Params for Params {
    type ChaincodeSize = array::sizes::U32;

    type ChildNumberCodec = BigEndian;

    type Group = ProjectivePoint;

    type HardenedHasher = Hasher<true>;

    type NonHardenedHasher = Hasher<false>;

    type PubkeyCodec = Sec1CompressedCodec;

    type SecretExtra = SecretExtra;

    type SecretExtraCodec = SecretExtraCodec;

    type SecretScalar = Scalar;

    type SecretScalarCodec = Sec1CompressedCodec;

    const MAX_DEPTH: usize = usize::MAX;
}

static SECP256K1_CTXT: LazyLock<
    bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
> = LazyLock::new(bitcoin::secp256k1::Secp256k1::new);

fn test_public_derive_at_idx(
    pubkey: ProjectivePoint,
    chaincode: [u8; 32],
    idx: U31,
) -> anyhow::Result<()> {
    let (derived_cpubkey, derived_chaincode) = {
        let xpub = Xpub::<Params>::new_master(pubkey, Array(chaincode));
        let derived_xpub = xpub.derive(idx)?;
        let derived_cpubkey =
            sec1_encode_affine(&derived_xpub.pubkey.to_affine());
        (derived_cpubkey, derived_xpub.chaincode.0)
    };

    let (expected_cpubkey, expected_chaincode) = {
        let cpubkey_bytes = sec1_encode_affine(&pubkey.to_affine());
        let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&cpubkey_bytes)?;
        let xpub = bitcoin::bip32::Xpub {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: 0u32.into(),
            public_key: pubkey,
            chain_code: chaincode.into(),
        };
        let derived_xpub = xpub.ckd_pub(
            &SECP256K1_CTXT,
            bitcoin::bip32::ChildNumber::Normal { index: idx.value() },
        )?;
        (
            derived_xpub.public_key.serialize(),
            derived_xpub.chain_code.to_bytes(),
        )
    };

    anyhow::ensure!(derived_cpubkey == expected_cpubkey);
    anyhow::ensure!(derived_chaincode == expected_chaincode);
    Ok(())
}

#[test]
fn test_public_derive() -> anyhow::Result<()> {
    for scalar in 1..100u32 {
        let pubkey = ProjectivePoint::generator() * Scalar::from(scalar);
        test_public_derive_at_idx(pubkey, [0x69; 32], U31(420))?
    }
    Ok(())
}

fn test_hardened_derive_at_idx(
    secret_scalar: Scalar,
    chaincode: [u8; 32],
    idx: U31,
) -> anyhow::Result<()> {
    let (derived_cpubkey, derived_chaincode) = {
        let xpriv = Xpriv::<Params>::new_master(
            secret_scalar,
            SecretExtra,
            Array(chaincode),
        );
        let derived_xpriv = xpriv.derive_hardened(idx)?;
        let derived_xpub = derived_xpriv.xpub();
        let derived_cpubkey =
            sec1_encode_affine(&derived_xpub.pubkey.to_affine());
        (derived_cpubkey, derived_xpub.chaincode.0)
    };

    let (expected_cpubkey, expected_chaincode) = {
        let secret_bytes = sec1_encode_scalar(&secret_scalar);
        let private_key =
            bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes)?;
        let xpriv = bitcoin::bip32::Xpriv {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: 0u32.into(),
            private_key,
            chain_code: chaincode.into(),
        };
        let derived_xpriv = xpriv.derive_priv(
            &SECP256K1_CTXT,
            &[bitcoin::bip32::ChildNumber::Hardened { index: idx.value() }],
        )?;
        let derived_xpub =
            bitcoin::bip32::Xpub::from_priv(&SECP256K1_CTXT, &derived_xpriv);
        (
            derived_xpub.public_key.serialize(),
            derived_xpub.chain_code.to_bytes(),
        )
    };

    anyhow::ensure!(derived_cpubkey == expected_cpubkey);
    anyhow::ensure!(derived_chaincode == expected_chaincode);
    Ok(())
}

#[test]
fn test_hardened_derive() -> anyhow::Result<()> {
    for scalar in 1..100u32 {
        let secret_scalar = Scalar::from(scalar);
        test_hardened_derive_at_idx(secret_scalar, [0x69; 32], U31(420))?
    }
    Ok(())
}

fn test_derivation_path<DerivationPath>(
    secret_scalar: Scalar,
    chaincode: [u8; 32],
    derivation_path: DerivationPath,
) -> anyhow::Result<()>
where
    DerivationPath: IntoIterator<Item = ChildIndex>,
{
    let mut derived_xpriv = Xpriv::<Params>::new_master(
        secret_scalar,
        SecretExtra,
        Array(chaincode),
    );
    let mut expected_xpriv = {
        let secret_bytes = sec1_encode_scalar(&secret_scalar);
        let private_key =
            bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes)?;
        bitcoin::bip32::Xpriv {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: 0u32.into(),
            private_key,
            chain_code: chaincode.into(),
        }
    };
    for child_idx in derivation_path.into_iter() {
        match child_idx {
            ChildIndex::Hardened { index } => {
                derived_xpriv = derived_xpriv.derive_hardened(index)?;
                expected_xpriv = expected_xpriv.derive_priv(
                    &SECP256K1_CTXT,
                    &[bitcoin::bip32::ChildNumber::Hardened {
                        index: index.value(),
                    }],
                )?;
            }
            ChildIndex::NonHardened { index } => {
                // Verify non-hardened derivation for xpubs
                {
                    let derived_xpub = {
                        let derived_xpub = derived_xpriv.xpub();
                        derived_xpub.derive(index)?
                    };
                    derived_xpriv = derived_xpriv.derive_non_hardened(index)?;
                    anyhow::ensure!(derived_xpub == derived_xpriv.xpub());
                }
                expected_xpriv = expected_xpriv.derive_priv(
                    &SECP256K1_CTXT,
                    &[bitcoin::bip32::ChildNumber::Normal {
                        index: index.value(),
                    }],
                )?;
            }
        }
    }
    let (derived_cpubkey, derived_chaincode) = {
        let derived_xpub = derived_xpriv.xpub();
        let derived_cpubkey =
            sec1_encode_affine(&derived_xpub.pubkey.to_affine());
        (derived_cpubkey, derived_xpub.chaincode.0)
    };
    let (expected_cpubkey, expected_chaincode) = {
        let derived_xpub =
            bitcoin::bip32::Xpub::from_priv(&SECP256K1_CTXT, &expected_xpriv);
        (
            derived_xpub.public_key.serialize(),
            derived_xpub.chain_code.to_bytes(),
        )
    };
    anyhow::ensure!(derived_cpubkey == expected_cpubkey);
    anyhow::ensure!(derived_chaincode == expected_chaincode);
    Ok(())
}

#[test]
fn bip32_test_vectors() -> anyhow::Result<()> {
    struct Test<'a> {
        seed_hex: &'static str,
        path: &'a [ChildIndex],
    }
    let tests = [
        Test {
            seed_hex: "000102030405060708090a0b0c0d0e0f",
            path: &[
                ChildIndex::Hardened {
                    index: 0u32.try_into()?,
                },
                ChildIndex::NonHardened {
                    index: 1u32.try_into()?,
                },
                ChildIndex::Hardened {
                    index: 2u32.try_into()?,
                },
                ChildIndex::NonHardened {
                    index: 2u32.try_into()?,
                },
                ChildIndex::NonHardened {
                    index: 1_000_000_000u32.try_into()?,
                },
            ],
        },
        Test {
            seed_hex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            path: &[
                ChildIndex::NonHardened {
                    index: 0u32.try_into()?,
                },
                ChildIndex::Hardened {
                    index: 2147483647u32.try_into()?,
                },
                ChildIndex::NonHardened {
                    index: 1u32.try_into()?,
                },
                ChildIndex::Hardened {
                    index: 2147483646u32.try_into()?,
                },
                ChildIndex::NonHardened {
                    index: 2u32.try_into()?,
                },
            ],
        },
        Test {
            seed_hex: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            path: &[ChildIndex::Hardened {
                index: 0u32.try_into()?,
            }],
        },
        Test {
            seed_hex: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            path: &[
                ChildIndex::Hardened {
                    index: 0u32.try_into()?,
                },
                ChildIndex::Hardened {
                    index: 1u32.try_into()?,
                },
            ],
        },
    ];

    for test in tests {
        let seed: Vec<u8> = bitcoin::hex::FromHex::from_hex(test.seed_hex)?;
        let (secret_scalar, chaincode) = {
            let master_xpriv = bitcoin::bip32::Xpriv::new_master(
                bitcoin::Network::Bitcoin,
                &seed,
            )?;
            let scalar =
                sec1_decode_scalar(master_xpriv.private_key.secret_bytes())?;
            (scalar, master_xpriv.chain_code.to_bytes())
        };
        let () = test_derivation_path(
            secret_scalar,
            chaincode,
            test.path.iter().copied(),
        )?;
    }
    Ok(())
}
