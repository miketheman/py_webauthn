from enum import Enum
from typing import Annotated

from cryptography.hazmat import asn1


# ASN.1 ENUMERATED isn't supported by cryptography's declarative ASN.1 API, so the following
# enumerated types are defined as Enums for reference, and their values are left unparsed as TLVs
class SecurityLevel(int, Enum):
    Software = 0
    TrustedEnvironment = 1
    StrongBox = 2


class VerifiedBootState(int, Enum):
    Verified = 0
    SelfSigned = 1
    Unverified = 2
    Failed = 3


@asn1.sequence
class RootOfTrust:
    verifiedBootKey: bytes
    deviceLocked: bool
    # VerifiedBootState
    verifiedBootState: asn1.TLV
    verifiedBootHash: bytes


@asn1.sequence
class AuthorizationList:
    purpose: Annotated[asn1.SetOf[int] | None, asn1.Explicit(1)]
    algorithm: Annotated[int | None, asn1.Explicit(2)]
    keySize: Annotated[int | None, asn1.Explicit(3)]
    digest: Annotated[asn1.SetOf[int] | None, asn1.Explicit(5)]
    padding: Annotated[asn1.SetOf[int] | None, asn1.Explicit(6)]
    ecCurve: Annotated[int | None, asn1.Explicit(10)]
    rsaPublicExponent: Annotated[int | None, asn1.Explicit(200)]
    rollbackResistance: Annotated[asn1.Null | None, asn1.Explicit(303)]
    activeDateTime: Annotated[int | None, asn1.Explicit(400)]
    originationExpireDateTime: Annotated[int | None, asn1.Explicit(401)]
    usageExpireDateTime: Annotated[int | None, asn1.Explicit(402)]
    noAuthRequired: Annotated[asn1.Null | None, asn1.Explicit(503)]
    userAuthType: Annotated[int | None, asn1.Explicit(504)]
    authTimeout: Annotated[int | None, asn1.Explicit(505)]
    allowWhileOnBody: Annotated[asn1.Null | None, asn1.Explicit(506)]
    trustedUserPresenceRequired: Annotated[asn1.Null | None, asn1.Explicit(507)]
    trustedConfirmationRequired: Annotated[asn1.Null | None, asn1.Explicit(508)]
    unlockedDeviceRequired: Annotated[asn1.Null | None, asn1.Explicit(509)]
    allApplications: Annotated[asn1.Null | None, asn1.Explicit(600)]
    applicationId: Annotated[bytes | None, asn1.Explicit(601)]
    creationDateTime: Annotated[int | None, asn1.Explicit(701)]
    origin: Annotated[int | None, asn1.Explicit(702)]
    rollbackResistant: Annotated[asn1.Null | None, asn1.Explicit(703)]
    rootOfTrust: Annotated[RootOfTrust | None, asn1.Explicit(704)]
    osVersion: Annotated[int | None, asn1.Explicit(705)]
    osPatchLevel: Annotated[int | None, asn1.Explicit(706)]
    attestationApplicationId: Annotated[bytes | None, asn1.Explicit(709)]
    attestationIdBrand: Annotated[bytes | None, asn1.Explicit(710)]
    attestationIdDevice: Annotated[bytes | None, asn1.Explicit(711)]
    attestationIdProduct: Annotated[bytes | None, asn1.Explicit(712)]
    attestationIdSerial: Annotated[bytes | None, asn1.Explicit(713)]
    attestationIdImei: Annotated[bytes | None, asn1.Explicit(714)]
    attestationIdMeid: Annotated[bytes | None, asn1.Explicit(715)]
    attestationIdManufacturer: Annotated[bytes | None, asn1.Explicit(716)]
    attestationIdModel: Annotated[bytes | None, asn1.Explicit(717)]
    vendorPatchLevel: Annotated[int | None, asn1.Explicit(718)]
    bootPatchLevel: Annotated[int | None, asn1.Explicit(719)]
    deviceUniqueAttestation: Annotated[asn1.Null | None, asn1.Explicit(720)]
    attestationIdSecondImei: Annotated[bytes | None, asn1.Explicit(723)]
    moduleHash: Annotated[bytes | None, asn1.Explicit(724)]


@asn1.sequence
class KeyDescription:
    """Attestation extension content as ASN.1 schema (DER-encoded)

    Corresponds to X.509 certificate extension with the following OID:

    `1.3.6.1.4.1.11129.2.1.17`

    See https://source.android.com/security/keystore/attestation#schema
    """

    attestationVersion: int
    # SecurityLevel
    attestationSecurityLevel: asn1.TLV
    keymasterVersion: int
    # SecurityLevel
    keymasterSecurityLevel: asn1.TLV
    attestationChallenge: bytes
    uniqueId: bytes
    softwareEnforced: AuthorizationList
    teeEnforced: AuthorizationList


class KeyOrigin(int, Enum):
    """`Tag::ORIGIN`

    See https://source.android.com/security/keystore/tags#origin
    """

    GENERATED = 0
    DERIVED = 1
    IMPORTED = 2
    UNKNOWN = 3


class KeyPurpose(int, Enum):
    """`Tag::PURPOSE`

    See https://source.android.com/security/keystore/tags#purpose
    """

    ENCRYPT = 0
    DECRYPT = 1
    SIGN = 2
    VERIFY = 3
    DERIVE_KEY = 4
    WRAP_KEY = 5
