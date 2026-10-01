from typing import Annotated

from cryptography import x509
from cryptography.hazmat import asn1


@asn1.sequence
class Extension:
    extnID: x509.ObjectIdentifier
    # RFC 5280 declares this as `BOOLEAN DEFAULT FALSE`, and DER forbids encoding a value equal to
    # its DEFAULT. Some Android devices encode `critical` as an explicit FALSE anyway, so this is
    # modeled as OPTIONAL to tolerate that particular DER violation.
    critical: bool | None
    extnValue: bytes


@asn1.sequence
class TBSCertificate:
    # `[0] EXPLICIT Version DEFAULT v1`, modeled as OPTIONAL for the same reason as above
    version: Annotated[int | None, asn1.Explicit(0)]
    # The following fields aren't needed so they're left unparsed
    serialNumber: asn1.TLV
    signature: asn1.TLV
    issuer: asn1.TLV
    validity: asn1.TLV
    subject: asn1.TLV
    subjectPublicKeyInfo: asn1.TLV
    issuerUniqueID: Annotated[asn1.BitString | None, asn1.Implicit(1)]
    subjectUniqueID: Annotated[asn1.BitString | None, asn1.Implicit(2)]
    extensions: Annotated[list[Extension] | None, asn1.Explicit(3)]


@asn1.sequence
class Certificate:
    """A minimal X.509 certificate schema for reading extensions

    `cryptography.x509.load_der_x509_certificate()` refuses to parse certificates that violate
    ASN.1 DER in any way. This schema only parses as much of the certificate as is needed to get
    to its extensions, and is lenient about known DER violations in the fields it does parse.

    See https://www.rfc-editor.org/rfc/rfc5280#section-4.1
    """

    tbsCertificate: TBSCertificate
    signatureAlgorithm: asn1.TLV
    signatureValue: asn1.TLV
