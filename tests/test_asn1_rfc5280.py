from unittest import TestCase
from base64 import b64decode

from cryptography import x509
from cryptography.hazmat import asn1

from webauthn.helpers.asn1.android_key import KeyDescription, KeyOrigin, KeyPurpose
from webauthn.helpers.asn1.rfc5280 import Certificate


class TestASN1RFC5280Certificate(TestCase):
    def test_parses_extensions_of_cert_with_der_violation(self) -> None:
        """
        This "android-key" leaf certificate explicitly encodes Extension.critical as FALSE, in
        violation of ASN.1 DER, which makes `cryptography.x509` refuse to parse it. Its extensions
        should still be readable.
        """
        cert_bytes = b64decode(
            "MIID9jCCAmCgAwIBAgIBATALBgkqhkiG9w0BAQswOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA4YmM3NDljNzljZTI2M2JhZWU4Mzk4MGUzYWMzYjA5ODAeFw03MDAxMDEwMDAwMDBaFw00MDEyMzExNTU5NTlaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXEG0W2FVdhLgKOiZIALhInYRztj3WfUScPEUURuNbpkpXPjJ7+cUDb+vb3hLXOZ/9oGmDanb071tFB6qHEFGPaOCAXAwggFsMA4GA1UdDwEB/wQEAwIAgDCCAVgGCisGAQQB1nkCAREBAQAEggFFMIIBQQIBAwoBAQIBKQoBAQQg5PdENrEy/qA83J1g9S/sNRgWk2jEP7XcxTeL1OnbicQEADB3v4U9CAIGAZ6zlWkwv4VFZwRlMGMxPTAbBBZjb20uZ29vZ2xlLmFuZHJvaWQuZ3NmAgEiMB4EFmNvbS5nb29nbGUuYW5kcm9pZC5nbXMCBA+eRrUxIgQg8P1sW0EPJcslw7UzRsiXL64w+O50Ed+RBICtay1g24MwgZWhBTEDAgECogMCAQOjBAICAQClBTEDAgEEqgMCAQG/g3gDAgEDv4N5AwIBCr+FPgMCAQC/hUBMMEoEIKYU4CcUa00TICoOSLUeRawNqsWxi4oQz4Mh4hCAk4z+AQH/CgEABCAtDIeecTRGo7jpxGHABTqkluIgRVVZIcDf5RXV9rnym7+FQQUCAwIi4L+FQgUCAwMXazALBgkqhkiG9w0BAQsDggGBABBp2lD6ayRxjJdroWD6qrvNEQvDWsVONCiXolivI5W3U1oPf1DRVk4a8eupBSbqg6u45SHKnE5MjbMEysR+zJsvZqZx6/a860FJqEc8PvgrQny5UmGUIuq7mNP+N3fsVI8hS2rzXc0DtQLDLCom5j1GEMUPimI+gWJXyAy5d5y8pmutX7AYk45a44o8zlWNWjEzyo80SxET1XQz0kPCAgw5SB/nRZ05nmY7KYAaWf5TRXda8iLmRNcSw+W7AFzl8s3DKrRk5wIvNNAu0ixg6fcTGoj7lDfYpqKdQ2UDmO6A50acRvTvLTopRPGOl4ZcgyDi1AU9F+sI9YGqoWmNw7KxSdaKvnuKT71MJUpWS0iG9dq+z1QrFBaRq5CXXRmdOr4IbI0t0oHU3v/hfmvsL5kxE/p8Zi8id0L9PqQCWAFTNNLpsPV31Z6MSPHX2uqjSxWJ5TbsaY/AytS18dsPEhc9HDy4Zkac4UE3efs3DGRn/9gJQaTOJIZQu6NJ0ALjiQ=="
        )

        with self.assertRaises(ValueError):
            x509.load_der_x509_certificate(cert_bytes)

        cert = asn1.decode_der(Certificate, cert_bytes)
        extensions = cert.tbsCertificate.extensions or []
        ext_key_description = next(
            ext
            for ext in extensions
            if ext.extnID == x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
        )
        assert ext_key_description.critical is False

        key_description = asn1.decode_der(KeyDescription, ext_key_description.extnValue)
        assert key_description.attestationVersion == 3
        assert key_description.teeEnforced.origin == KeyOrigin.GENERATED
        assert key_description.teeEnforced.purpose is not None
        assert key_description.teeEnforced.purpose.as_list() == [KeyPurpose.SIGN]
        assert key_description.teeEnforced.allApplications is None
        assert key_description.softwareEnforced.allApplications is None
