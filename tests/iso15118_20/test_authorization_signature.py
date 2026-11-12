# Copyright (c) 2026 pulsatrix gmbh, Apache-2.0 (DEV-3989).
"""Real-codec signature vectors; test keys are generated in memory only."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.enums import AuthEnum, Namespace
from iso15118.shared.messages.iso15118_20.common_messages import (
    AuthorizationReq,
    ContractCertificateChain,
    PnCAuthReqParams,
    SubCertificates,
)
from iso15118.shared.messages.iso15118_20.common_types import MessageHeader
from iso15118.shared.security import create_signature


def authorization_vector():
    """Return full EXI request and its test key, without writing private material."""
    EXI().get_exi_codec()
    now = datetime.now(timezone.utc)
    keys = [ec.generate_private_key(ec.SECP521R1()) for _ in range(4)]
    names = [
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        for name in ("Test MO Root", "Test MO Sub1", "Test MO Sub2", "DE8AA1A2B3C4D59")
    ]
    certificates = []
    for i in range(4):
        issuer = max(0, i - 1)
        cert = (
            x509.CertificateBuilder()
            .subject_name(names[i])
            .issuer_name(names[issuer])
            .public_key(keys[i].public_key())
            .serial_number(i + 1)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=14))
            .add_extension(
                x509.BasicConstraints(ca=i < 3, path_length=2 - i if i < 3 else None),
                True,
            )
            .sign(keys[issuer], hashes.SHA512())
        )
        certificates.append(cert.public_bytes(serialization.Encoding.DER))
    params = PnCAuthReqParams(
        id="id1",
        gen_challenge=bytes(range(16)),
        contract_cert_chain=ContractCertificateChain(
            certificate=certificates[3],
            sub_certificates=SubCertificates(
                certificates=[certificates[2], certificates[1]]
            ),
        ),
    )
    fragment = EXI().to_exi(params, Namespace.ISO_V20_COMMON_MSG)
    signature = create_signature([("id1", fragment)], keys[3], iso20=True)
    request = AuthorizationReq(
        header=MessageHeader(
            session_id="0102030405060708", timestamp=1, signature=signature
        ),
        selected_auth_service=AuthEnum.PNC,
        pnc_params=params,
    )
    return EXI().to_exi(request, Namespace.ISO_V20_COMMON_MSG), keys[3]


def test_iso20_authorization_uses_sha512_and_fixed_width_p521():
    encoded, key = authorization_vector()
    request = EXI().from_exi(encoded, Namespace.ISO_V20_COMMON_MSG)
    signature = request.header.signature
    assert signature.signed_info.signature_method.algorithm.endswith("#ecdsa-sha512")
    reference = signature.signed_info.reference[0]
    assert reference.digest_method.algorithm.endswith("#sha512")
    assert len(reference.digest_value) == 64
    raw = signature.signature_value.value
    assert len(raw) == 132
    key.public_key().verify(
        encode_dss_signature(
            int.from_bytes(raw[:66], "big"), int.from_bytes(raw[66:], "big")
        ),
        EXI().to_exi(signature.signed_info, Namespace.XML_DSIG),
        ec.ECDSA(hashes.SHA512()),
    )


def test_iso20_rejects_a_p256_key():
    with pytest.raises(ValueError, match="secp521r1"):
        create_signature(
            [("id1", b"test fragment")],
            ec.generate_private_key(ec.SECP256R1()),
            iso20=True,
        )


def test_encoded_signed_info_preserves_algorithms():
    encoded, _ = authorization_vector()
    request = EXI().from_exi(encoded, Namespace.ISO_V20_COMMON_MSG)
    info = request.header.signature.signed_info
    encoded_info = EXI().to_exi(info, Namespace.XML_DSIG)
    decoded = json.loads(
        EXI().get_exi_codec().decode(encoded_info, Namespace.XML_DSIG)
    )["SignedInfo"]
    assert decoded["SignatureMethod"]["Algorithm"] == info.signature_method.algorithm
    assert (
        decoded["Reference"][0]["DigestMethod"]["Algorithm"]
        == info.reference[0].digest_method.algorithm
    )
    assert len(encoded_info) == 241


def test_default_iso2_profile_is_unchanged():
    EXI().get_exi_codec()
    signature = create_signature(
        [("id1", b"test fragment")], ec.generate_private_key(ec.SECP256R1())
    )
    assert signature.signed_info.signature_method.algorithm.endswith("#ecdsa-sha256")
    assert len(signature.signed_info.reference[0].digest_value) == 32
    assert len(signature.signature_value.value) == 64
