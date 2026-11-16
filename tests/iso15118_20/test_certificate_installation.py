"""DEV-4022: run-generated credentials and real EXI, without payload logging.

Inventory links (exercises; not a complete conformance claim):
https://github.com/pulsatrix-emobility/compliance-inventory
iso15118-20:V2G20-1078, iso15118-20:V2G20-2648,
iso15118-20:V2G20-2535, iso15118-20:V2G20-2505,
iso15118-20:V2G20-2678, iso15118-20:V2G20-2507,
iso15118-20:V2G20-1578, iso15118-20:V2G20-1581.
"""

import logging
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.x509.oid import NameOID

from iso15118.evcc import EVCCConfig
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.states.iso15118_20_states import (
    Authorization,
    AuthorizationSetup,
    CertificateInstallation,
)
from iso15118.shared import exi_codec, settings
from iso15118.shared.exceptions import DecryptionError
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.enums import AuthEnum, Namespace, Protocol
from iso15118.shared.messages.iso15118_20 import common_messages as m
from iso15118.shared.messages.iso15118_20.common_types import MessageHeader
from iso15118.shared.security import (
    CertPath,
    KeyPath,
    KeyPasswordPath,
    create_signature,
    decrypt_priv_key_iso20,
    verify_signature,
    load_priv_key,
    KeyEncoding,
)
from iso15118.shared.states import Terminate

NS = Namespace.ISO_V20_COMMON_MSG


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def chain(domain, cn, curve=None):
    curve = curve or ec.SECP521R1()
    keys = [ec.generate_private_key(curve) for _ in range(4)]
    certs = []
    now = datetime.utcnow()
    for i, key in enumerate(keys):
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, cn if i == 3 else f"Test {domain} {i}"
                ),
                x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain),
            ]
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(certs[-1].subject if certs else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(
                x509.BasicConstraints(i < 3, 2 - i if 0 < i < 3 else None), True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
            )
            .add_extension(
                x509.KeyUsage(
                    i == 3,
                    False,
                    False,
                    False,
                    i == 3 and domain == "OEM",
                    i < 3,
                    False,
                    False,
                    False,
                ),
                True,
            )
        )
        if certs:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    keys[i - 1].public_key()
                ),
                False,
            )
        certs.append(
            builder.sign(
                keys[max(0, i - 1)],
                hashes.SHA512() if curve.key_size == 521 else hashes.SHA256(),
            )
        )
    return keys, certs


def chain_dict(certs):
    return dict(
        certificate=der(certs[3]),
        sub_certificates=m.SubCertificates(certificates=[der(certs[2]), der(certs[1])]),
    )


@pytest.fixture
def material(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PKI_Path", str(tmp_path))
    monkeypatch.setattr(exi_codec, "MESSAGE_LOG_JSON", False)
    monkeypatch.setattr(exi_codec, "MESSAGE_LOG_EXI", False)
    # Existing codec diagnostics can include payloads even with JSON logging disabled.
    logger = logging.getLogger("iso15118.shared.exi_codec")
    monkeypatch.setattr(logger, "disabled", True)
    EXI().set_exi_codec(EXI().get_exi_codec())
    cps_keys, cps = chain("CPS", "Test CPS")
    oem_keys, oem = chain("OEM", "DE" + secrets.token_hex(8).upper())
    mo_keys, mo = chain("MO", "DE" + secrets.token_hex(6).upper())
    password = secrets.token_urlsafe(24).encode()
    files = {
        CertPath.V2G_ROOT_DER: der(cps[0]),
        CertPath.OEM_LEAF_DER: der(oem[3]),
        CertPath.OEM_SUB_CA1_DER: der(oem[1]),
        CertPath.OEM_SUB_CA2_DER: der(oem[2]),
        KeyPasswordPath.OEM_LEAF_KEY_PASSWORD: password,
        KeyPath.OEM_LEAF_PEM: oem_keys[3].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        ),
    }
    for relative, content in files.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    for folder in ("client/mo", "ca/mo"):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        path=tmp_path,
        cps=cps,
        cps_keys=cps_keys,
        oem=oem,
        oem_keys=oem_keys,
        mo=mo,
        mo_keys=mo_keys,
    )


def response(material, scalar=None, aad_suffix=b"", short_ski=False):
    """Independent producer matching the test CPS's P-521 wire construction."""
    ephemeral = ec.generate_private_key(ec.SECP521R1())
    secret = ephemeral.exchange(ec.ECDH(), material.oem_keys[3].public_key())
    symmetric = ConcatKDFHash(
        algorithm=hashes.SHA512(), length=32, otherinfo=b"\x01UV"
    ).derive(secret)
    contract = material.mo[3]
    ski = contract.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest
    if short_ski:
        ski = bytes([(ski[-8] & 15) | 64]) + ski[-7:]
        builder = (
            x509.CertificateBuilder()
            .subject_name(contract.subject)
            .issuer_name(contract.issuer)
            .public_key(contract.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(contract.not_valid_before)
            .not_valid_after(contract.not_valid_after)
        )
        for ext in contract.extensions:
            builder = builder.add_extension(
                (
                    x509.SubjectKeyIdentifier(ski)
                    if isinstance(ext.value, x509.SubjectKeyIdentifier)
                    else ext.value
                ),
                ext.critical,
            )
        contract = builder.sign(material.mo_keys[2], hashes.SHA512())
    pcid = material.oem[3].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    aad = pcid.encode() + ski.hex().upper().encode() + aad_suffix
    iv = secrets.token_bytes(12)
    scalar = (
        scalar
        if scalar is not None
        else material.mo_keys[3].private_numbers().private_value.to_bytes(66, "big")
    )
    encrypted = iv + AESGCM(symmetric).encrypt(iv, scalar, aad)
    data = m.SignedInstallationData(
        id="data",
        contract_cert_chain=m.ContractCertificateChain(
            **{**chain_dict(material.mo), "certificate": der(contract)}
        ),
        ecdh_curve="SECP521",
        dh_public_key=ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        ),
        secp521_encrypted_private_key=encrypted,
    )
    signature = create_signature(
        [(data.id, EXI().to_exi(data, NS))], material.cps_keys[3], iso20=True
    )
    return m.CertificateInstallationRes(
        header=MessageHeader(
            session_id="0102030405060708", timestamp=1, signature=signature
        ),
        response_code="OK",
        evse_processing="Finished",
        cps_certificate_chain=m.CertificateChain(**chain_dict(material.cps)),
        signed_installation_data=data,
        remaining_contract_cert_chains=0,
    )


def verify(res, material):
    data = res.signed_installation_data
    return verify_signature(
        res.header.signature,
        [(data.id, EXI().to_exi(data, NS))],
        res.cps_certificate_chain.certificate,
        (
            res.cps_certificate_chain.sub_certificates.certificates
            if res.cps_certificate_chain.sub_certificates
            else None
        ),
        der(material.cps[0]),
        iso20=True,
    )


def decrypt(res, material):
    return decrypt_priv_key_iso20(
        res.signed_installation_data, material.oem_keys[3], der(material.oem[3])
    )


@pytest.mark.parametrize("short_ski", [False, True])
def test_real_exi_response_signature_and_decryption(material, short_ski):
    res = EXI().from_exi(EXI().to_exi(response(material, short_ski=short_ski), NS), NS)
    assert verify(res, material)
    matches = (
        int.from_bytes(decrypt(res, material), "big")
        == material.mo_keys[3].private_numbers().private_value
    )
    assert matches


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "signature",
        "width",
        "digest",
        "method",
        "reference",
        "duplicate",
        "transform",
        "root",
        "chain",
        "tamper",
    ],
)
def test_reject_signature_or_trust(material, change):
    res = response(material)
    signature = res.header.signature
    if change == "missing":
        res.header.signature = None
    elif change == "signature":
        signature.signature_value.value = secrets.token_bytes(132)
    elif change == "width":
        signature.signature_value.value = signature.signature_value.value[1:]
    elif change == "digest":
        signature.signed_info.reference[0].digest_value = bytes(64)
    elif change == "method":
        signature.signed_info.signature_method.algorithm = (
            "http://example.invalid/algorithm"
        )
    elif change == "reference":
        signature.signed_info.reference[0].uri = "#wrong"
    elif change == "duplicate":
        signature.signed_info.reference *= 2
    elif change == "transform":
        signature.signed_info.reference[0].transforms.transform[
            0
        ].algorithm = "http://example.invalid/algorithm"
    elif change == "root":
        material.cps[0] = material.oem[0]
    elif change == "chain":
        res.cps_certificate_chain.sub_certificates = None
    elif change == "tamper":
        res.signed_installation_data.dh_public_key = b"\x04" + bytes(132)
    assert not verify(res, material)


@pytest.mark.parametrize(
    "change",
    ["tag", "aad", "padding", "zero", "order", "mismatch", "point", "curve", "oem"],
)
def test_reject_key_data(material, change):
    scalar = {
        "padding": b"\x80" + bytes(65),
        "zero": bytes(66),
        "order": b"\x01" + b"\xff" * 65,
        "mismatch": (1).to_bytes(66, "big"),
    }.get(change)
    res = response(material, scalar, b"wrong" if change == "aad" else b"")
    data = res.signed_installation_data
    if change == "tag":
        data.secp521_encrypted_private_key = data.secp521_encrypted_private_key[
            :-1
        ] + bytes([data.secp521_encrypted_private_key[-1] ^ 1])
    elif change == "point":
        data.dh_public_key = bytes(133)
    elif change == "curve":
        data.ecdh_curve = "X448"
    elif change == "oem":
        material.oem_keys[3] = ec.generate_private_key(ec.SECP521R1())
    with pytest.raises(DecryptionError):
        decrypt(res, material)


def session(material):
    config = EVCCConfig(isCertInstallNeeded=True)
    controller = SimEVController(config)
    return SimpleNamespace(
        config=config,
        ev_controller=controller,
        session_id="0102030405060708",
        protocol=Protocol.ISO_15118_20_AC,
        ongoing_timer=-1,
        writer=Mock(),
        current_state=None,
    )


def auth_setup():
    return m.AuthorizationSetupRes(
        header=MessageHeader(session_id="0102030405060708", timestamp=1),
        response_code="OK",
        auth_services=[AuthEnum.PNC],
        cert_install_service=True,
        pnc_as_res=m.PnCAuthSetupResParams(gen_challenge=secrets.token_bytes(16)),
    )


@pytest.mark.asyncio
async def test_install_stores_p521_and_authorizes_with_new_key(material):
    comm = session(material)
    setup = AuthorizationSetup(comm)
    setup.create_next_message = Mock()
    advertised = auth_setup()
    await setup.process_message(advertised)
    request = comm.certificate_installation_request
    assert request.header.signature.signed_info.signature_method.algorithm.endswith(
        "ecdsa-sha512"
    )
    # Verify the request with the OEM public key independently of the verifier under test.
    raw = request.header.signature.signature_value.value
    material.oem_keys[3].public_key().verify(
        encode_dss_signature(
            int.from_bytes(raw[:66], "big"), int.from_bytes(raw[66:], "big")
        ),
        EXI().to_exi(request.header.signature.signed_info, Namespace.XML_DSIG),
        ec.ECDSA(hashes.SHA512()),
    )
    state = CertificateInstallation(comm)
    state.create_next_message = Mock()
    res = EXI().from_exi(EXI().to_exi(response(material), NS), NS)
    await state.process_message(res)
    args = state.create_next_message.call_args.args
    assert args[0] is Authorization
    auth = args[1]
    assert auth.pnc_params.gen_challenge == advertised.pnc_as_res.gen_challenge
    matches = auth.pnc_params.contract_cert_chain.certificate == der(material.mo[3])
    assert matches
    private = load_priv_key(
        str(material.path / KeyPath.CONTRACT_LEAF_PEM),
        KeyEncoding.PEM,
        str(material.path / KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD),
    )
    assert private.curve.name == "secp521r1"
    matches = private.private_numbers() == material.mo_keys[3].private_numbers()
    assert matches
    raw = auth.header.signature.signature_value.value
    material.mo_keys[3].public_key().verify(
        encode_dss_signature(
            int.from_bytes(raw[:66], "big"), int.from_bytes(raw[66:], "big")
        ),
        EXI().to_exi(auth.header.signature.signed_info, Namespace.XML_DSIG),
        ec.ECDSA(hashes.SHA512()),
    )
    assert (material.path / KeyPath.CONTRACT_LEAF_PEM).stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["signature", "key", "warning", "failed", "session"])
async def test_failed_install_never_stores_or_continues(material, kind):
    comm = session(material)
    comm.ev_controller.store_contract_cert_and_priv_key = AsyncMock()
    state = CertificateInstallation(comm)
    state.create_next_message = Mock()
    res = response(material, aad_suffix=b"bad" if kind == "key" else b"")
    if kind == "signature":
        res.header.signature = None
    if kind == "warning":
        res.response_code = "WARNING_CertificateExpired"
    if kind == "failed":
        res.response_code = "FAILED"
    if kind == "session":
        res.header.session_id = "1122334455667788"
    await state.process_message(res)
    assert state.next_state is Terminate
    comm.ev_controller.store_contract_cert_and_priv_key.assert_not_called()
    state.create_next_message.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("clock_base", [10.0, 10000.0])
async def test_ongoing_resends_unchanged_request_and_times_out(
    material, monkeypatch, clock_base
):
    comm = session(material)
    setup = AuthorizationSetup(comm)
    setup.create_next_message = Mock()
    await setup.process_message(auth_setup())
    res = response(material)
    res.evse_processing = "Ongoing"
    res.header.signature = None
    state = CertificateInstallation(comm)
    state.create_next_message = Mock()
    monkeypatch.setattr(
        "iso15118.evcc.states.iso15118_20_states.time",
        SimpleNamespace(monotonic=lambda: clock_base),
    )
    await state.process_message(res)
    assert (
        state.create_next_message.call_args.args[1]
        is comm.certificate_installation_request
    )
    started = comm.ongoing_timer
    # Advance the clock, not the saved timestamp: negative values mean inactive.
    clock_base += 61
    await state.process_message(res)
    assert comm.ongoing_timer == started
    assert state.next_state is Terminate


@pytest.mark.asyncio
async def test_storage_validates_before_replacing_existing_files(material):
    controller = SimEVController(EVCCConfig())
    data = response(material).signed_installation_data
    await controller.store_contract_cert_and_priv_key(
        data.contract_cert_chain, decrypt(response(material), material)
    )
    before = {p: p.read_bytes() for p in material.path.rglob("*") if p.is_file()}
    with pytest.raises(ValueError):
        await controller.store_contract_cert_and_priv_key(
            data.contract_cert_chain, (1).to_bytes(66, "big")
        )
    unchanged = before == {p: p.read_bytes() for p in before}
    assert unchanged


@pytest.mark.parametrize(
    "change", ["expired", "domain", "usage", "authority", "critical"]
)
def test_reject_cps_profile_with_valid_certificate_signature(material, change):
    leaf = material.cps[3]
    subject = leaf.subject
    if change == "domain":
        subject = x509.Name(
            [
                (
                    x509.NameAttribute(a.oid, "MO")
                    if a.oid == NameOID.DOMAIN_COMPONENT
                    else a
                )
                for a in subject
            ]
        )
    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(leaf.issuer)
        .public_key(leaf.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(
            now - timedelta(days=1) if change == "expired" else now + timedelta(days=1)
        )
    )
    for ext in leaf.extensions:
        value = ext.value
        if change == "usage" and isinstance(value, x509.KeyUsage):
            value = x509.KeyUsage(
                False, False, False, False, False, False, False, False, False
            )
        if change == "authority" and isinstance(value, x509.AuthorityKeyIdentifier):
            value = x509.AuthorityKeyIdentifier(bytes(20), None, None)
        builder = builder.add_extension(value, ext.critical)
    if change == "critical":
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"),
            True,
        )
    material.cps[3] = builder.sign(material.cps_keys[2], hashes.SHA512())
    assert not verify(response(material), material)


@pytest.mark.asyncio
async def test_storage_preserves_p256_support(material):
    from iso15118.shared.messages.iso15118_2.datatypes import CertificateChain

    keys, certs = chain("MO", "Test contract", ec.SECP256R1())
    controller = SimEVController(EVCCConfig())
    await controller.store_contract_cert_and_priv_key(
        CertificateChain(**chain_dict(certs)),
        keys[3].private_numbers().private_value.to_bytes(32, "big"),
    )
    key = load_priv_key(
        str(material.path / KeyPath.CONTRACT_LEAF_PEM),
        KeyEncoding.PEM,
        str(material.path / KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD),
    )
    matches = key.private_numbers() == keys[3].private_numbers()
    assert matches


@pytest.mark.asyncio
@pytest.mark.parametrize("request_kind", ["initial", "resend"])
async def test_installation_request_uses_common_message_v2gtp_header(
    material, request_kind
):
    """iso15118-20:V2G20-2307: inspect the serialized header, without mocking send construction."""
    comm = session(material)
    state = AuthorizationSetup(comm)
    await state.process_message(auth_setup())
    initial_payload = state.next_v2gtp_msg.payload
    if request_kind == "resend":
        res = response(material)
        res.evse_processing = "Ongoing"
        state = CertificateInstallation(comm)
        await state.process_message(res)
    wire = state.next_v2gtp_msg.to_bytes()
    assert int.from_bytes(wire[2:4], "big") == 0x8002
    unchanged = state.next_v2gtp_msg.payload == initial_payload
    assert unchanged
