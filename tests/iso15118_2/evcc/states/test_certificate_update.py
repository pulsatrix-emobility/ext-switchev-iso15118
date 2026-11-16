"""DEV-4022: generated PKI, real EXI and V2GTP, no credential payload logging.

Covers ISO 15118-2 certificate update behavior in the bench EV fixture.
"""

import logging
import secrets
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from iso15118.evcc import EVCCConfig
from iso15118.evcc.controller import simulator
from iso15118.evcc.controller.simulator import SimEVController
from iso15118.evcc.states.iso15118_2_states import (
    CertificateInstallation,
    CertificateUpdate,
    PaymentDetails,
    PaymentServiceSelection,
    ServiceDetail,
    ServiceDiscovery,
)
from iso15118.shared import settings, exi_codec
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.datatypes import SelectedService
from iso15118.shared.messages.enums import AuthEnum, Namespace, Protocol
from iso15118.shared.messages.iso15118_2 import body as b, datatypes as d
from iso15118.shared.messages.iso15118_2.header import MessageHeader
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage
from iso15118.shared.security import (
    CertPath,
    KeyPath,
    KeyPasswordPath,
    KeyEncoding,
    create_signature,
    encrypt_priv_key,
    load_priv_key,
)
from iso15118.shared.states import Terminate

NS = Namespace.ISO_V2_MSG_DEF
SESSION = "0102030405060708"


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def issue(
    key, subject, issuer_cert, issuer_key, ca, path_length, now, expiry, agreement=False
):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(expiry)
        .add_extension(x509.BasicConstraints(ca, path_length), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(not ca, False, False, False, agreement, ca, ca, False, False),
            True,
        )
    )
    if issuer_cert:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            False,
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def chain(domain, name, now):
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
    certs = []
    for i, key in enumerate(keys):
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, name if i == 3 else f"Test {domain} {i}"
                ),
                x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain),
            ]
        )
        certs.append(
            issue(
                key,
                subject,
                certs[-1] if certs else None,
                keys[max(0, i - 1)],
                i < 3,
                2 - i if 0 < i < 3 else None,
                now,
                now + timedelta(days=14),
                i == 3 and domain != "CPS",
            )
        )
    return keys, certs


def cert_chain(certs, identifier=None):
    return d.CertificateChain(
        id=identifier,
        certificate=der(certs[3]),
        sub_certificates=d.SubCertificates(certificates=[der(certs[2]), der(certs[1])]),
    )


def message(body, signature=None):
    return V2GMessage(
        header=MessageHeader(session_id=SESSION, signature=signature), body=body
    )


@pytest_asyncio.fixture
async def material(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PKI_Path", str(tmp_path))
    monkeypatch.setattr(exi_codec, "MESSAGE_LOG_JSON", False)
    monkeypatch.setattr(exi_codec, "MESSAGE_LOG_EXI", False)
    monkeypatch.setattr(
        logging.getLogger("iso15118.shared.exi_codec"), "disabled", True
    )
    EXI().set_exi_codec(EXI().get_exi_codec())
    now = datetime.utcnow().replace(microsecond=0)
    monkeypatch.setattr(simulator, "datetime", SimpleNamespace(utcnow=lambda: now))
    emaid = "DE" + secrets.token_hex(6).upper()
    keys, certs = chain("MO", emaid, now)
    cps_keys, cps = chain("CPS", "Test CPS", now)
    oem_keys, oem = chain("OEM", "DE" + secrets.token_hex(8).upper(), now)
    old_key = ec.generate_private_key(ec.SECP256R1())
    old = issue(
        old_key,
        certs[3].subject,
        certs[2],
        keys[2],
        False,
        None,
        now,
        now + timedelta(hours=23),
        True,
    )
    for folder in ("ca/v2g", "ca/mo", "ca/oem", "client/mo", "client/oem"):
        (tmp_path / folder).mkdir(parents=True, exist_ok=True)
    (tmp_path / CertPath.V2G_ROOT_DER.value).write_bytes(der(cps[0]))
    (tmp_path / CertPath.OEM_LEAF_DER.value).write_bytes(der(oem[3]))
    password = secrets.token_urlsafe(24).encode()
    (tmp_path / KeyPath.OEM_LEAF_PEM.value).write_bytes(
        oem_keys[3].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password),
        )
    )
    (tmp_path / KeyPasswordPath.OEM_LEAF_KEY_PASSWORD.value).write_bytes(password)
    controller = SimEVController(EVCCConfig())
    await controller.store_contract_cert_and_priv_key(
        cert_chain([*certs[:3], old]),
        old_key.private_numbers().private_value.to_bytes(32, "big"),
    )
    return SimpleNamespace(
        path=tmp_path,
        now=now,
        keys=keys,
        certs=certs,
        cps=cps,
        cps_keys=cps_keys,
        old=old,
        old_key=old_key,
        controller=controller,
        emaid=emaid,
    )


def session(material, offered=2):
    return SimpleNamespace(
        ev_controller=material.controller,
        protocol=Protocol.ISO_15118_2,
        selected_auth_option=AuthEnum.PNC_V2,
        session_id=SESSION,
        is_tls=True,
        writer=Mock(),
        stop_reason=None,
        selected_services=[
            SelectedService(
                service_id=d.ServiceID.CERTIFICATE, parameter_set_id=offered
            )
        ],
        service_details_to_request=[],
    )


def response(material, change=None):
    recipient = material.old if change != "wrong_key" else material.certs[3]
    dh, encrypted = encrypt_priv_key(der(recipient), material.keys[3])
    response = b.CertificateUpdateRes(
        response_code="OK",
        cps_cert_chain=cert_chain(material.cps),
        contract_cert_chain=cert_chain(material.certs, "chain"),
        encrypted_private_key=d.EncryptedPrivateKey(id="key", value=encrypted),
        dh_public_key=d.DHPublicKey(id="dh", value=dh),
        emaid=d.EMAID(id="contract", value=material.emaid),
    )
    elements = [
        response.contract_cert_chain,
        response.encrypted_private_key,
        response.dh_public_key,
        response.emaid,
    ]
    if change == "reordered":
        elements.reverse()
    signature = create_signature(
        [(v.id, EXI().to_exi(v, NS)) for v in elements], material.cps_keys[3]
    )
    return message(b.Body(certificate_update_res=response), signature)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hours,expected", [(23, True), (24, True), (24.01, False), (0, False), (-1, False)]
)
async def test_renewal_window_is_simulator_policy(material, hours, expected):
    cert = issue(
        material.old_key,
        material.old.subject,
        material.certs[2],
        material.keys[2],
        False,
        None,
        material.now,
        material.now + timedelta(hours=hours),
        True,
    )
    (material.path / CertPath.CONTRACT_LEAF_DER.value).write_bytes(der(cert))
    assert await material.controller.is_cert_update_needed() is expected


@pytest.mark.asyncio
async def test_explicit_install_and_missing_contract_prevent_update(material):
    material.controller.config.is_cert_install_needed = True
    assert not await material.controller.is_cert_update_needed()
    material.controller.config.is_cert_install_needed = False
    (material.path / CertPath.CONTRACT_LEAF_DER.value).unlink()
    assert not await material.controller.is_cert_update_needed()
    assert await material.controller.is_cert_install_needed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "install,offered,selected",
    [(False, [1, 2], 2), (True, [1, 2], 1), (False, [1], None)],
)
async def test_discovery_and_parameter_selection(material, install, offered, selected):
    material.controller.config.is_cert_install_needed = install
    comm = session(material)
    comm.selected_services = []
    await ServiceDiscovery(comm).select_services(
        Mock(
            charge_service=Mock(service_id=d.ServiceID.CHARGING),
            service_list=Mock(
                services=[
                    Mock(
                        service_id=d.ServiceID.CERTIFICATE,
                        service_category=d.ServiceCategory.CERTIFICATE,
                    )
                ]
            ),
        )
    )
    assert comm.service_details_to_request == [d.ServiceID.CERTIFICATE]
    comm.service_details_to_request = []
    state = ServiceDetail(comm)
    await state.process_message(
        message(
            b.Body(
                service_detail_res=b.ServiceDetailRes(
                    response_code="OK",
                    service_id=d.ServiceID.CERTIFICATE,
                    service_parameter_list=d.ServiceParameterList(
                        parameter_set=[
                            d.ParameterSet(parameter_set_id=v, parameters=[])
                            for v in offered
                        ]
                    ),
                )
            )
        )
    )
    assert [
        s.parameter_set_id
        for s in comm.selected_services
        if s.service_id == d.ServiceID.CERTIFICATE
    ] == ([selected] if selected else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [None, "reordered"])
async def test_update_roundtrip_real_exi_and_v2gtp(material, change):
    comm = session(material)
    await PaymentServiceSelection(comm).process_message(
        message(
            b.Body(
                payment_service_selection_res=b.PaymentServiceSelectionRes(
                    response_code="OK"
                )
            )
        )
    )
    state = comm.current_state
    assert isinstance(state, CertificateUpdate)
    wire = state.next_v2gtp_msg.to_bytes()
    assert int.from_bytes(wire[2:4], "big") == 0x8001
    request = EXI().from_exi(wire[8:], NS)
    body = request.body.certificate_update_req
    assert isinstance(body.emaid, str)
    matches = body.emaid == material.emaid
    assert matches
    raw = request.header.signature.signature_value.value
    material.old_key.public_key().verify(
        encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        ),
        EXI().to_exi(request.header.signature.signed_info, Namespace.XML_DSIG),
        ec.ECDSA(hashes.SHA256()),
    )
    await state.process_message(
        EXI().from_exi(EXI().to_exi(response(material, change), NS), NS)
    )
    assert state.next_state is PaymentDetails
    assert int.from_bytes(state.next_v2gtp_msg.to_bytes()[2:4], "big") == 0x8001
    key = load_priv_key(
        str(material.path / KeyPath.CONTRACT_LEAF_PEM.value),
        KeyEncoding.PEM,
        str(material.path / KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD.value),
    )
    matches = key.private_numbers() == material.keys[3].private_numbers()
    assert matches
    assert (
        key.public_key().public_numbers()
        != material.old_key.public_key().public_numbers()
    )
    assert not await material.controller.is_cert_update_needed()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "install,tls,parameter,expected",
    [
        (True, True, 1, CertificateInstallation),
        (False, False, 2, PaymentDetails),
        (False, True, 1, PaymentDetails),
    ],
)
async def test_request_gates(material, install, tls, parameter, expected):
    material.controller.config.is_cert_install_needed = install
    comm = session(material, parameter)
    comm.is_tls = tls
    state = PaymentServiceSelection(comm)
    await state.process_message(
        message(
            b.Body(
                payment_service_selection_res=b.PaymentServiceSelectionRes(
                    response_code="OK"
                )
            )
        )
    )
    assert state.next_state is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "signature",
        "bad_signature",
        "missing_chain",
        "extra_reference",
        "duplicate_reference",
        "wrong_key",
        "root",
        "domain",
        "expired_cps",
        "failed",
    ],
)
async def test_reject_without_replacing_contract(material, change):
    comm = session(material)
    state = CertificateUpdate(comm)
    res = response(material, change)
    if change == "signature":
        res.header.signature = None
    elif change == "bad_signature":
        res.header.signature.signature_value.value = bytes(64)
    elif change == "missing_chain":
        res.body.certificate_update_res.cps_cert_chain.sub_certificates = None
    elif change == "extra_reference":
        res.header.signature.signed_info.reference.append(
            res.header.signature.signed_info.reference[0]
        )
    elif change == "duplicate_reference":
        res.header.signature.signed_info.reference[1] = (
            res.header.signature.signed_info.reference[0]
        )
    elif change == "root":
        (material.path / CertPath.V2G_ROOT_DER.value).write_bytes(
            der(material.certs[0])
        )
    elif change in ("domain", "expired_cps"):
        subject = (
            material.cps[3].subject if change == "expired_cps" else material.old.subject
        )
        replacement = issue(
            material.cps_keys[3],
            subject,
            material.cps[2],
            material.cps_keys[2],
            False,
            None,
            material.now,
            material.now + timedelta(days=-1 if change == "expired_cps" else 1),
        )
        res.body.certificate_update_res.cps_cert_chain.certificate = der(replacement)
    elif change == "failed":
        res.header.signature = None
        res.body.certificate_update_res.response_code = "FAILED_NoCertificateAvailable"
        res.body.certificate_update_res.retry_counter = -1
    before = {p: p.read_bytes() for p in (material.path / "client/mo").iterdir()}
    await state.process_message(res)
    assert state.next_state is Terminate
    unchanged = before == {p: p.read_bytes() for p in before}
    assert unchanged
    if change == "failed":
        assert state.retry_counter == -1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["critical", "foreign_signer", "authority"])
async def test_reject_invalid_cps_path_without_replacing_contract(material, change):
    # Keep the issuer name, public key, and (except in the AKI case) identifiers.
    # The foreign signature must fail even when all names and identifiers match.
    index = 2 if change == "foreign_signer" else 3
    original = material.cps[index]
    builder = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.issuer)
        .public_key(original.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(original.not_valid_before)
        .not_valid_after(original.not_valid_after)
    )
    for ext in original.extensions:
        value = ext.value
        if change == "authority" and isinstance(value, x509.AuthorityKeyIdentifier):
            value = x509.AuthorityKeyIdentifier(bytes(20), None, None)
        builder = builder.add_extension(value, ext.critical)
    if change == "critical":
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00"),
            True,
        )
    signer = (
        ec.generate_private_key(ec.SECP256R1())
        if change == "foreign_signer"
        else material.cps_keys[index - 1]
    )
    material.cps[index] = builder.sign(signer, hashes.SHA256())
    state = CertificateUpdate(session(material))
    before = {p: p.read_bytes() for p in (material.path / "client/mo").iterdir()}
    await state.process_message(response(material))
    assert state.next_state is Terminate
    unchanged = before == {p: p.read_bytes() for p in before}
    assert unchanged


@pytest.mark.asyncio
async def test_contract_storage_uses_enum_values_and_removes_stale_intermediate(
    material,
):
    # Literal paths catch Python 3.11 pathlib stringifying str/Enum members by name.
    files = (
        "client/mo/MO_LEAF.der",
        "client/mo/MO_LEAF.key",
        "client/mo/MO_LEAF_PASSWORD.txt",
        "ca/mo/MO_SUB_CA2.der",
        "ca/mo/MO_SUB_CA1.der",
    )
    assert all((material.path / path).is_file() for path in files)
    assert await material.controller.is_cert_update_needed()
    replacement = cert_chain(material.certs)
    replacement.sub_certificates.certificates = [der(material.certs[2])]
    await material.controller.store_contract_cert_and_priv_key(
        replacement,
        material.keys[3].private_numbers().private_value.to_bytes(32, "big"),
    )
    assert not (material.path / "ca/mo/MO_SUB_CA1.der").exists()
    assert all((material.path / path).is_file() for path in files[:-1])
    assert not list(material.path.glob("CertPath.*"))
    assert not list(material.path.glob("KeyPath.*"))
    assert not list(material.path.glob("KeyPasswordPath.*"))
