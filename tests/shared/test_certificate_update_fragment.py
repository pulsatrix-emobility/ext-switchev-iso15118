"""Independent LC fragment oracle; dummy byte strings, no certificate/key material."""

from pathlib import Path

from iso15118.shared import exi_codec
from iso15118.shared.exi_codec import EXI
from iso15118.shared.exificient_exi_codec import ExificientEXICodec
from iso15118.shared.messages.enums import Namespace
from iso15118.shared.messages.iso15118_2.body import CertificateUpdateReq
from iso15118.shared.messages.iso15118_2.datatypes import (
    CertificateChain,
    RootCertificateIDList,
    SubCertificates,
)
from iso15118.shared.messages.xmldsig import X509IssuerSerial


def test_certificate_update_fragment_matches_independent_lc_encoder(monkeypatch):
    monkeypatch.setattr(exi_codec, "MESSAGE_LOG_JSON", False)
    monkeypatch.setattr(exi_codec, "MESSAGE_LOG_EXI", False)
    codec = ExificientEXICodec()
    monkeypatch.setattr(EXI(), "exi_codec", codec)
    request = CertificateUpdateReq(
        id="update",
        contract_cert_chain=CertificateChain(
            certificate=b"leaf",
            sub_certificates=SubCertificates(certificates=[b"sub2", b"sub1"]),
        ),
        emaid="DE8AA1A2B3C4D59",  # Placeholder.
        list_of_root_cert_ids=RootCertificateIDList(
            x509_issuer_serials=[
                X509IssuerSerial(
                    x509_issuer_name="CN=fixture-root", x509_serial_number=1
                )
            ]
        ),
    )
    expected = bytes.fromhex(
        (Path(__file__).parent / "fixtures/certificate_update/fragment.hex").read_text()
    )
    try:
        assert EXI().to_exi(request, Namespace.ISO_V2_MSG_DEF) == expected
    finally:
        codec.shutdown()
