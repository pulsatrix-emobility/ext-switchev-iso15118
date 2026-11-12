# Changes Copyright (c) 2026 pulsatrix gmbh, Apache-2.0 (DEV-3989).
import json
import logging
from builtins import Exception

from iso15118.shared.iexi_codec import IEXICodec
from iso15118.shared.settings import JAR_FILE_PATH

logger = logging.getLogger(__name__)


def compare_messages(json_to_encode, decoded_json):
    json_obj = json.loads(json_to_encode)
    decoded_json_obj = json.loads(decoded_json)
    return sorted(json_obj.items()) == sorted(decoded_json_obj.items())


class ExificientEXICodec(IEXICodec):
    def __init__(self):
        from py4j.java_gateway import JavaGateway

        logging.getLogger("py4j").setLevel(logging.CRITICAL)
        self.gateway = JavaGateway.launch_gateway(
            classpath=JAR_FILE_PATH,
            die_on_exit=True,
            javaopts=["--add-opens", "java.base/java.lang=ALL-UNNAMED"],
        )

        self.exi_codec = self.gateway.jvm.com.siemens.ct.exi.main.cmd.EXICodec()

    def encode(self, message: str, namespace: str) -> bytes:
        """
        Calls the Exificient EXI implmentation to encode input json.
        Returns a byte[] for the input message if conversion was successful.
        """
        if namespace == "http://www.w3.org/2000/09/xmldsig#":
            info = json.loads(message).get("SignedInfo", {})
            if (
                info.get("SignatureMethod", {})
                .get("Algorithm", "")
                .endswith("#ecdsa-sha512")
            ):
                return self._encode_signed_info(message, namespace)
        exi = self.exi_codec.encode(message, namespace)

        if exi is None:
            raise Exception(self.exi_codec.get_last_encoding_error())
        return exi

    def _encode_signed_info(self, message: str, namespace: str) -> bytes:
        # The jar's SecurityPayloads.GetSignedInfo hardcodes SHA-256 URIs.
        # Use its JAXB model and signature grammar with the supplied fields.
        j = self.gateway.jvm
        context = j.org.eclipse.persistence.jaxb.JAXBContextFactory.createContext(
            "com.siemens.ct.exi.main.messages.iso15118_2",
            j.java.lang.Thread.currentThread().getContextClassLoader(),
            j.java.util.HashMap(),
        )
        unmarshaller = context.createUnmarshaller()
        unmarshaller.setProperty("eclipselink.media-type", "application/json")
        unmarshaller.setProperty("eclipselink.json.include-root", True)
        element = unmarshaller.unmarshal(j.java.io.StringReader(message))
        element = j.javax.xml.bind.JAXBElement(
            j.javax.xml.namespace.QName(namespace, "SignedInfo"),
            element.getDeclaredType(),
            element.getValue(),
        )
        xml = j.java.io.StringWriter()
        context.createMarshaller().marshal(element, xml)
        factory = j.com.siemens.ct.exi.core.helpers.DefaultEXIFactory.newInstance()
        factory.setGrammars(
            j.com.siemens.ct.exi.main.generatedgrammar.XMLDSIG_Core_Schema_Grammar()
        )
        factory.setFragment(True)
        factory.setValuePartitionCapacity(0)
        factory.setMaximumNumberOfBuiltInElementGrammars(0)
        factory.setMaximumNumberOfBuiltInProductions(0)
        output = j.java.io.ByteArrayOutputStream()
        result = j.com.siemens.ct.exi.main.api.sax.EXIResult(factory)
        result.setOutputStream(output)
        parser = j.javax.xml.parsers.SAXParserFactory.newInstance()
        parser.setNamespaceAware(True)
        reader = parser.newSAXParser().getXMLReader()
        reader.setContentHandler(result.getHandler())
        reader.parse(j.org.xml.sax.InputSource(j.java.io.StringReader(xml.toString())))
        return bytes(output.toByteArray())

    def decode(self, stream: bytes, namespace: str) -> str:
        """
        Calls the EXIficient EXI implementation to decode the input EXI stream.
        Returns a JSON representation of the input EXI stream if the conversion
        was successful.
        """
        decoded_message = self.exi_codec.decode(stream, namespace)

        if decoded_message is None:
            raise Exception(self.exi_codec.get_last_decoding_error())
        return decoded_message

    def get_version(self) -> str:
        """
        Returns the version of the Exificient codec
        """
        return self.exi_codec.get_version()

    def shutdown(self):
        """
        Shutdown the java gateway manually
        """
        self.gateway.shutdown()
