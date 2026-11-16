import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import com.pulsatrix.csc.iso15118.v2g.exi.ExiFragmentEncoder;
import com.pulsatrix.csc.iso15118.v2g.jaxb.datatypes.CertificateChainType;
import com.pulsatrix.csc.iso15118.v2g.jaxb.datatypes.ListOfRootCertificateIDsType;
import com.pulsatrix.csc.iso15118.v2g.jaxb.datatypes.SubCertificatesType;
import com.pulsatrix.csc.iso15118.v2g.jaxb.msgbody.CertificateUpdateReqType;
import com.pulsatrix.csc.iso15118.v2g.jaxb.msgbody.ObjectFactory;
import com.pulsatrix.csc.iso15118.v2g.jaxb.xmldsig.X509IssuerSerialType;

// Run against local-controller b79e77620, not the josev codec.
public class GenerateUpdateFragment {
    public static void main(String[] args) throws Exception {
        var chain = new CertificateChainType();
        chain.setCertificate("leaf".getBytes(StandardCharsets.US_ASCII));
        var subs = new SubCertificatesType();
        subs.getCertificate().add("sub2".getBytes(StandardCharsets.US_ASCII));
        subs.getCertificate().add("sub1".getBytes(StandardCharsets.US_ASCII));
        chain.setSubCertificates(subs);
        var root = new X509IssuerSerialType();
        root.setX509IssuerName("CN=fixture-root");
        root.setX509SerialNumber(BigInteger.ONE);
        var roots = new ListOfRootCertificateIDsType();
        roots.getRootCertificateID().add(root);
        var request = new CertificateUpdateReqType();
        request.setId("update");
        request.setContractSignatureCertChain(chain);
        request.setEMAID("DE8AA1A2B3C4D59"); // Placeholder, not a contract identity.
        request.setListOfRootCertificateIDs(roots);
        var element = new ObjectFactory().createCertificateUpdateReq(request);
        System.out.println(HexFormat.of().formatHex(ExiFragmentEncoder.iso2Message().encode(element)));
    }
}
