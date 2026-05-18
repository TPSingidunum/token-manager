package rs.ac.singidunum.tokenmanager.services;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import rs.ac.singidunum.tokenmanager.config.AppConfig;
import rs.ac.singidunum.tokenmanager.entities.DnProperties;
import rs.ac.singidunum.tokenmanager.entities.Token;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class TokenService {
    private AppConfig appConfig;
    private List<Token> tokens;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public TokenService(AppConfig appConfig) {
        this.appConfig = appConfig;
   }

    public void generateLocalToken(String name) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, NoSuchProviderException {
        String keyId = UUID.randomUUID().toString();
        Path tokenLocation = Path.of(appConfig.getProperty("storage.key.path")).resolve(keyId);
        Files.createDirectories(tokenLocation);

        Path certPath = tokenLocation.resolve("cert.pem");
        Path keyPath = tokenLocation.resolve("key.pem");

        Token token = new Token(keyId, name, Token.TOKEN_TYPE.LOCAL, certPath, keyPath);

        // tokens / KeyID / certs
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(4096);
        KeyPair tokenKP = kpg.generateKeyPair();

        X509Certificate tokenCert = generateCertificate(tokenKP, name);
        writePem(certPath, tokenCert);
        writePem(keyPath, tokenKP.getPrivate());

        System.out.println("Token with params:  " + name + ". Has been successfully created");
    }

    public X509Certificate generateCertificate(KeyPair kp, String name) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException, CertificateException {
        // Parametri za sertifikat
        // Produziti subject sa ostalim parametrima Sertifikata
        DnProperties properties = new DnProperties(name,"Token Manager","EDrive","Belgrade","RS","RS");
        X500Name subject = new X500Name(properties.toX500Principal());
        BigInteger serial = generateSerialNumber();
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plus((Integer.parseInt(appConfig.getProperty(AppConfig.TOKEN_DURATION))), ChronoUnit.DAYS));

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic()
        );

        // Dodavanje privilegija sertifikatu
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(kp.getPublic()));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build((kp.getPrivate()));

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    private BigInteger generateSerialNumber() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return new BigInteger(bytes).abs();
    }

    public void writePem(Path target, Object object) {
        try(JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(target.toFile()))) {
            pw.writeObject(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
