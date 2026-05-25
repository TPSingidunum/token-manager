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

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class TokenService {
    private AppConfig appConfig;
    private List<Token> tokens;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public TokenService(AppConfig appConfig) {
        this.appConfig = appConfig;
        this.tokens = new ArrayList<>();
        loadLocalTokens();
   }

    public void listAllTokens() {
        for (Token token : tokens) {
            System.out.println(token.toString());
        }
    }

    public Optional<Token> getTokenByKeyId(String keyId) {
        return tokens.stream().filter(token -> token.getKeyId().equals(keyId)).findFirst();
    }

    public List<Token> getTokens() {
        return tokens;
    }

    private void loadLocalTokens() {
        Path localTokenLocation = Path.of(appConfig.getProperty("storage.key.path"));

        try (var dirs = Files.list(localTokenLocation)) {
            dirs.filter(Files::isDirectory).forEach(this::load);

        } catch (IOException e) {
            System.out.println("Error while reading local tokens: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    // @NotNull
    private void load(Path path) {
        Path certPath = path.resolve("cert.pem");
        Path keyPath = path.resolve("key.enc");

        if (Files.isReadable(certPath) && Files.isReadable(keyPath)) {
            X509Certificate cert = readCertificatePem(certPath);
            String name = getCommonName(cert);
            String keyId = path.getFileName().toString();
            Token token = new Token(keyId, name, Token.TOKEN_TYPE.LOCAL, certPath, keyPath);
            tokens.add(token);
        } else {
            System.out.println("Error while reading local tokens: " + path);
        }
    }

    public Token generateLocalToken(String name, String pin) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, IOException, NoSuchProviderException {
        String keyId = UUID.randomUUID().toString();
        Path tokenLocation = Path.of(appConfig.getProperty("storage.key.path")).resolve(keyId);
        Files.createDirectories(tokenLocation);

        Path certPath = tokenLocation.resolve("cert.pem");
        Path keyPath = tokenLocation.resolve("key.enc");

        Token token = new Token(keyId, name, Token.TOKEN_TYPE.LOCAL, certPath, keyPath);

        // tokens / KeyID / certs
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(4096);
        KeyPair tokenKP = kpg.generateKeyPair();

        X509Certificate tokenCert = generateCertificate(tokenKP, name);
        writePem(certPath, tokenCert);

        byte[] encryptedKey = encryptPrivateKey(tokenKP.getPrivate(), pin);
        Files.write(keyPath, encryptedKey);

        System.out.println("Token with params:  " + name + ". Has been successfully created");

        return token;
    }

    private byte[] encryptPrivateKey(PrivateKey privateKey, String pin) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] pinBytes = digest.digest(pin.getBytes(StandardCharsets.UTF_8));

            byte[] IV = Arrays.copyOf(pinBytes, 16);
            SecretKeySpec skc = new SecretKeySpec(Arrays.copyOfRange(pinBytes, 16, 32), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skc, new IvParameterSpec(IV));

            return cipher.doFinal(privateKey.getEncoded());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public PrivateKey decryptPrivateKey(Token token, String pin) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] pinBytes = digest.digest(pin.getBytes(StandardCharsets.UTF_8));

            byte[] IV = Arrays.copyOf(pinBytes, 16);
            SecretKeySpec skc = new SecretKeySpec(Arrays.copyOfRange(pinBytes, 16, 32), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skc, new IvParameterSpec(IV));

            byte[] encodedKey = Files.readAllBytes(token.getKeyPath());
            byte[] decryptedKey =  cipher.doFinal(encodedKey);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePrivate(keySpec);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException |
                 InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public SecretKey decryptEnvelopeKey(byte[] envelopeKeyBytes, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedEnvelopeKeyBytes = cipher.doFinal(envelopeKeyBytes);
            System.out.println("Decrypted envelope key: " + decryptedEnvelopeKeyBytes.length);
            return new SecretKeySpec(decryptedEnvelopeKeyBytes, "AES");
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

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

    public X509Certificate readCertificatePem(Path target) {
        try(FileInputStream fis = new FileInputStream(target.toFile())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

            return (X509Certificate) cf.generateCertificate(fis);
        } catch (IOException | CertificateException | NoSuchProviderException e) {
            System.out.println("Error while reading certificate: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public String getCommonName(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();

        try {
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    return rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }

        return null;
    }

    public String getPublicKeyPemByKeyId(String keyId) {
        Optional<Token> exists = tokens.stream()
                .filter(t -> t.getKeyId().equals(keyId))
                .findFirst();

        if (exists.isEmpty()) {
            System.out.println("Token with params:  " + keyId + " not found");
            return null;
        }

        X509Certificate cert = readCertificatePem(exists.get().getCertificatePath());
        PublicKey publicKey = cert.getPublicKey();
        StringWriter sw = new StringWriter();

        try(JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(publicKey);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return sw.toString();
    }
}
