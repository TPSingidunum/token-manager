package com.example.tokenmanager.configs;

import com.example.tokenmanager.entities.Token;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TokenManager {
    private final AppConfig appConfig = AppConfig.getInstance();
    private List<Token> tokens = new ArrayList<>();

    public TokenManager() {
        loadTokens();
    }

    private void loadTokens() {
        try {
            if(Files.exists(appConfig.getTokensStoragePath())) {
                Files.list(appConfig.getTokensStoragePath()).filter(Files::isDirectory).forEach(directory -> {
                    Path certificatePath = directory.resolve("certificate.pem");
                    Path privateKeyPath = directory.resolve("private.pem");
                    if (Files.exists(certificatePath) && Files.isReadable(certificatePath) &&
                            Files.exists(privateKeyPath)  && Files.isReadable(privateKeyPath)) {
                        tokens.add(new Token(directory.getFileName().toString(), certificatePath, privateKeyPath));
                    }
                });
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public List<Token> getTokens() {
        return tokens;
    }

    public Token generateToken(String name, SecureRandom random, String pin) throws IOException, NoSuchAlgorithmException, OperatorCreationException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        Path tokenLocation = appConfig.getTokensStoragePath().resolve(name);
        Files.createDirectories(tokenLocation);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Path certificatePath = tokenLocation.resolve("certificate.pem");
        Path privateKeyPath = tokenLocation.resolve("private.pem");

        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        X500Name subject = new X500Name("CN=" + name);
        BigInteger serial = new BigInteger(64, random);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner singer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(singer);

        try (JcaPEMWriter w = new JcaPEMWriter(Files.newBufferedWriter(certificatePath))) {
            w.writeObject(holder);
        }

        byte[] encryptedPrivateKey = encrypt(keyPair.getPrivate().getEncoded(), pin.toCharArray());
        Files.write(privateKeyPath, encryptedPrivateKey);
        Token token = new Token(name, certificatePath, privateKeyPath);
        tokens.add(token);
        return token;
    }

    private byte[] encrypt(byte[] data, char[] pin) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(pin, salt, 65536, 256);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey baseKey = secretKeyFactory.generateSecret(spec);
        SecretKey key = new SecretKeySpec(baseKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(data);

        byte[] result = new byte[salt.length + encryptedBytes.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(encryptedBytes, 0, result, salt.length, encryptedBytes.length);

        return result;
    }

    public byte[] decrypt(Token token, char[] pin) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] data = Files.readAllBytes(token.getPrivateKeyPath());

        byte[] salt = new byte[16];
        System.arraycopy(data, 0, salt, 0, salt.length);

        byte[] encryptedBytes = new byte[data.length - salt.length];
        System.arraycopy(data, salt.length, encryptedBytes, 0, encryptedBytes.length);

        PBEKeySpec spec = new PBEKeySpec(pin, salt, 65536, 256);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey baseKey = secretKeyFactory.generateSecret(spec);
        SecretKey key = new SecretKeySpec(baseKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedBytes);
    }
}
