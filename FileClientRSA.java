package NS_Project;

/**
 * Created by zhouxuexuan on 13/4/17.
 */
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

import static java.util.Base64.getEncoder;


public class FileClientRSA {
    private static String rootpath = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/";
    public static void main(String[] args) throws Exception {
        String hostName = "127.0.0.1";
        int portNumber = 4999;
        boolean Handshake = false;
        String path = rootpath;
        Socket echoSocket = new Socket(hostName, portNumber);
        InputStream inputStream = echoSocket.getInputStream();
        if (EstablishHandshake(inputStream)) {
            Handshake=true;
            System.out.println("Handshake established\n\n");
        }
        if(Handshake) {
            String filepath = rootpath+"largeFile.txt";
            Cipher encryptCipher = Cipher.getInstance("RSA");
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey publickey = keyPair.getPublic();
            PrivateKey privatekey = keyPair.getPrivate();
            SaveKeyPair(path,keyPair);
            dumpKeyPair(keyPair);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publickey);
            PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);
            byte[] cipherbytes = Files.readAllBytes(Paths.get(filepath));
            byte[][] cipherchunks = splitArray(cipherbytes,117);
            for(byte[] i:cipherchunks){
                String s = new String(i);
                String flushingstring = encrypt(s,privatekey);
                out.println(flushingstring);
                out.flush();
            }
            out.println("&&&NOMORE&&&");
            inputStream.close();
            out.close();
            echoSocket.close();
            System.out.println("Client Socket Closed");
        }else {
            System.out.println("Reject!");
        }
    }

    private static boolean EstablishHandshake(InputStream ca) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert =(X509Certificate)cf.generateCertificate(ca);
        PublicKey CAcertPublicKey = CAcert.getPublicKey();
        try {
            CAcert.checkValidity();
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
        }
        try {
            CAcert.verify(CAcertPublicKey);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return true;
    }

    public static void SaveKeyPair(String path, KeyPair keyPair) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/public.key");
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        fos = new FileOutputStream(path + "/private.key");
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }
    public static byte[][] splitArray(byte[] arrayToSplit, int chunkSize){
        if(chunkSize<=0){
            return null;
        }
        int rest = arrayToSplit.length % chunkSize;
        int chunks = arrayToSplit.length / chunkSize + (rest > 0 ? 1 : 0);
        byte[][] arrays = new byte[chunks][];
        for(int i = 0; i < (rest > 0 ? chunks - 1 : chunks); i++){
            arrays[i] = Arrays.copyOfRange(arrayToSplit, i * chunkSize, i * chunkSize + chunkSize);
        }
        if(rest > 0){
            arrays[chunks - 1] = Arrays.copyOfRange(arrayToSplit, (chunks - 1) * chunkSize, (chunks - 1) * chunkSize + rest);
        }
        return arrays;
    }

    public static String encrypt(String plainText, PrivateKey privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    private static void dumpKeyPair(KeyPair keyPair) {
        PublicKey pub = keyPair.getPublic();
        System.out.println("Public Key: " + getHexString(pub.getEncoded()));

        PrivateKey priv = keyPair.getPrivate();
        System.out.println("Private Key: " + getHexString(priv.getEncoded()));
    }

    private static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }
}