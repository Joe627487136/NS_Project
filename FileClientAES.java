package NS_Project;

/**
 * Created by skychaser on 04/14/2017.
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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.util.Base64.getEncoder;


public class FileClientAES {
    public static void main(String[] args) throws Exception {
        String hostName = "127.0.0.1";
        int portNumber = 4999;
        boolean Handshake = false;
        Socket echoSocket = new Socket(hostName, portNumber);
        InputStream inputStream = echoSocket.getInputStream();
        if (EstablishHandshake(inputStream)) {
            Handshake=true;
            System.out.println("Handshake established\n\n");
        }
        if(Handshake) {
            String key = "Bar12345Bar12345";
            String initVector = "RandomInitVector";
            //
            //String filepath = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/largeFile.txt";
            String filepath = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/globe.bmp";
            //
            PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);
            byte[] cipherbytes = Files.readAllBytes(Paths.get(filepath));
            System.out.println(cipherbytes.length);
            String ciphertxt = encrypt(key,initVector,cipherbytes);
            out.println(ciphertxt);
            out.flush();
            out.println("&&&NOMORE&&&");
            out.close();
            echoSocket.close();
            System.out.println("Client Socket Closed");
        }else {
            System.out.println("Reject!");
            echoSocket.close();
        }
    }

    private static boolean EstablishHandshake(InputStream ca) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(ca);
            PublicKey CAcertPublicKey = CAcert.getPublicKey();
            CAcert.checkValidity();
            CAcert.verify(CAcertPublicKey);
            return true;
        }catch (Exception e){
            System.out.println("Bye!");
        }
        return false;
    }


    public static String encrypt(String key, String initVector, byte[] value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value);
            System.out.println("encrypted string: " + Base64.getEncoder().encodeToString(encrypted));

            return Base64.getEncoder().encodeToString(encrypted);
        } catch (NullPointerException e){
            System.out.print("Looping completed, upload finished");
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

}


