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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.util.Base64.getEncoder;


public class FileClientAES {
    public static void main(String[] args) throws Exception {
        String hostName = "127.0.0.1";
        int portNumber = 4999;
        boolean Handshake = false;
        byte[] filebytes;
        byte[][]byteschunksarray;
        String path = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/";
        Socket echoSocket = new Socket(hostName, portNumber);
        InputStream inputStream = echoSocket.getInputStream();
        if (EstablishHandshake(inputStream)) {
            Handshake=true;
            System.out.println("Handshake established\n\n");
        }
        if(Handshake) {
            String key = "Bar12345Bar12345";
            String initVector = "RandomInitVector";
            PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(echoSocket.getInputStream()));
            BufferedReader is = new BufferedReader(new FileReader("/Users/zhouxuexuan/desktop/input.txt"));
            String inputraw = is.readLine();
            String inputLine = encrypt(key,initVector,inputraw);
            System.out.println(inputLine);
            while (inputraw != null) {
                while (true) {
                    out.println(inputLine);
                    out.flush();
                    try {
                        in.readLine();
                        break;
                    }
                    catch (java.net.SocketTimeoutException e) {
                    }
                }
                inputraw = is.readLine();
                try{inputLine = encrypt(key,initVector,inputraw);
                }catch (NullPointerException e){
                    break;
                }
                System.out.println(inputLine);
            }
            while (true) {
                out.println("&&&NOMORE&&&");
                try {
                    inputLine = in.readLine();
                    break;
                }
                catch (java.net.SocketTimeoutException e) {
                }
            }

            is.close();
            in.close();
            out.close();
            echoSocket.close();
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

    public static String encrypt(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
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