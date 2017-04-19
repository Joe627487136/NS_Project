package NS_Project;

/**
 * Created by skychaser on 04/14/2017.
 */
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
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
import java.security.KeyFactory;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.imageio.ImageIO;

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
            String filepath1 = rootpath+"smallfile.txt";
            String filepath2 = rootpath+"globe.bmp";
            Cipher encryptCipher = Cipher.getInstance("RSA");
            KeyPair ShareKeyPair=LoadKeyPair(path,"RSA");
            dumpKeyPair(ShareKeyPair);
            PrivateKey privateKey=ShareKeyPair.getPrivate();
            PublicKey publicKey=ShareKeyPair.getPublic();
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            PrintWriter out = new PrintWriter(echoSocket.getOutputStream(), true);

            //Txt:
            byte[] cipherbytes = Files.readAllBytes(Paths.get(filepath2));

            //Image:
            //byte[] cipherbytes = extractBytes(filepath2);

            byte[][] cipherchunks = splitArray(cipherbytes,117);
            for(byte[] i:cipherchunks){
                String flushingstring = encrypt(i,publicKey);
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

    public static String encrypt(byte[] k, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(k);
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

    public static KeyPair LoadKeyPair(String path, String algorithm)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read Public Key.
        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Read Private Key.
        File filePrivateKey = new File(path + "/private.key");
        fis = new FileInputStream(path + "/private.key");
        byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    public static byte[] extractBytes (String ImageName) throws IOException {
        // open image
        File imgPath = new File(ImageName);
        BufferedImage bufferedImage = ImageIO.read(imgPath);

        // get DataBufferBytes from Raster
        WritableRaster raster = bufferedImage .getRaster();
        DataBufferByte data   = (DataBufferByte) raster.getDataBuffer();

        return ( data.getData() );
    }
}
