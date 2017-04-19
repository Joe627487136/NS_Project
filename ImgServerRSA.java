package NS_Project;

/**
 * Created by skychaser on 04/14/2017.
 */
import java.awt.SystemColor;
import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.server.ExportException;
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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;

import sun.security.provider.SHA;


public class ImgServerRSA implements Runnable{
    private ServerSocket serverSockets;
    private int portnum;
    private static String rootpath = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/";

    private ImgServerRSA(int port) throws InterruptedException {
        try {
            portnum = port;
            serverSockets = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        while (true) {
            try {
                System.out.println("Port "+portnum+" is waiting for connection");
                Socket clientSock = serverSockets.accept();
                System.out.println("A Client is connected to "+portnum);
                final long startTime = System.currentTimeMillis();
                saveFile(clientSock);
                final long endTime = System.currentTimeMillis();
                System.out.println("Total execution time in ms: " + (endTime - startTime));
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            } catch (Exception e) {
                System.out.print("Some Errors");
            }
        }
    }

    private void saveFile(Socket clientSock) throws Exception {
        Path cafile = Paths.get(rootpath + "CA.crt");
        byte[] cabytes = Files.readAllBytes(cafile);
        OutputStream os = clientSock.getOutputStream();
        System.out.println("Sending CA: " + "(" + cabytes.length + " bytes)");
        os.write(cabytes, 0, cabytes.length);
        os.flush();
        System.out.println(cabytes);
        System.out.println("CA sent.");
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSock.getInputStream()));
        PrintWriter out = new PrintWriter(clientSock.getOutputStream(), true);
        String inputLine;
        byte[] imgbyte = new byte[0];
        int count = 0;
        String path = rootpath;
        KeyPair ShareKeyPair = LoadKeyPair(path, "RSA");
        dumpKeyPair(ShareKeyPair);
        PrivateKey privateKey = ShareKeyPair.getPrivate();
        PublicKey publicKey = ShareKeyPair.getPublic();
        try {
            do {
                inputLine = in.readLine();
                System.out.println("Adding chunks " + count);
                count++;
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(imgbyte);
                outputStream.write(decrypttoimg(inputLine, privateKey));
                imgbyte = outputStream.toByteArray();
            } while (!(inputLine == null));
        }catch (NullPointerException e){
        }
        System.out.println("Img byte length: " + imgbyte.length);
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(imgbyte));
        ImageIO.write(img, "bmp", new File(rootpath + "new-darksouls.bmp"));
        in.close();
        out.close();
        clientSock.close();
        System.out.println("Finished!");
    }


    public static void main(String[] args) throws Exception {
        int max_pool_size = 5;
        ExecutorService exec = Executors.newFixedThreadPool(max_pool_size);
        for(int i=4999; i<=5003;i++){
            Runnable worker = new ImgServerRSA(i);
            exec.execute(worker);
        }
    }

    public KeyPair LoadKeyPair(String path, String algorithm)
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
    public static byte[] decrypttoimg(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        //System.out.println("Signed bytes[] length: "+bytes.length);

        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] byteset=decriptCipher.doFinal(bytes);
        return byteset;
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


    private static String parsefileimg(String path, int count) {
        String fdn = "Out"+count+".bmp";
        File fl = new File(path+fdn);
        while (fl.exists()){
            count++;
            fdn = "Out"+count+".bmp";
            fl = new File(path+fdn);
        }
        return path+fdn;
    }
}