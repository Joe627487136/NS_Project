package NS_Project;

/**
 * Created by zhouxuexuan on 13/4/17.
 */
import java.io.BufferedInputStream;
import java.io.BufferedReader;
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

import sun.security.provider.SHA;


public class FileServerRSA implements Runnable{
    private ServerSocket serverSockets;
    private int portnum;

    private FileServerRSA(int port) throws InterruptedException {
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
                System.out.println("A Client is connected");
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
                e.printStackTrace();
            }
        }
    }

    private void saveFile(Socket clientSock) throws Exception {
        Path cafile = Paths.get("/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/CA.crt");
        byte [] cabytes  = Files.readAllBytes(cafile);
        OutputStream os = clientSock.getOutputStream();
        System.out.println("Sending CA: " + "(" + cabytes.length + " bytes)");
        os.write(cabytes,0,cabytes.length);
        os.flush();
        System.out.println(cabytes);
        System.out.println("CA sent.");
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSock.getInputStream()));
        PrintWriter out = new PrintWriter(clientSock.getOutputStream(), true);
        PrintWriter printWriter = new PrintWriter("/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/RSAcipher.txt");
        String inputLine;
        do {
            inputLine = in.readLine();
            out.println("pass my fiend");
            out.flush();
            if (!inputLine.equals("&&&NOMORE&&&")) {
                printWriter.write(inputLine + "\r\n");
            }
        } while (!inputLine.equals("&&&NOMORE&&&"));
        out.println("pass my fiend");
        out.flush();
        printWriter.close();
        in.close();
        out.close();
        clientSock.close();
        ConvertFile();
    }
    private void ConvertFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        int count=0;
        String path = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/";
        String workingpath = parsefile(path,count);
        KeyPair ShareKeyPair=LoadKeyPair(path,"RSA");
        dumpKeyPair(ShareKeyPair);
        PrivateKey privateKey=ShareKeyPair.getPrivate();
        PublicKey publicKey=ShareKeyPair.getPublic();
        PrintWriter printWriter = new PrintWriter(workingpath);
        try (BufferedReader br = new BufferedReader(new FileReader("/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/RSAcipher.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                printWriter.write(decrypt(line,publicKey) + "\r\n");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        printWriter.close();
        System.out.println("Decrypt Finished");
    }

    public static void main(String[] args) throws Exception {
        int max_pool_size = 10;
        ExecutorService exec = Executors.newFixedThreadPool(max_pool_size);
        for(int i=4999; i<=5003;i++){
            Runnable worker = new FileServerRSA(i);
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
    public static String decrypt(String cipherText, PublicKey publicKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        //System.out.println("Signed bytes[] length: "+bytes.length);

        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decriptCipher.init(Cipher.DECRYPT_MODE, publicKey);

        return new String(decriptCipher.doFinal(bytes));
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
    private static String parsefile(String path, int count) {
        String fdn = "Out"+count+".txt";
        File fl = new File(path+fdn);
        while (fl.exists()){
            count++;
            fdn = "Out"+count+".txt";
            fl = new File(path+fdn);
        }
        return path+fdn;
    }
}
