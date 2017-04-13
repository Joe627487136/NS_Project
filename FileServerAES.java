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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.security.provider.SHA;


public class FileServerAES implements Runnable{
    private ServerSocket serverSockets;

    private FileServerAES(int port) throws InterruptedException {
        try {
            serverSockets = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        while (true) {
            try {
                Socket clientSock = serverSockets.accept();
                System.out.println("One Client in");
                saveFile(clientSock);
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
        int nRead;
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
        PrintWriter printWriter = new PrintWriter("/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/AEScipher.txt");
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
    public void ConvertFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        String key = "Bar12345Bar12345";
        String initVector = "RandomInitVector";
        String path = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/";
        PrintWriter printWriter = new PrintWriter("/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/output.txt");
        try (BufferedReader br = new BufferedReader(new FileReader("/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/AEScipher.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println("Printing one line");
                printWriter.write(decrypt(key,initVector,line) + "\r\n");
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
            Runnable worker = new FileServerAES(i);
            exec.execute(worker);
        }
    }

    public static String decrypt(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
