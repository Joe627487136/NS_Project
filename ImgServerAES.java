package NS_Project;

/**
 * Created by skychaser on 04/14/2017.
 */

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;


public class ImgServerAES implements Runnable{
    private ServerSocket serverSockets;
    private int portnum;
    private static String rootpath = "/Users/zhouxuexuan/AndroidStudioProjects/Lab/lab/src/main/java/NS_Project/";

    private ImgServerAES(int port) throws InterruptedException {
        try {
            portnum = port;
            serverSockets = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        while(true) {
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
            }
        }
    }

    private void saveFile(Socket clientSock) throws Exception {
        Path cafile = Paths.get(rootpath+"CA.crt");
        byte [] cabytes  = Files.readAllBytes(cafile);
        OutputStream os = clientSock.getOutputStream();
        System.out.println("Sending CA: " + "(" + cabytes.length + " bytes)");
        os.write(cabytes,0,cabytes.length);
        os.flush();
        System.out.println("CA sent.");
        int count=0;
        byte[] Decryptedbytes;
        String key = "Bar12345Bar12345";
        String initVector = "RandomInitVector";
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSock.getInputStream()));
        PrintWriter out = new PrintWriter(clientSock.getOutputStream(), true);
        String inputLine;
        try {
            inputLine = in.readLine();
            if(!inputLine.equals("&&&NOMORE&&&")){
                System.out.println("Input String Length: "+inputLine.length());
                Decryptedbytes = decrypttoimg(key,initVector,inputLine);
                BufferedImage img = ImageIO.read(new ByteArrayInputStream(Decryptedbytes));
                ImageIO.write(img, "bmp", new File(rootpath+"new-darksouls2.bmp"));
            }else {
                System.out.println("Decrypt liao");
            }
        }catch (SocketException e){
            System.out.println("Reset!");
        }catch (IllegalArgumentException e){
            System.out.println("Pass");
        }
        out.println("pass my friend");
        out.flush();
        in.close();
        out.close();
        clientSock.close();
        System.out.println("Image Transfer Finished");
    }

    public static void main(String[] args) throws Exception {
        int max_pool_size = 5;
        ExecutorService exec = Executors.newFixedThreadPool(max_pool_size);
        for(int i=4999; i<=5003;i++){
            Runnable worker = new ImgServerAES(i);
            exec.execute(worker);
        }
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

    public static byte[] decrypttoimg(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

            return original;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
