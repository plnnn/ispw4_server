package lt.viko.eif.nychyporuk.ispw4_server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Server {
    public static void main(String[] args) {

        final String ANSI_RESET = "\u001B[0m";
        final String ANSI_RED = "\u001B[31m";
        final String ANSI_GREEN = "\u001B[32m";
        final String ANSI_PURPLE = "\u001B[35m";

        try (ServerSocket serverSocket = new ServerSocket(1338)) {
            System.out.println(ANSI_PURPLE +
                    "Listening on port 1338. Waiting for connection...\n" +
                    ANSI_RESET);

            Socket socket = serverSocket.accept();
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            System.out.println(ANSI_GREEN +
                    "Connection from MITM established!" +
                    ANSI_RESET);

            while (true) {
                // Receive data from MITM
                String receivedPublicKey = dis.readUTF();
                System.out.println(ANSI_PURPLE +
                        "Received public key:\n" +
                        ANSI_GREEN +
                        receivedPublicKey);

                String receivedSignature = dis.readUTF();
                System.out.println(ANSI_PURPLE +
                        "Received signature:\n" +
                        ANSI_GREEN +
                        receivedSignature);

                String receivedMessage = dis.readUTF();
                System.out.println(ANSI_PURPLE +
                        "Received message:\n" +
                        ANSI_GREEN +
                        receivedMessage);

                // Decode the received data
                byte[] publicKeyBytes = Base64.getDecoder().decode(receivedPublicKey);
                byte[] signatureBytes = Base64.getDecoder().decode(receivedSignature);

                // Check the structure of signature
                final int EXPECTED_SIGNATURE_LENGTH = 256;

                if (signatureBytes.length != EXPECTED_SIGNATURE_LENGTH) {
                    System.out.printf(ANSI_RED +
                                    "Invalid signature length. " +
                                    "Expected %d bytes but received %d\n" +
                                    ANSI_RESET,
                            EXPECTED_SIGNATURE_LENGTH, signatureBytes.length);
                    continue;
                }

                // Convert bytes to public key
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(keySpec);

                // Verify the digital signature
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(receivedMessage.getBytes());

                boolean isSignatureValid = signature.verify(signatureBytes);
                System.out.print(ANSI_PURPLE +
                        "Signature verification result: " +
                        ANSI_RESET);
                if (isSignatureValid) {
                    System.out.println(ANSI_GREEN + "OK" + ANSI_RESET);
                    System.out.println(ANSI_GREEN + "The signature is client's.\n" + ANSI_RESET);
                } else {
                    System.out.println(ANSI_RED + "FAIL" + ANSI_RESET);
                    System.out.println(ANSI_RED + "The MITM modified the signature.\n" + ANSI_RESET);
                }
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException
                 | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}