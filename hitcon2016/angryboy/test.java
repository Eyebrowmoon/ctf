/**
 * Created by illuxic on 2016. 10. 9..
 */

import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;


public class test {
    private static String a = "./secret";
    
    private static byte[] a() {
      try {
        return Arrays.copyOfRange(Files.readAllBytes(Paths.get(a, new String[0])), 0, 16);
      } catch (Exception e) { return new byte[0]; }
    }

    private static byte[] a(String arrby) {
      byte[] arrBy;

      try {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        arrBy = messageDigest.digest(arrby.getBytes("UTF-8"));

        return arrBy;
      } catch (Exception e) { return new byte[0]; }
    }
                               
    private static byte[] aesDecryptCbc(String sKey, byte[] encrypted, String sInitVector) {
        byte[] key = null;
        byte[] iv = null;
        byte[] decrypted = null;
        final int AES_KEY_SIZE_128 = 128;

        try {
            // UTF-8
            key = sKey.getBytes("UTF-8");

            // Key size 맞춤 (128bit, 16byte)
            key = Arrays.copyOf(key, AES_KEY_SIZE_128 / 8);

            if (sInitVector != null) {
                // UTF-8
                iv = sInitVector.getBytes("UTF-8");

                // Key size 맞춤 (128bit, 16byte)
                iv = Arrays.copyOf(iv, AES_KEY_SIZE_128 / 8);

                // AES/EBC/PKCS5Padding
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec ips = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ips);
                decrypted = cipher.doFinal(encrypted);
            } else {
                // AES/EBC/PKCS5Padding
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                decrypted = cipher.doFinal(encrypted);
            }
        } catch (Exception e) {
            decrypted = null;
            e.printStackTrace();
        }

        return decrypted;
    }

    private static String toHexString(byte[] b) {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < b.length; i++) {
            sb.append(String.format("%02X", b[i]));
            if ((i + 1) % 16 == 0 && ((i + 1) != b.length)) {
                sb.append(" ");
            }
        }

        return sb.toString();
    }

    static int fromDigit(char ch)
    {
        if ((ch >= '0') && (ch <= '9'))
        {
            return ch - '0';
        } else if ((ch >= 'A') && (ch <= 'F'))
        {
            return ch + 10 - 'A';
        } else if ((ch >= 'a') && (ch <= 'f'))
        {
            return ch + 10 - 'a';
        } else
        {
            throw new IllegalArgumentException(String.format("Invalid hex character 0x%04x", 0xff & ch));
        }
    }
    static byte[] hexFromString( String hex ) {

        int len = hex.length();
        byte[] buf = new byte[((len + 1) / 2)];

        int i = 0, j = 0;
        if ((len % 2) == 1)
            buf[j++] = (byte) fromDigit(hex.charAt(i++));

        while (i < len) {

            buf[j++] = (byte) ((fromDigit(hex.charAt(i++)) << 4) |
                    fromDigit(hex.charAt(i++)));
        }
        return buf;
    }

    public static void main(String[] args) {
        //String sKey = toHexString(test.a("141.223.199.43" + new String(test.a())));
        //String sKey = "d125bb23fbe007116cd871d19eb852bb";
        String sKey = new String(test.a("141:223:199:43" + new String(test.a())));

        System.out.println(new String(hexFromString("61616161")));

        StringBuilder SBKey = new StringBuilder();
        for (int i = 0; i < SBKey.length(); i += 2) {
            String str = SBKey.substring(i, i + 2);
            SBKey.append((char)Integer.parseInt(str, 16));
        }

        String sInitVector = "0011223344556677";

        String hex = "016264da521215abc24fd0d6bb2bd5e6986164b5bb3b2d1df750b2da6507a0e76734a92105582f1dee5f6e56f0144573";
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i+=2) {
            String str = hex.substring(i, i+2);
            output.append((char)Integer.parseInt(str, 16));
        }


        try {
            byte[] encrypted = output.toString().getBytes("UTF-8");
            byte[] decrypted = null;
            System.out.println("* AES/CBC/IV");
            System.out.println("    - KEY : " + sKey);
            System.out.println("    - IV : " + sInitVector);

            // AES/CBC/IV 복호화
            decrypted = aesDecryptCbc(sKey, hexFromString(hex), sInitVector);

            if (decrypted == null) {
                System.out.println("    - Decrypted : ERROR!!!");
            } else {
                System.out.println("    - Decrypted : " + new String(decrypted, "UTF-8"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
