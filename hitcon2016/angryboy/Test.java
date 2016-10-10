import java.io.PrintWriter;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Test{
	private static String a = "84cb29d734f89f1a143b08b177fc2b1c";
	private static String b = "FLAG";
	private static String c = "0011223344556677";

	private static byte[] a() {
		byte[] temp; //= Arrays.copyOfRange(Files.readAllBytes(Paths.get(a, new String[0])), 0, 16);
		try {
			temp= Arrays.copyOfRange(Files.readAllBytes(Paths.get(a, new String[0])), 0, 16);
			return temp; // Arrays.copyOfRange(Files.readAllBytes(Paths.get(a, new String[0])), 0, 16);
		} 
		catch(Exception e) {
			return new byte[]{0};
		}
	}
	private static String a(byte[] arrby) {
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < arrby.length; ++i) {
			stringBuilder.append(String.format("%02x", Byte.valueOf(arrby[i])));
		}
		return stringBuilder.toString();
	}

	private static byte[] b() {
		try {
			return Files.readAllBytes(Paths.get(b, new String[0]));
		} 
		catch(Exception e) {
			return new byte[]{0};
		}
	}

	private static byte[] a(String arrby) {
		byte[] arrbyb = new byte[]{0};
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			arrbyb = messageDigest.digest(arrby.getBytes("UTF-8"));
		}
		catch(Exception e) {
		}
		return arrbyb;
	}

    private boolean a(byte by, int n) {
        if (by == Test.a()[n]) {
            return true;
        }
        return false;
    }


	public static void main(String arg[]){
        String string;
        byte[] arrby2;
        Object object;
        object = "0kukr5vZlUMEY3qR"; //prefix
        arrby2 = new byte[]{0};
        String string2 = "9267766"; //captcha
        try {
            arrby2 = Test.a((String)object + string2);
        }
        catch (Exception v0) {}
        object = "15"; //line
        int n = Integer.parseInt((String)object);
        if (n >= 0 && n <= 3) {
            string = "333";
        } else if (n >= 4 && n <= 7) {
            string = "4444";
        } else if (n >= 8 && n <= 11) {
            string = "55555";
        } else if (n >= 12 && n <= 15) {
            string = "666666";
        } else {
            System.out.println("line error");
            return;
        }
		/*
		byte[] temps = {0x1c};
        byte by = temps.toCharArray()[0]; //guess
		*/
		byte by = 0x1c;
        if (Test.a(arrby2).startsWith(string)) {
            int n2 = n;
            byte by2 = by;
            Object object2;
            if (by2 == Test.a()[n2]) {
                if (n == 15) {
                    byte[] arrby3;
                    arrby3 = new byte[]{0};
                    try {
                        arrby3 = Test.a("141:223:175:203" + new String(Test.a()));
						//System.out.println(Test.a(arrby3));
						//System.out.println(String.format("%02x", arrby3[0]));
						/*
						System.out.println(new String(Test.a()));
						System.out.println("141.223.175.203" + new String(Test.a()));
						System.out.println(new String(arrby3));
						*/
                    }
                    catch (Exception v1) {}
                    try {
                        SecretKeySpec arrby = new SecretKeySpec(arrby3, "AES");
                        Cipher arrby32 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                        object2 = new IvParameterSpec(c.getBytes("UTF-8"));
                        arrby32.init(1, (Key)arrby, (AlgorithmParameterSpec)object2);
                        byte[] arrby22 = arrby32.doFinal(Files.readAllBytes(Paths.get(b, new String[0])));
                        System.out.println("encrypted flag is " + Test.a(arrby22));
                    }
                    catch (Exception v2) {
                        System.out.println("encryption error");
                        return;
                    }
                }
                System.out.println("good");
                //System.out.println(new String(new byte[]{49}));
                return;
            }
            System.out.println("bad luck");
            return;
        }
        System.out.println("captcha error");

		System.out.println(new String(a()));
	}
}
