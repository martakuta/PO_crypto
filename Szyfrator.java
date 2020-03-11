package main.java.pl.edu.mimuw.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;



public class Szyfrator implements ISzyfrator {

    private int IV_LENGTH = 16;

    public SecretKey generujKluczOTP(int dlugosc) throws InvalidKeySpecException {
        if (dlugosc <= 0) {
            throw new InvalidKeySpecException();
        } else {
            SecureRandom r = new SecureRandom();
            byte[] tablicaKlucza = r.generateSeed(dlugosc);
            return new SecretKeySpec(tablicaKlucza, "OTP");
        }
    }

    public SecretKey generujKluczAES(int dlugosc) throws InvalidKeySpecException {
        if (!(dlugosc == 128 || dlugosc == 192 || dlugosc == 256)) {
            throw new InvalidKeySpecException();
        } else {
            SecureRandom r = new SecureRandom();
            byte[] tablicaKlucza = r.generateSeed(dlugosc/8);
            return new SecretKeySpec(tablicaKlucza, "AES");
        }
    }

    public byte[] szyfrujOTP(String tekst, SecretKey klucz)
            throws InvalidKeyException {

        if (klucz == null)
            throw new InvalidKeyException();

        byte[] wiadomosc = tekst.getBytes();
        byte[] kluczTablica = klucz.getEncoded();

        if (wiadomosc.length > kluczTablica.length)
            throw new InvalidKeyException();

        for (int i = 0; i < wiadomosc.length; i++) {
            wiadomosc[i] = (byte)(wiadomosc[i]^kluczTablica[i]);
        }

        return wiadomosc;
    }

    public byte[] szyfrujAES(String tekst, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        return szyfrujAES(tekst.getBytes(), klucz);
    }

    public byte[] szyfrujOTP(byte[] tekst, SecretKey klucz)
            throws InvalidKeyException {

        if (klucz == null)
            throw new InvalidKeyException();

        byte[] wiadomosc = Arrays.copyOf(tekst, tekst.length);
        byte[] kluczTablica = klucz.getEncoded();

        if (wiadomosc.length > kluczTablica.length)
            throw new InvalidKeyException();

        for (int i = 0; i < wiadomosc.length; i++) {
            wiadomosc[i] = (byte)(wiadomosc[i]^kluczTablica[i]);
        }

        return wiadomosc;
    }

    public byte[] szyfrujAES(byte[] tekst, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        byte[] wiadomoscIV = null;
        try {
            byte[] wiadomosc = Arrays.copyOf(tekst, tekst.length);

            SecureRandom r = new SecureRandom();
            byte[] iv = r.generateSeed(IV_LENGTH);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            aesCipher.init(Cipher.ENCRYPT_MODE, klucz, new IvParameterSpec(iv));

            wiadomosc = aesCipher.doFinal(wiadomosc);

            wiadomoscIV = new byte[iv.length + wiadomosc.length];
            System.arraycopy(iv, 0, wiadomoscIV, 0, iv.length);
            System.arraycopy(wiadomosc, 0, wiadomoscIV, IV_LENGTH, wiadomosc.length);

        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException();
        } catch (BadPaddingException e) {
            throw new NoSuchPaddingException();
        } catch (IllegalBlockSizeException ignore) {
            //wyjatek, do ktorego dojscia niedopuszczamy za pomoca PCKS5Padding
        }
        return wiadomoscIV;
    }

    public byte[] deszyfrujOTP(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException {

        return szyfrujOTP(szyfrogram, klucz);

    }

    public byte[] deszyfrujAES(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, BadPaddingException {
        byte[] wiadomosc = new byte[szyfrogram.length - IV_LENGTH];
        try {
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(szyfrogram, 0, iv, 0, IV_LENGTH);
            System.arraycopy(szyfrogram, IV_LENGTH, wiadomosc, 0, wiadomosc.length);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, klucz, new IvParameterSpec(iv));

            wiadomosc = aesCipher.doFinal(wiadomosc);

        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException();
        } catch (IllegalBlockSizeException ignore) {
            //wyjatek, do ktorego dojscia niedopuszczamy za pomoca PCKS5Padding
       }
        return wiadomosc;
    }

    public String deszyfrujOTPJakoNapis(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException {

        byte[] wiadomosc = deszyfrujOTP(szyfrogram, klucz);
        return new String(wiadomosc);

    }

    public String deszyfrujAESJakoNapis(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, BadPaddingException {

        byte[] wiadomosc = deszyfrujAES(szyfrogram, klucz);
        return new String(wiadomosc);

    }


}
