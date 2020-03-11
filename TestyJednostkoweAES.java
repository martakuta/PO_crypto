package main.java.pl.edu.mimuw.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;


import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@TestMethodOrder(OrderAnnotation.class)
public class TestyJednostkoweAES {

    private Szyfrator s = new Szyfrator();

    @Test
    @Order(1)
    public void nieprawidlowaDlugoscKlucza() {
        try {
            SecretKey klucz = s.generujKluczAES(-1);
            fail("Nie można generować klucza o ujemnej długości.");
        } catch (InvalidKeySpecException e) {
            assertFalse(false);
        }

        try {
            SecretKey klucz = s.generujKluczAES(0);
            fail("Nie ma sensu generować klucza długości 0.");
        } catch (InvalidKeySpecException e) {
            assertFalse(false);
        }
        try {
            SecretKey klucz = s.generujKluczAES(20);
            fail("Nie można generować klucza AES długości 20");
        } catch (InvalidKeySpecException e) {
            assertTrue(true);
        }
        try {
            SecretKey klucz = s.generujKluczAES(256);
            assertEquals(klucz.getEncoded().length, 256/8);
        } catch (InvalidKeySpecException e) {
            fail("Generowanie klucza długości 256 powinno się udać.");
        }
        try {
            SecretKey klucz = s.generujKluczAES(192);
            assertEquals(klucz.getEncoded().length, 192/8);
        } catch (InvalidKeySpecException e) {
            fail("Generowanie klucza długości 192 powinno się udać.");
        }
        try {
            SecretKey klucz = s.generujKluczAES(128);
            assertEquals(klucz.getEncoded().length, 128/8);
        } catch (InvalidKeySpecException e) {
            fail("Generowanie klucza długości 128 powinno się udać.");
        }
    }

    @Test
    @Order(2)
    public void poprawneSzyfrowanieStringa () {
        String tekst = "Ala ma kota, a kot ma Ale";
        try {
            SecretKey klucz = s.generujKluczAES(128);
            byte[] wynik = s.szyfrujAES(tekst, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 128 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        } catch (NoSuchAlgorithmException e) {
            fail("Algorytm AES nie jest dostępny w środowisku");
        } catch (NoSuchPaddingException e) {
            fail("PKCS5Padding niedostępne w Twoim środowisku");
        }

        try {
            SecretKey klucz = s.generujKluczAES(192);
            byte[] wynik = s.szyfrujAES(tekst, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 192 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        } catch (NoSuchAlgorithmException e) {
            fail("Algorytm AES nie jest dostępny w środowisku");
        } catch (NoSuchPaddingException e) {
            fail("PKCS5Padding niedostępne w Twoim środowisku");
        }

        try {
            SecretKey klucz = s.generujKluczAES(256);
            byte[] wynik = s.szyfrujAES(tekst, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 256 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        } catch (NoSuchAlgorithmException e) {
            fail("Algorytm AES nie jest dostępny w środowisku");
        } catch (NoSuchPaddingException e) {
            fail("PKCS5Padding niedostępne w Twoim środowisku");
        }
    }

    @Test
    @Order(3)
    public void poprawneDeszyfrowanieStringa () {

        String tekst = "Ala ma kota, a kot ma Ale";

        try {
            SecretKey klucz = s.generujKluczAES(128);
            byte[] wynik = s.szyfrujAES(tekst, klucz);
            byte[] deszyfr = s.deszyfrujAES(wynik, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 128 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        } catch (NoSuchAlgorithmException e) {
            fail("Algorytm AES nie jest dostępny w środowisku");
        } catch (NoSuchPaddingException e) {
            fail("PKCS5Padding niedostępne w Twoim środowisku");
        } catch (BadPaddingException e) {
            fail("Zaszyfrowana wiadomość nie jest wyrównana zgodnie z PKCS #5");
        }

        try {
            SecretKey klucz = s.generujKluczAES(192);
            byte[] wynik = s.szyfrujAES(tekst, klucz);
            byte[] deszyfr = s.deszyfrujAES(wynik, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 128 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        } catch (NoSuchAlgorithmException e) {
            fail("Algorytm AES nie jest dostępny w środowisku");
        } catch (NoSuchPaddingException e) {
            fail("PKCS5Padding niedostępne w Twoim środowisku");
        } catch (BadPaddingException e) {
            fail("Zaszyfrowana wiadomość nie jest wyrównana zgodnie z PKCS #5");
        }

        try {
            SecretKey klucz = s.generujKluczAES(256);
            byte[] wynik = s.szyfrujAES(tekst, klucz);
            byte[] deszyfr = s.deszyfrujAES(wynik, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 128 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        } catch (NoSuchAlgorithmException e) {
            fail("Algorytm AES nie jest dostępny w środowisku");
        } catch (NoSuchPaddingException e) {
            fail("PKCS5Padding niedostępne w Twoim środowisku");
        } catch (BadPaddingException e) {
            fail("Zaszyfrowana wiadomość nie jest wyrównana zgodnie z PKCS #5");
        }
    }
}
