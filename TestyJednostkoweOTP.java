package main.java.pl.edu.mimuw.crypto;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.*;
import org.junit.Test;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

public class TestyJednostkoweOTP {

    private Szyfrator s = new Szyfrator();


    @Test
    public void nieprawidlowaDlugoscKlucza() {
        try {
            SecretKey klucz = s.generujKluczOTP(-1);
            fail("Nie można generować klucza o ujemnej długości.");
        } catch (InvalidKeySpecException e) {
            assertFalse(false);
        }

        try {
            SecretKey klucz = s.generujKluczOTP(0);
            fail("Nie ma sensu generować klucza długości 0.");
        } catch (InvalidKeySpecException e) {
            assertFalse(false);
        }
        try {
            SecretKey klucz = s.generujKluczOTP(20);
            assertEquals(klucz.getEncoded().length, 20);
        } catch (InvalidKeySpecException e) {
            fail("Generowanie klucza długości 20 powinno się udać");
        }
    }

    @Test
    public void kluczKrotszyOdTekstu () {
        String tekst = "Ala ma kota, a kot ma Ale";
        try {
            SecretKey klucz = s.generujKluczOTP(20);
            s.szyfrujOTP(tekst, klucz);
            fail("Szyfrowanie z za krótkim kluczem nie powinno się udać");
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości 20 powinien się wygenerować");
        } catch (InvalidKeyException e) {
            assertTrue(true);
        }
    }

    @Test
    public void poprawneSzyfrowanieStringa () {
        String tekst = "Ala ma kota, a kot ma Ale";
        try {
            SecretKey klucz = s.generujKluczOTP(tekst.length());
            byte[] wynik = s.szyfrujOTP(tekst, klucz);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości niepustego napisu powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie z prawidłowym kluczem.");
        }
    }

    @Test
    public void poprawneDeszyfrowanieStringa () {
        String tekst = "Ala ma kota, a kot ma Ale";
        try {
            SecretKey klucz = s.generujKluczOTP(tekst.length());
            byte[] wynik = s.szyfrujOTP(tekst, klucz);
            byte[] deszyfrowany = s.deszyfrujOTP(wynik, klucz);
            assertEquals(new String(deszyfrowany), tekst);
        } catch (InvalidKeySpecException e) {
            fail("Klucz długości niepustego napisu powinien się wygenerować");
        } catch (InvalidKeyException e) {
            fail("Klucz jest prawidłowy, nieudane szyfrowanie lub deszyfrowanie z prawidłowym kluczem.");
        }
    }
}
