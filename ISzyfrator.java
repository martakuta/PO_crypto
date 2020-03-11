package main.java.pl.edu.mimuw.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public interface ISzyfrator {

    /**
     * Tworzy losowy klucz dla szyfru z kluczem jednorazowym (one-time pad).
     *
     * @throws {@link InvalidKeySpecException}
     */
    public SecretKey generujKluczOTP(int dlugosc) throws InvalidKeySpecException;

    /**
     * Generuje losowy klucz dla algorytmu AES.
     *
     * @param dlugosc
     *            długość klucza (w bitach); dopuszczalne wartości to: 128, 192 i 256
     * @throws {@link InvalidKeySpecException}
     */
    public SecretKey generujKluczAES(int dlugosc) throws InvalidKeySpecException;

    /**
     * Wykonuje szyfrowanie z kluczem jednorazowym (one-time pad) podanej
     * wiadomości. W przypadku, gdy długość wiadomości i klucza są niezgodne
     * zgłasza wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm
     * szyfrowania nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}
     *
     * @param tekst
     *            wiadomość do zaszyfrowania
     * @param klucz
     *            tajny klucz
     * @return szyfrogram
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     */
    public byte[] szyfrujOTP(String tekst, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException;

    /**
     * Wykonuje szyfrowanie algorytmem AES (w trybie CBC z wyrównaniem zgodnym z
     * PKCS #5; formalnie jest to wyrównanie PKCS #7) podanej wiadomości przy
     * użyciu danego klucza.
     *
     * W przypadku, gdy długość klucza jest inna niż dopuszczalna w AES (128, 192 albo 256 bitów)
     * zgłasza wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm szyfrowania (w
     * trybie CBC) nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}. W przypadku, gdy wyrównywanie PKCS #5
     * nie jest dostępne w środowisku zgłasza wyjątek
     * {@link NoSuchPaddingException}.
     *
     * @param tekst
     *            wiadomość do zaszyfrowania
     * @param klucz
     *            tajny klucz AES
     * @return szyfrogram (z wyrównaniem do wielokrotności 8 bajtów)
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     * @throws {@link NoSuchPaddingException}
     */
    public byte[] szyfrujAES(String tekst, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException;

    /**
     * Wykonuje szyfrowanie z kluczem jednorazowym (one-time pad) podanej
     * wiadomości. W przypadku, gdy długość wiadomości i klucza są niezgodne
     * zgłasza wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm
     * szyfrowania nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}
     *
     * @param tekst
     *            wiadomość do zaszyfrowania (zadana jako ciąg bajtów)
     * @param klucz
     *            tajny klucz
     * @return szyfrogram
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     */
    public byte[] szyfrujOTP(byte[] tekst, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException;

    /**
     * Wykonuje szyfrowanie algorytmem AES (w trybie CBC z wyrównaniem zgodnym z
     * PKCS #5; formalnie jest to wyrównanie PKCS #7) podanej wiadomości przy
     * użyciu danego klucza.
     *
     * W przypadku, gdy długość klucza jest inna niż dopuszczalna w AES (128, 192 albo 256 bitów)
     * zgłasza wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm szyfrowania (w
     * trybie CBC) nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}. W przypadku, gdy wyrównywanie PKCS #5
     * nie jest dostępne w środowisku zgłasza wyjątek
     * {@link NoSuchPaddingException}.
     *
     * @param tekst
     *            wiadomość do zaszyfrowania (zadana jako ciąg bajtów)
     * @param klucz
     *            tajny klucz AES
     * @return szyfrogram (z wyrównaniem do wielokrotności 8 bajtów)
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     * @throws {@link NoSuchPaddingException}
     */
    public byte[] szyfrujAES(byte[] tekst, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException;

    /**
     * Deszyfruje wiadomość przy użyciu klucza jednorazowego (one-time pad). W
     * przypadku, gdy długość szyfrogramu i klucza są niezgodne zgłasza wyjątek
     * {@link InvalidKeyException}. W przypadku, gdy algorytm szyfrowania nie
     * jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}
     *
     * @param szyfrogram
     *            tekst zaszyfrowany
     * @param klucz
     *            klucz jednorazowy
     * @return odszyfrowana wiadomość (ciąg bajtów)
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     */
    public byte[] deszyfrujOTP(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException;

    /**
     * Deszyfruje wiadomość przy użyciu algorytmu AES (w trybie CBC z wyrównaniem zgodnym z
     * PKCS #5; formalnie jest to wyrównanie PKCS #7).
     *
     * W przypadku, gdy długość klucza jest inna niż dopuszczalna w AES (128, 192 albo 256 bitów)
     * zgłasza wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm szyfrowania (w
     * trybie CBC) nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}. W przypadku, gdy wyrównywanie PKCS #5
     * nie jest dostępne w środowisku zgłasza wyjątek
     * {@link NoSuchPaddingException}. W przypadku, gdy zaszyfrowana wiadomość
     * nie jest wyrównana zgodnie z PKCS #5 zgłasza wyjątek
     * {@link BadPaddingException}.
     *
     * @param szyfrogram
     *            tekst zaszyfrowany
     * @param klucz
     *            tajny klucz AES
     * @return odszyfrowana wiadomość (ciąg bajtów)
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     * @throws {@link NoSuchPaddingException}
     * @throws {@link BadPaddingException}
     */
    public byte[] deszyfrujAES(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, BadPaddingException;

    /**
     * Deszyfruje wiadomość przy użyciu klucza jednorazowego (one-time pad) jako
     * napis. W przypadku, gdy długość szyfrogramu i klucza są niezgodne zgłasza
     * wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm
     * szyfrowania nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}
     *
     * @param szyfrogram
     *            tekst zaszyfrowany
     * @param klucz
     *            klucz jednorazowy
     * @return odszyfrowana wiadomość (napis)
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     */
    public String deszyfrujOTPJakoNapis(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException;

    /**
     * Deszyfruje wiadomość przy użyciu algorytmu AES (w trybie CBC z wyrównaniem zgodnym z
     * PKCS #5; formalnie jest to wyrównanie PKCS #7).
     *
     * W przypadku, gdy długość klucza jest inna niż dopuszczalna w AES (128, 192 albo 256 bitów)
     * zgłasza wyjątek {@link InvalidKeyException}. W przypadku, gdy algorytm szyfrowania (w
     * trybie CBC) nie jest dostępny w środowisku zgłasza wyjątek
     * {@link NoSuchAlgorithmException}. W przypadku, gdy wyrównywanie PKCS #5
     * nie jest dostępne w środowisku zgłasza wyjątek
     * {@link NoSuchPaddingException}. W przypadku, gdy zaszyfrowana wiadomość
     * nie jest wyrównana zgodnie z PKCS #5 zgłasza wyjątek
     * {@link BadPaddingException}.
     *
     * @param szyfrogram
     *            tekst zaszyfrowany
     * @param klucz
     *            tajny klucz AES
     * @return odszyfrowana wiadomość (napis)
     * @throws {@link InvalidKeyException}
     * @throws {@link NoSuchAlgorithmException}
     * @throws {@link NoSuchPaddingException}
     * @throws {@link BadPaddingException}
     */
    public String deszyfrujAESJakoNapis(byte[] szyfrogram, SecretKey klucz)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, BadPaddingException;

}
