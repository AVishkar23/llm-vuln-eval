import javax.crypto.Cipher;

public class MessageCipher {
    public Cipher newCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
