import javax.crypto.Cipher;

public class MessageCipher {
    public Cipher newCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
