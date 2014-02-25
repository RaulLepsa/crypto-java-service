
public class Example {

    public static void main(String[] args) {
        CryptService cryptService = new CryptService();

        String initial = "I w@nt to encrypT th!s";
        String encrypted = cryptService.crypt(initial);
        String decrypted = cryptService.decrypt(encrypted);

        System.out.println("Initial string:" + initial);
        System.out.println("Encrypted string:" + encrypted);
        System.out.println("Initial string:" + decrypted);
    }
}