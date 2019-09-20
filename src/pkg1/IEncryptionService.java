package pkg1;

public interface IEncryptionService {

    public static final String ENCRYPTOR_REGISTERED_NAME = "encryptorRegisteredName";

    public static final String STRING_ENCRYPTOR = "HibernateStringEncryptor";

    public static final String ENCRPYT_PASSWORD_PROVIDER = "org.jasypt.hibernate.connectionprovider.EncryptedPasswordC3P0ConnectionProvider";

    public String generateHash(String input);

    public boolean validateHash(String plainInput, String hash);

    public String encrypt(String message);

    public String decrypt(String encryptedMessage);

    public String encryptWithZeroSalt(String message);

}

