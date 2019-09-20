package pkg1;

import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.hibernate.encryptor.HibernatePBEEncryptorRegistry;
import org.jasypt.salt.ZeroSaltGenerator;
import org.jasypt.util.password.StrongPasswordEncryptor;

public class EncryptionService implements IEncryptionService{

    private static int storeSize = 32;
    private static final String KEY = "jasypt";
    private static final String ALGORITHM = "PBEWITHSHA256AND256BITAES-CBC-BC";
    private static EncryptionService _INSTANCE = null;
    private EncryptorStore encryptorStore = null;

    public static EncryptionService getInstance() {
        if (_INSTANCE != null)
            return _INSTANCE;
        synchronized (EncryptionService.class) {
            if (_INSTANCE == null)
                _INSTANCE = new EncryptionService();
        }
        return _INSTANCE;
    }

    private EncryptionService() {
        initialize();
    }

    private void initialize() {
        encryptorStore = new EncryptorStore();
        encryptorStore.initialize();

        StandardPBEStringEncryptor stringEncryptor = new StandardPBEStringEncryptor();
        stringEncryptor.setProvider(new BouncyCastleProvider());
        stringEncryptor.setAlgorithm(ALGORITHM);
        stringEncryptor.setPassword(getKey());

        HibernatePBEEncryptorRegistry registry = HibernatePBEEncryptorRegistry.getInstance();
        registry.registerPBEStringEncryptor(STRING_ENCRYPTOR, stringEncryptor);
    }


    public String generateHash(String password) {
        if (isStringNull(password))
            return null;
        return encryptorStore.getPasswordEncryptor().encryptPassword(password);
    }

    public boolean validateHash(String inputPassword, String encryptedPassword) {
        if (inputPassword == null && encryptedPassword == null)
            return true;
        if (isStringNull(inputPassword) || isStringNull(encryptedPassword)) {
            return false;
        }

        return encryptorStore.getPasswordEncryptor().checkPassword(inputPassword, encryptedPassword);
    }

    public String encrypt(String message) {
        if (isStringNull(message))
            return null;
        return encryptorStore.getStringEncryptor().encrypt(message);
    }

    public String decrypt(String encryptedMessage) {
        if (isStringNull(encryptedMessage))
            return null;
        return encryptorStore.getStringEncryptor().decrypt(encryptedMessage);
    }

    private String getKey() {
        return KEY;
    }

    public String encryptWithZeroSalt(String message) {
        if (isStringNull(message))
            return null;
        return encryptorStore.getZeroSaltStringEncryptor().encrypt(message);
    }

    public static boolean isStringNull(String s) {
        return (s == null || s.trim().length() == 0);
    }

    private class EncryptorStore {

        private StandardPBEStringEncryptor[] stringEncryptors = null;
        private StandardPBEStringEncryptor[] zeroSaltStringEncryptors = null;
        private StrongPasswordEncryptor[] passwordEncryptors = null;

        AtomicInteger index = new AtomicInteger(0);

        private void initialize() {
            stringEncryptors = new StandardPBEStringEncryptor[storeSize];
            zeroSaltStringEncryptors = new StandardPBEStringEncryptor[storeSize];
            passwordEncryptors = new StrongPasswordEncryptor[storeSize];

            for (int i = 0; i < storeSize; i++) {

                stringEncryptors[i] = new StandardPBEStringEncryptor();
                stringEncryptors[i].setProvider(new BouncyCastleProvider());
                stringEncryptors[i].setAlgorithm(ALGORITHM);
                stringEncryptors[i].setPassword(getKey());

                zeroSaltStringEncryptors[i] = new StandardPBEStringEncryptor();
                zeroSaltStringEncryptors[i].setProvider(new BouncyCastleProvider());
                zeroSaltStringEncryptors[i].setSaltGenerator(new ZeroSaltGenerator());
                zeroSaltStringEncryptors[i].setAlgorithm(ALGORITHM);
                zeroSaltStringEncryptors[i].setPassword(getKey());

                passwordEncryptors[i] = new StrongPasswordEncryptor();
            }
        }

        public StandardPBEStringEncryptor getStringEncryptor() {
            return stringEncryptors[getIndex()];
        }

        public StandardPBEStringEncryptor getZeroSaltStringEncryptor() {
            return zeroSaltStringEncryptors[getIndex()];
        }

        public StrongPasswordEncryptor getPasswordEncryptor() {
            return passwordEncryptors[getIndex()];
        }

        private int getIndex() {
            if (index.get() > 10000) {
                index = new AtomicInteger(0);
            }
            return index.incrementAndGet() % storeSize;
        }

    }


}
