package com.jingwei.encryption;

import com.jingwei.encryption.Utils.AESUtil;
import com.jingwei.encryption.Utils.DFUtil;
import com.jingwei.encryption.Utils.RC4Util;
import com.jingwei.encryption.Utils.RSAUtil;

import java.math.BigInteger;
import java.util.Random;

public class EncryptionManager {

    static private AESUtil aesUtil;
    static private RC4Util rc4Util;
    static private DFUtil dfUtil;
    static private RSAUtil rsaUtil;

    static {
        BigInteger primeNum = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628" +
                "B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
                "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637" +
                "ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45" +
                "B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3A" +
                "D961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA23" +
                "7327FFFFFFFFFFFFFFFF", 16);
        BigInteger primitiveRoot = new BigInteger("5");
        BigInteger privateSecretKey = new BigInteger(new Random().nextInt(1000) + "");
        dfUtil = new DFUtil(primeNum, primitiveRoot, privateSecretKey);
        rsaUtil = new RSAUtil();
    }

    public static void init(byte[] key) {
        rc4Util = new RC4Util(key);
        aesUtil = new AESUtil(key);
    }

    public static RC4Util getRc4Util() {
        return rc4Util;
    }

    public static DFUtil getDfUtil() {
        return dfUtil;
    }

    public static RSAUtil getRsaUtil() {
        return rsaUtil;
    }

    public static AESUtil getAesUtil() {
        return aesUtil;
    }
}
