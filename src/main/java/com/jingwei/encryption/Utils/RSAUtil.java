package com.jingwei.encryption.Utils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAUtil {

    private BigInteger n, d, e;

    private final int bitLength = 2048;

    public RSAUtil() {
        // 选择两个大素数 p 和 q
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);

        // 计算 Φ(n) = (p-1)*(q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // 选择 e，保证 e 和 Φ(n) 互质
        e = BigInteger.probablePrime(bitLength / 2, random);

        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e.add(BigInteger.ONE);
        }

        // 计算 d 使得 d * e ≡ 1 (mod phi)
        d = e.modInverse(phi);
    }

    public byte[] encrypt(byte[] message) {
        return new BigInteger(1, message).modPow(e, n).toByteArray();
    }

    public byte[] decrypt(byte[] encrypted) {
        return new BigInteger(1, encrypted).modPow(d, n).toByteArray();
    }

    public static byte[] encrypt(byte[] message, BigInteger e, BigInteger n) {
        return new BigInteger(1, message).modPow(e, n).toByteArray();
    }


    public BigInteger getPublicKey() {
        return e;
    }

    public BigInteger getPrivateKey() {
        return d;
    }

    public BigInteger getModulus() {
        return n;
    }


}
