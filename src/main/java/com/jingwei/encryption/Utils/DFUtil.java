package com.jingwei.encryption.Utils;

import java.math.BigInteger;

public class DFUtil {
    private BigInteger primeNum;
    private BigInteger primitiveRoot;
    private BigInteger privateSecretKey;

    public DFUtil(BigInteger primeNum, BigInteger primitiveRoot, BigInteger privateSecretKey) {
        this.primeNum = primeNum;
        this.primitiveRoot = primitiveRoot;
        this.privateSecretKey = privateSecretKey;
    }

    public BigInteger generateMyKey() {
        return new BigInteger(primitiveRoot.modPow(privateSecretKey, primeNum).toString());
    }

    public byte[] generateSecretKey(BigInteger otherKey) {
        return otherKey.modPow(privateSecretKey, primeNum).toString().getBytes();
    }
}
