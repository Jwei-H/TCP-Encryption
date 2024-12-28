package com.jingwei.encryption;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class DiffieHellmanCrack {
    public static void main(String[] args) {
        BigInteger g = new BigInteger("5");
        List<BigInteger> primeNums = new ArrayList<>();
        primeNums.add(new BigInteger("307"));
        primeNums.add(new BigInteger("1543"));
        primeNums.add(new BigInteger("6151"));
        primeNums.add(new BigInteger("30103"));
        primeNums.add(new BigInteger("88993"));
        primeNums.add(new BigInteger("222289"));
        primeNums.add(new BigInteger("514571"));
        primeNums.add(new BigInteger("1514633"));
        primeNums.add(new BigInteger("7646659"));
        primeNums.add(new BigInteger("35695687"));
        primeNums.add(new BigInteger("715827883"));
        primeNums.add(new BigInteger("2147483647"));
        primeNums.add(new BigInteger("8589934583"));
        primeNums.add(new BigInteger("68719476731"));
        for (BigInteger p : primeNums) {
            BigInteger a = p.divide(new BigInteger("3"));
            BigInteger A = g.modPow(a, p);

            long startTime = System.currentTimeMillis();
            BigInteger sharedKey = bruteForceDiscreteLog(A, g, p);
            long endTime = System.currentTimeMillis();

            if (sharedKey != null) {
                System.out.println("Prime number: " + p);
                System.out.println("Found private key: " + sharedKey);
                System.out.println("Calculation took " + (endTime - startTime) + " milliseconds");
            } else {
                System.out.println("No solution found");
            }
        }
    }

    public static BigInteger bruteForceDiscreteLog(BigInteger A, BigInteger g, BigInteger p) {
        BigInteger x = BigInteger.ZERO;
        BigInteger currentValue = BigInteger.ONE;

        while (x.compareTo(p) < 0) {
            if (currentValue.equals(A)) {
                return x;
            }
            currentValue = currentValue.multiply(g).mod(p);
            x = x.add(BigInteger.ONE);
        }
        return null;
    }
}
