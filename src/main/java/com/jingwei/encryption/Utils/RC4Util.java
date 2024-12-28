package com.jingwei.encryption.Utils;

public class RC4Util {
    static private int[] rc4Vector;

    public RC4Util(byte[] key) {
        rc4Vector = new int[256];
        for (int i = 0; i < 256; i++) {
            rc4Vector[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + rc4Vector[i] + (key[i % key.length] & 0xFF)) % 256;
            int temp = rc4Vector[i];
            rc4Vector[i] = rc4Vector[j];
            rc4Vector[j] = temp;
        }
    }

    public byte[] encrypt(byte[] data) {
        int[] S = rc4Vector.clone();
        int i = 0, j = 0;
        byte[] result = new byte[data.length];
        for (int k = 0; k < data.length; k++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;
            int t = (S[i] + S[j]) % 256;
            int K = S[t];
            result[k] = (byte) (data[k] ^ K);
        }
        return result;
    }

    public byte[] decrypt(byte[] data) {
        int[] S = rc4Vector.clone();
        int i = 0, j = 0;
        byte[] result = new byte[data.length];
        for (int k = 0; k < data.length; k++) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            int temp = S[i];
            S[i] = S[j];
            S[j] = temp;
            int t = (S[i] + S[j]) % 256;
            int K = S[t];
            result[k] = (byte) (data[k] ^ K);
        }
        return result;
    }
}
