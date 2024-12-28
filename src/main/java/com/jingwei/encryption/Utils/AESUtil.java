package com.jingwei.encryption.Utils;


public class AESUtil {
    private final int BLOCK_SIZE = 4;
    private final int KEY_LENGTH = 4;// 秘钥长度
    private final int NUM_ROUNDS = 10;// 变化轮次
    private final byte[] KEY;// 秘钥
    private final byte[][] ROUND_KEYS;// 轮密钥表
    private final byte[][] INV_ROUND_KEYS;// 反向轮密钥表
    /*
     * rcon常数表参考自http://msdn.microsoft.com/zh-cn/magazine/cc164055(en-us).aspx#S3
     */
    // 轮常量表
    private final byte[][] RCON = {{0x00, 0x00, 0x00, 0x00},
            {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00}, {(byte) 0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00}};

    /* s盒，16×16的矩阵 */
    private final static byte[][] SBOX = {
            {0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5,
                    0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7,
                    (byte) 0xab, 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa,
                    0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4,
                    (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4,
                    0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f,
                    (byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5,
                    (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15},
            {0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96,
                    0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80,
                    (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75},
            {0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0,
                    0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29,
                    (byte) 0xe3, 0x2f, (byte) 0x84},
            {0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc,
                    (byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe,
                    0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43,
                    0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f,
                    0x50, 0x3c, (byte) 0x9f, (byte) 0xa8},
            {0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92,
                    (byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc,
                    (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff,
                    (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97,
                    0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64,
                    0x5d, 0x19, 0x73},
            {0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a,
                    (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee,
                    (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb},
            {(byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
                    (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62,
                    (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79},
            {(byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d,
                    (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56,
                    (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08},
            {(byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6,
                    (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd,
                    0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e,
                    0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86,
                    (byte) 0xc1, 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69,
                    (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b,
                    0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55,
                    0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf,
                    (byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f,
                    (byte) 0xb0, 0x54, (byte) 0xbb, 0x16}};
    /* 逆s盒 */
    private final static byte[][] INV_SBOX = {
            {0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38,
                    (byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e,
                    (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
            {0x7c, (byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f,
                    (byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43,
                    0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9,
                    (byte) 0xcb},
            {0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2,
                    0x23, 0x3d, (byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42,
                    (byte) 0xfa, (byte) 0xc3, 0x4e},
            {0x08, 0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24,
                    (byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d,
                    (byte) 0x8b, (byte) 0xd1, 0x25},
            {0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68,
                    (byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c,
                    (byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92},
            {0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed,
                    (byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57,
                    (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
            {(byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c,
                    (byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7,
                    (byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3,
                    0x45, 0x06},
            {(byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f, (byte) 0xca, 0x3f,
                    0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd,
                    0x03, 0x01, 0x13, (byte) 0x8a, 0x6b},
            {0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc,
                    (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf,
                    (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6,
                    0x73},
            {(byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7,
                    (byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2,
                    (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75,
                    (byte) 0xdf, 0x6e},
            {0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5,
                    (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e,
                    (byte) 0xaa, 0x18, (byte) 0xbe, 0x1b},
            {(byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2,
                    0x79, 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0,
                    (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4},
            {0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88, 0x07,
                    (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27,
                    (byte) 0x80, (byte) 0xec, 0x5f},
            {0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d,
                    0x2d, (byte) 0xe5, 0x7a, (byte) 0x9f, (byte) 0x93,
                    (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
            {(byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a,
                    (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb,
                    (byte) 0xbb, 0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26,
                    (byte) 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

    public AESUtil(byte[] key) {
        if (key.length > 16) {
            // 如果密钥长度超过128位（16字节），则取前128位
            this.KEY = new byte[16];
            System.arraycopy(key, 0, this.KEY, 0, 16);
        } else if (key.length == 16) {
            this.KEY = key;
        } else {
            throw new IllegalArgumentException("Key length must be 128 bits (16 bytes)");
        }
        ROUND_KEYS = new byte[BLOCK_SIZE * (NUM_ROUNDS + 1)][4];
        INV_ROUND_KEYS = new byte[BLOCK_SIZE * (NUM_ROUNDS + 1)][4];
        keyExpansion();
    }

    /*
     * 取自google xtime() function, used for multiplication by x. This takes byte
     * b, performs a left shift on it, and a conditional XOR with 0x1b. The XOR
     * is necessary to reduce the polynomial if b7 is equal to one. In other
     * words, if b & 0x80 is set.
     * xtime 方法用于执行字节的有限域乘法操作
     */
    static private byte xtime(byte b) {
        if ((b & (byte) 0x80) != 0)
            return (byte) ((b << 1) ^ 0x1b);
        return (byte) (b << 1);
    }

    /*
     * 通过s盒的转换得到state的新替代值
     */
    private void subBytes(byte[][] state) {
        for (int i = 0; i < KEY_LENGTH; i++) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                state[i][j] = SBOX[(state[i][j] & 0xff) >> 4][state[i][j] & 0x0f];
            }
        }
    }

    /*
     * 取自google Byte Multiplication by x. Invokes xtime in a loop and adds the
     * results using XOR.
     * multx 方法在有限域 ( GF(2^8) ) 中执行多项式乘法
     */
    private static byte multx(byte b, byte x) {
        byte prod = 0, shift = 1, xt = b;
        do {
            if ((x & shift) != 0)
                prod ^= xt;
            xt = xtime(xt);
            shift <<= 1;
        } while (shift != 0
                && ((int) shift & 0x000000ff) <= ((int) x & 0x0000000ff));
        return prod;
    }

    /*
     *
     * 行位移变换,第一行不受影响，其实是旋转了0列，其他行row+1，左移的col+1，例如第2行左移1列
     */
    private void shiftRows(byte[][] state) {
        byte[][] tmp = new byte[KEY_LENGTH][BLOCK_SIZE];
        for (int i = 0; i < KEY_LENGTH; i++)
            System.arraycopy(state[i], 0, tmp[i], 0, BLOCK_SIZE);
        for (int row = 1; row < BLOCK_SIZE; row++)
            for (int col = 0; col < BLOCK_SIZE; col++)
                state[row][col] = tmp[row][(col + row) % BLOCK_SIZE];
    }

    /*
     * 列混合变换，一种基于有限域的加法和乘法，是AES最精妙的部分，详情请google
     */
    private void mixColumns(byte[][] state) {
        byte[][] tmp = new byte[KEY_LENGTH][BLOCK_SIZE];

        for (int i = 0; i < KEY_LENGTH; i++) {
            System.arraycopy(state[i], 0, tmp[i], 0, BLOCK_SIZE);
        }
        for (int i = 0; i < BLOCK_SIZE; i++) {
            for (int j = 0; j < KEY_LENGTH; j++) {
                state[j][i] = (byte) (multx((byte) 0x02, tmp[j][i])
                        ^ multx((byte) 0x03, tmp[(j + 1) % 4][i])
                        ^ tmp[(j + 2) % 4][i]
                        ^ tmp[(j + 3) % 4][i]);
            }
        }
    }

    /*
     * 轮秘钥转换，用秘钥调度表w对state实行一个xor操作例如w[c,r] xor State[r,c]。
     */
    private void addRoundKey(byte[][] state, byte[][] words, int start) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            for (int j = 0; j < KEY_LENGTH; j++) {
                state[j][i] ^= words[start + i][j];
            }
        }
    }

    /*
     * 将w通过s盒进行替换
     */

    /*
     * 将w左移，与ShiftRows操作类似
     */
    private byte[] rotWord(byte[] word) {
        byte holder = word[0];
        for (int i = 0; i < 3; i++)
            word[i] = word[i + 1];
        word[3] = holder;
        return word;
    }

    private void invShiftRows(byte[][] state) {
        byte[][] tmp = new byte[KEY_LENGTH][BLOCK_SIZE];

        for (int i = 0; i < KEY_LENGTH; i++)
            System.arraycopy(state[i], 0, tmp[i], 0, BLOCK_SIZE);

        // 进行列的右移
        for (int row = 1; row < BLOCK_SIZE; row++)
            for (int col = 0; col < BLOCK_SIZE; col++)
                state[row][(col + row) % BLOCK_SIZE] = tmp[row][col];
    }

    private void invMixColumns(byte[][] state) {
        byte[][] tmp = new byte[KEY_LENGTH][BLOCK_SIZE];
        for (int i = 0; i < KEY_LENGTH; i++) {
            System.arraycopy(state[i], 0, tmp[i], 0, BLOCK_SIZE);
        }
        for (int i = 0; i < KEY_LENGTH; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = (byte) (multx((byte) 0x0e, tmp[j][i])
                        ^ multx((byte) 0x0b, tmp[(j + 1) % 4][i])
                        ^ multx((byte) 0x0d, tmp[(j + 2) % 4][i])
                        ^ multx((byte) 0x09, tmp[(j + 3) % 4][i]));
            }
        }
    }

    private void invSubBytes(byte[][] state) {
        for (int i = 0; i < KEY_LENGTH; i++) {
            for (int j = 0; j < BLOCK_SIZE; j++) {
                state[i][j] = INV_SBOX[(state[i][j] & 0xff) >> 4][state[i][j] & 0x0f];
            }
        }
    }

    /*
     * 创建秘钥调度表，用以从旧的秘钥转换成新的秘钥
     */
    private void keyExpansion() {
        byte[] temp = new byte[4];

        for (int i = 0; i < KEY_LENGTH; i++) {
            ROUND_KEYS[i][0] = KEY[4 * i];
            ROUND_KEYS[i][1] = KEY[4 * i + 1];
            ROUND_KEYS[i][2] = KEY[4 * i + 2];
            ROUND_KEYS[i][3] = KEY[4 * i + 3];
        }

        // 生成剩余的轮密钥
        for (int i = KEY_LENGTH; i < (BLOCK_SIZE * (NUM_ROUNDS + 1)); i++) {
            System.arraycopy(ROUND_KEYS[i - 1], 0, temp, 0, 4);
            if ((i % KEY_LENGTH) == 0) {
                // 每 KEY_LENGTH 个字进行一次特殊处理
                byte[] word = rotWord(temp); // 轮转字
                for (int j = 0; j < 4; j++) {
                    word[j] = SBOX[(word[j] & 0xff) >> 4][word[j] & 0x0f]; // S 盒替换
                }
                temp[0] ^= RCON[i / KEY_LENGTH][0]; // 与轮常量异或
            }
            for (int x = 0; x < 4; x++)
                ROUND_KEYS[i][x] = (byte) (ROUND_KEYS[i - KEY_LENGTH][x] ^ temp[x]);
        }
        // 复制轮密钥到反向轮密钥表
        for (int i = 0; i < (NUM_ROUNDS + 1) * BLOCK_SIZE; i++) {
            System.arraycopy(ROUND_KEYS[i], 0, INV_ROUND_KEYS[i], 0, ROUND_KEYS[i].length);
        }
    }

    private void cipher(byte[][] state) {
        addRoundKey(state, ROUND_KEYS, 0);
        for (int round = 1; round < NUM_ROUNDS; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, ROUND_KEYS, round * BLOCK_SIZE);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, ROUND_KEYS, NUM_ROUNDS * BLOCK_SIZE);
    }

    public void invCipher(byte[][] state) {
        addRoundKey(state, INV_ROUND_KEYS, NUM_ROUNDS * BLOCK_SIZE);
        for (int round = NUM_ROUNDS - 1; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, INV_ROUND_KEYS, round * BLOCK_SIZE);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, INV_ROUND_KEYS, 0);
    }

    public byte[] encrypt(byte[] plaintext) {
        int blockSize = BLOCK_SIZE * KEY_LENGTH;
        int numBlocks = (plaintext.length + blockSize - 1) / blockSize;
        byte[] ciphertext = new byte[numBlocks * blockSize];
        int paddingLength = BLOCK_SIZE * KEY_LENGTH - (plaintext.length % (BLOCK_SIZE * KEY_LENGTH));

        for (int block = 0; block < numBlocks; block++) {
            byte[][] state = new byte[KEY_LENGTH][BLOCK_SIZE];
            int offset = block * blockSize;
            for (int i = 0; i < KEY_LENGTH; i++) {
                for (int j = 0; j < BLOCK_SIZE; j++) {
                    int index = offset + 4 * i + j;
                    state[i][j] = (index < plaintext.length) ? plaintext[index] : (byte) paddingLength;
                }
            }
            cipher(state);
            for (int i = 0; i < KEY_LENGTH; i++) {
                System.arraycopy(state[i], 0, ciphertext, offset + 4 * i, BLOCK_SIZE);
            }
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        int blockSize = BLOCK_SIZE * KEY_LENGTH;
        int numBlocks = ciphertext.length / blockSize;
        byte[] plaintext = new byte[ciphertext.length];

        for (int block = 0; block < numBlocks; block++) {
            byte[][] state = new byte[KEY_LENGTH][BLOCK_SIZE];
            int offset = block * blockSize;
            for (int i = 0; i < KEY_LENGTH; i++) {
                System.arraycopy(ciphertext, offset + 4 * i, state[i], 0, BLOCK_SIZE);
            }
            invCipher(state);
            for (int i = 0; i < KEY_LENGTH; i++) {
                System.arraycopy(state[i], 0, plaintext, offset + 4 * i, BLOCK_SIZE);
            }
        }
        // 去除填充字符
        int paddingLength = plaintext[plaintext.length - 1] & 0xFF;
        byte[] unpaddedPlaintext = new byte[plaintext.length - paddingLength];
        System.arraycopy(plaintext, 0, unpaddedPlaintext, 0, unpaddedPlaintext.length);

        return unpaddedPlaintext;
    }

}