package com.jingwei.encryption.handler;

import com.jingwei.encryption.BaseMessage;
import com.jingwei.encryption.EncryptionManager;
import com.jingwei.encryption.Utils.RSAUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import javax.crypto.KeyGenerator;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSAHandler {

    public static class ServerHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws NoSuchAlgorithmException {
            BaseMessage message = (BaseMessage) msg;
            byte type = message.getType();
            switch (type) {
                case 1:
                    Map<String, String> map = (Map<String, String>) message.getContent();
                    BigInteger modulus = new BigInteger(map.get("modulus"));
                    BigInteger publicKey = new BigInteger(map.get("publicKey"));
                    // 生成对称密钥
                    byte[] secretKey = KeyGenerator.getInstance("AES").generateKey().getEncoded();
                    secretKey = new BigInteger(1, secretKey).toByteArray();
                    byte[] encryptSecretKey = RSAUtil.encrypt(secretKey, publicKey, modulus);
                    ctx.channel().writeAndFlush(new BaseMessage<>((byte) 1, Base64.getEncoder().encodeToString(encryptSecretKey)));
                    System.out.println("密钥交换成功，密钥为：");
                    System.out.println(new String(secretKey));
                    EncryptionManager.init(secretKey);
                    break;
                case 2:
                    System.out.println("收到数据：" + message.getContent());
                    break;
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }

    public static class ClientHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            Map<String, String> map = new HashMap<>();
            map.put("modulus", EncryptionManager.getRsaUtil().getModulus().toString());
            map.put("publicKey", EncryptionManager.getRsaUtil().getPublicKey().toString());
            System.out.println("发送公钥：" + map);
            ctx.channel().writeAndFlush(new BaseMessage<>((byte) 1, map));
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            BaseMessage message = (BaseMessage) msg;
            byte type = message.getType();
            switch (type) {
                case 1:
                    String encodedKey = (String) message.getContent();
                    byte[] encryptSecretKey = Base64.getDecoder().decode(encodedKey);
                    byte[] secretKey = EncryptionManager.getRsaUtil().decrypt(encryptSecretKey);
                    EncryptionManager.init(secretKey);
                    System.out.println("密钥交换成功，密钥为：");
                    System.out.println(new String(secretKey));
                    break;
                case 2:
                    System.out.println("收到数据：" + message.getContent());
                    break;
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }
}