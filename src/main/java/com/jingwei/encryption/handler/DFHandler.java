package com.jingwei.encryption.handler;

import com.jingwei.encryption.BaseMessage;
import com.jingwei.encryption.EncryptionManager;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class DFHandler extends ChannelInboundHandlerAdapter {
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        BaseMessage message = (BaseMessage) msg;
        byte type = message.getType();
        switch (type) {
            case 1:
                BigInteger otherKey = new BigInteger(String.valueOf(message.getContent()));
                byte[] secretKey = EncryptionManager.getDfUtil().generateSecretKey(otherKey);
                EncryptionManager.init(secretKey);
                System.out.println("密钥交换成功，密钥为：");
                System.out.println(new String(secretKey, StandardCharsets.UTF_8));
                break;
            case 2:
                System.out.println("收到数据：" + message.getContent());
                break;
        }
    }

    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }

    public void channelActive(ChannelHandlerContext ctx) {
        ctx.channel().writeAndFlush(new BaseMessage<>((byte) 1, EncryptionManager.getDfUtil().generateMyKey().toString()));
    }
}
