package com.jingwei.encryption.handler;

import com.jingwei.encryption.EncryptionManager;
import com.jingwei.encryption.Utils.AESUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.util.ReferenceCountUtil;

import java.util.Arrays;

public class AESEncryptor extends ChannelOutboundHandlerAdapter {
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        AESUtil aesUtil = EncryptionManager.getAesUtil();
        if (aesUtil == null) {
            ctx.writeAndFlush(msg, promise);
            return;
        }
        ByteBuf buf = (ByteBuf) msg;
        try {
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            byte[] encryptData = aesUtil.encrypt(data);
            System.out.println(Arrays.toString(encryptData));
            ByteBuf encryptedBuf = Unpooled.wrappedBuffer(encryptData);
            ctx.writeAndFlush(encryptedBuf, promise);
        } finally {
            ReferenceCountUtil.release(buf);
        }
    }
}