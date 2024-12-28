package com.jingwei.encryption.handler;

import com.jingwei.encryption.EncryptionManager;
import com.jingwei.encryption.Utils.RC4Util;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.util.ReferenceCountUtil;

import java.util.Arrays;

public class RC4Encryptor extends ChannelOutboundHandlerAdapter {
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
        RC4Util rc4Util = EncryptionManager.getRc4Util();
        if (rc4Util == null) {
            ctx.writeAndFlush(msg, promise);
            return;
        }
        ByteBuf buf = (ByteBuf) msg;
        try {
            byte[] data = new byte[buf.readableBytes()];
            System.out.println(new String(data));
            buf.readBytes(data);
            byte[] encryptData = rc4Util.encrypt(data);
            System.out.println(Arrays.toString(encryptData));
            ByteBuf encryptedBuf = Unpooled.wrappedBuffer(encryptData);
            ctx.writeAndFlush(encryptedBuf, promise);
        } finally {
            ReferenceCountUtil.release(buf);
        }
    }

}