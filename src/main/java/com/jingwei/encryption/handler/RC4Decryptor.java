package com.jingwei.encryption.handler;

import com.jingwei.encryption.EncryptionManager;
import com.jingwei.encryption.Utils.RC4Util;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

import java.util.Arrays;

public class RC4Decryptor extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        RC4Util rc4Util = EncryptionManager.getRc4Util();
        if (rc4Util == null) {
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf buf = (ByteBuf) msg;
        try {
            byte[] data = new byte[buf.readableBytes()];
            System.out.println(Arrays.toString(data));
            buf.readBytes(data);
            byte[] decryptData = rc4Util.decrypt(data);
            System.out.println(new String(decryptData));
            ByteBuf decryptedBuf = Unpooled.wrappedBuffer(decryptData);
            ctx.fireChannelRead(decryptedBuf);
        } finally {
            ReferenceCountUtil.release(buf);
        }
    }

}
