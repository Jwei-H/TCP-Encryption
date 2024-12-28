package com.jingwei.encryption.handler;

import com.jingwei.encryption.EncryptionManager;
import com.jingwei.encryption.Utils.AESUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

public class AESDecryptor extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        AESUtil aesUtil = EncryptionManager.getAesUtil();
        if (aesUtil == null) {
            ctx.fireChannelRead(msg);
            return;
        }
        ByteBuf buf = (ByteBuf) msg;
        try {
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            byte[] decryptData = aesUtil.decrypt(data);
            ByteBuf decryptedBuf = Unpooled.wrappedBuffer(decryptData);
            ctx.fireChannelRead(decryptedBuf);
        } finally {
            ReferenceCountUtil.release(buf);
        }
    }

}
