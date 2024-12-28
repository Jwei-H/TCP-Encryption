package com.jingwei.encryption.handler;

import com.alibaba.fastjson.JSON;
import com.jingwei.encryption.BaseMessage;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.MessageToByteEncoder;

import java.util.List;

public class JsonCodec {

    public static class Encoder extends MessageToByteEncoder<BaseMessage> {
        @Override
        protected void encode(ChannelHandlerContext ctx, BaseMessage msg, ByteBuf out) {
            byte[] data = JSON.toJSONBytes(msg);
            out.writeInt(data.length);
            out.writeBytes(data);
        }
    }

    public static class Decoder extends ByteToMessageDecoder {
        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
            if (in.readableBytes() < 4) {
                return;
            }
            in.markReaderIndex();
            int length = in.readInt();
            if (in.readableBytes() < length) {
                in.resetReaderIndex();
                return;
            }
            byte[] data = new byte[length];
            in.readBytes(data);
            BaseMessage msg = JSON.parseObject(data, BaseMessage.class);
            out.add(msg);
        }
    }
}