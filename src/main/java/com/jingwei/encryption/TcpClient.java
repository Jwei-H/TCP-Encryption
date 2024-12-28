package com.jingwei.encryption;

import com.jingwei.encryption.handler.*;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

public class TcpClient {
    private final String host;
    private final int port;

    public TcpClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void start() throws InterruptedException {
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();
//                            p.addLast(new RC4Decryptor());
//                            p.addLast(new RC4Encryptor());
                            p.addLast(new AESDecryptor());
                            p.addLast(new AESEncryptor());
                            p.addLast(new JsonCodec.Decoder());
                            p.addLast(new JsonCodec.Encoder());
//                            p.addLast(new DFHandler());
                            p.addLast(new RSAHandler.ClientHandler());
                        }
                    });
            ChannelFuture f = b.connect(host, port).sync();
            Channel channel = f.channel();
            while (true) {
                BaseMessage msg = new BaseMessage((byte) 2, "Hello, world! " + System.currentTimeMillis());
                channel.writeAndFlush(msg);
                Thread.sleep(2000);
            }
            //channel.closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }

    public static void main(String[] args) throws InterruptedException {
        new TcpClient("localhost", 8888).start();
    }

}
