package com.jingwei.encryption;

import com.jingwei.encryption.handler.*;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;

public class TcpServer {
    private final int port;

    public TcpServer(int port) {
        this.port = port;
    }

    public void start() throws InterruptedException {
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .handler(new LoggingHandler(LogLevel.INFO))
                    .childHandler(new ChannelInitializer<SocketChannel>() {
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
                            p.addLast(new RSAHandler.ServerHandler());
                        }
                    });
            ChannelFuture future = b.bind("localhost", port).sync();
            future.channel().closeFuture().sync();
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    public static void main(String[] args) throws InterruptedException {
        new TcpServer(8888).start();
    }

}
