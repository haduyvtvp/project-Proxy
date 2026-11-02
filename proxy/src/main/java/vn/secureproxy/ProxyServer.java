
package vn.secureproxy;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import vn.secureproxy.security.ProxySecurity;
import vn.secureproxy.security.PublicDomainFeedUpdater;

import java.nio.file.Paths;

public class ProxyServer {

    public static void main(String[] args) throws InterruptedException {
        int port = 8888;
        ProxySecurity proxySecurity = ProxySecurity.fromEnvironment();
        String dataDirectory = System.getenv("DATA_DIR");
        if (dataDirectory == null || dataDirectory.isBlank()) {
            dataDirectory = "/data";
        }
        PublicDomainFeedUpdater.start(Paths.get(dataDirectory));

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        try {
            ServerBootstrap bootstrap = new ServerBootstrap();

            bootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            if (!proxySecurity.isTrusted(ch.remoteAddress())) {
                                ch.close();
                                return;
                            }

                            ch.pipeline().addLast(
                                    "httpCodec",
                                    new HttpServerCodec()
                            );

                            ch.pipeline().addLast(
                                    "httpAggregator",
                                    new HttpObjectAggregator(10485760)
                            );

                            ch.pipeline().addLast(
                                    "proxyHandler",
                                    new ProxyHandler(proxySecurity)
                            );
                        }
                    });

            Channel server = bootstrap.bind(port).sync().channel();

            System.out.println(
                    "Secure Proxy dang chay tai cong " + port
                            + "; allowed CIDRs=" + environment(
                                    "PROXY_ALLOWED_CIDRS", "private networks")
                            + "; rate=" + environment(
                                    "PROXY_RATE_LIMIT_PER_MINUTE", "120")
                            + "/minute, burst=" + environment(
                                    "PROXY_RATE_LIMIT_BURST", "30")
            );

            server.closeFuture().sync();

        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }

    private static String environment(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
