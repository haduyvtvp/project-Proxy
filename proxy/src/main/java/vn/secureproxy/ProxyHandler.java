
package vn.secureproxy;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;

public class ProxyHandler extends ChannelInboundHandlerAdapter {

    private static final NioEventLoopGroup CLIENT_GROUP =
            new NioEventLoopGroup();

    private final PolicyService policy = new PolicyService();

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (!(msg instanceof FullHttpRequest request)) {
            io.netty.util.ReferenceCountUtil.release(msg);
            return;
        }

        String method = request.method().name();

        if ("CONNECT".equalsIgnoreCase(method)) {
            System.out.println("DA NHAN CONNECT: " + request.uri());
            handleConnect(ctx, request);
            return;
        }

        try {
            URI uri = new URI(request.uri());
            String host = uri.getHost();

            if (host == null) {
                String hostHeader =
                        request.headers().get(HttpHeaderNames.HOST);

                if (hostHeader != null) {
                    host = hostHeader.replaceFirst(":\\d+$", "");
                }
            }

            if (host == null || host.isBlank()) {
                reply(ctx, HttpResponseStatus.BAD_REQUEST,
                        "Invalid destination");
                return;
            }

            if (!policy.choPhep(host)) {
                AccessLog.ghiLog(
                        String.valueOf(ctx.channel().remoteAddress()),
                        host, method, "BLOCKED");

                reply(ctx, HttpResponseStatus.FORBIDDEN,
                        "Access denied by Secure Proxy");
                return;
            }

            final String destination = host;
            final int port = uri.getPort() == -1 ? 80 : uri.getPort();

            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }

            if (uri.getRawQuery() != null) {
                path += "?" + uri.getRawQuery();
            }

            FullHttpRequest outbound = new DefaultFullHttpRequest(
                    request.protocolVersion(),
                    request.method(),
                    path,
                    Unpooled.copiedBuffer(request.content()));

            outbound.headers().set(request.headers());
            outbound.headers().set(HttpHeaderNames.HOST, destination);
            outbound.headers().remove(HttpHeaderNames.PROXY_CONNECTION);
            outbound.headers().setInt(
                    HttpHeaderNames.CONTENT_LENGTH,
                    outbound.content().readableBytes());

            AccessLog.ghiLog(
                    String.valueOf(ctx.channel().remoteAddress()),
                    destination, method, "ALLOWED");

            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(CLIENT_GROUP)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(new HttpClientCodec());
                            ch.pipeline().addLast(
                                    new HttpObjectAggregator(10 * 1024 * 1024));

                            ch.pipeline().addLast(
                                    new SimpleChannelInboundHandler<FullHttpResponse>() {
                                        @Override
                                        protected void channelRead0(
                                                ChannelHandlerContext upstream,
                                                FullHttpResponse response) {

                                            FullHttpResponse copy =
                                                    new DefaultFullHttpResponse(
                                                            response.protocolVersion(),
                                                            response.status(),
                                                            response.content().copy());

                                            copy.headers().set(response.headers());
                                            copy.headers().remove(
                                                    HttpHeaderNames.TRANSFER_ENCODING);
                                            copy.headers().setInt(
                                                    HttpHeaderNames.CONTENT_LENGTH,
                                                    copy.content().readableBytes());

                                            ctx.writeAndFlush(copy)
                                                    .addListener(
                                                            ChannelFutureListener.CLOSE);
                                        }

                                        @Override
                                        public void exceptionCaught(
                                                ChannelHandlerContext upstream,
                                                Throwable cause) {
                                            System.err.println(
                                                    "HTTP upstream error: "
                                                            + cause.getMessage());
                                            upstream.close();

                                            if (ctx.channel().isActive()) {
                                                reply(ctx,
                                                        HttpResponseStatus.BAD_GATEWAY,
                                                        "Upstream request failed");
                                            }
                                        }
                                    });
                        }
                    });

            bootstrap.connect(destination, port).addListener(
                    (ChannelFutureListener) future -> {
                        if (future.isSuccess()) {
                            future.channel().writeAndFlush(outbound)
                                    .addListener(result -> {
                                        if (!result.isSuccess()) {
                                            future.channel().close();

                                            if (ctx.channel().isActive()) {
                                                reply(ctx,
                                                        HttpResponseStatus.BAD_GATEWAY,
                                                        "Could not forward request");
                                            }
                                        }
                                    });
                        } else {
                            outbound.release();

                            System.err.println(
                                    "HTTP connect error: "
                                            + future.cause().getMessage());

                            reply(ctx, HttpResponseStatus.BAD_GATEWAY,
                                    "Could not connect to destination");
                        }
                    });

        } catch (Exception e) {
            System.err.println("HTTP request error: " + e.getMessage());
            reply(ctx, HttpResponseStatus.BAD_REQUEST,
                    "Invalid HTTP request");
        }
    }

    private void handleConnect(
            ChannelHandlerContext ctx, FullHttpRequest request) {

        String target = request.uri();
        String host = target;
        int port = 443;

        int colon = target.lastIndexOf(':');

        if (colon > 0) {
            host = target.substring(0, colon);

            try {
                port = Integer.parseInt(target.substring(colon + 1));
            } catch (NumberFormatException e) {
                reply(ctx, HttpResponseStatus.BAD_REQUEST,
                        "Invalid CONNECT port");
                return;
            }
        }

        if (host.isBlank() || port < 1 || port > 65535) {
            reply(ctx, HttpResponseStatus.BAD_REQUEST,
                    "Invalid CONNECT destination");
            return;
        }

        if (!policy.choPhep(host)) {
            AccessLog.ghiLog(
                    String.valueOf(ctx.channel().remoteAddress()),
                    host, "CONNECT", "BLOCKED");

            reply(ctx, HttpResponseStatus.FORBIDDEN,
                    "Access denied by Secure Proxy");
            return;
        }

        final String destination = host;
        final int destinationPort = port;

        System.out.println(
                "DANG KET NOI HTTPS: " + destination + ":" + destinationPort);

        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(CLIENT_GROUP)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        // Khong them HTTP codec: HTTPS duoc chuyen tiep nguyen ban.
                    }
                });

        bootstrap.connect(destination, destinationPort).addListener(
                (ChannelFutureListener) future -> {

                    if (!future.isSuccess()) {
                        Throwable cause = future.cause();

                        System.err.println(
                                "HTTPS CONNECT THAT BAI: "
                                        + destination + ":"
                                        + destinationPort + " - "
                                        + (cause == null
                                        ? "Unknown error"
                                        : cause.getMessage()));

                        AccessLog.ghiLog(
                                String.valueOf(ctx.channel().remoteAddress()),
                                destination, "CONNECT", "ERROR");

                        reply(ctx, HttpResponseStatus.BAD_GATEWAY,
                                "Could not connect to HTTPS destination");
                        return;
                    }

                    System.out.println(
                            "HTTPS CONNECT THANH CONG: "
                                    + destination + ":" + destinationPort);

                    Channel upstream = future.channel();

                    FullHttpResponse connected = new DefaultFullHttpResponse(
                            HttpVersion.HTTP_1_1,
                            HttpResponseStatus.OK);

                    ctx.writeAndFlush(connected).addListener(result -> {

                        if (!result.isSuccess()) {
                            upstream.close();
                            ctx.close();
                            return;
                        }

                        AccessLog.ghiLog(
                                String.valueOf(ctx.channel().remoteAddress()),
                                destination, "CONNECT", "ALLOWED");

                        ChannelPipeline clientPipeline = ctx.pipeline();

                        try {
                            if (clientPipeline.get("httpAggregator") != null) {
                                clientPipeline.remove("httpAggregator");
                            }

                            if (clientPipeline.get("httpCodec") != null) {
                                clientPipeline.remove("httpCodec");
                            }

                            if (clientPipeline.get("proxyHandler") != null) {
                                clientPipeline.remove("proxyHandler");
                            }

                            ctx.channel().config().setAutoRead(false);
                            upstream.config().setAutoRead(false);

                            ctx.channel().pipeline().addLast(
                                    "clientRelay", new RelayHandler(upstream));

                            upstream.pipeline().addLast(
                                    "upstreamRelay",
                                    new RelayHandler(ctx.channel()));

                            ctx.channel().config().setAutoRead(true);
                            upstream.config().setAutoRead(true);

                            ctx.read();
                            upstream.read();

                        } catch (Exception e) {
                            System.err.println(
                                    "HTTPS relay setup error: " + e.getMessage());
                            upstream.close();
                            ctx.close();
                        }
                    });
                });
    }

    private static class RelayHandler extends ChannelInboundHandlerAdapter {

        private final Channel peer;

        RelayHandler(Channel peer) {
            this.peer = peer;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            if (peer.isActive()) {
                peer.writeAndFlush(msg).addListener(result -> {
                    if (!result.isSuccess()) {
                        peer.close();
                        ctx.close();
                    }
                });
            } else {
                io.netty.util.ReferenceCountUtil.release(msg);
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            if (peer.isActive()) {
                peer.close();
            }
        }

        @Override
        public void exceptionCaught(
                ChannelHandlerContext ctx, Throwable cause) {
            System.err.println(
                    "Relay error: " + cause.getMessage());
            ctx.close();
            peer.close();
        }
    }

    private void reply(
            ChannelHandlerContext ctx,
            HttpResponseStatus status,
            String message) {

        if (!ctx.channel().isActive()) {
            return;
        }

        byte[] body = message.getBytes(StandardCharsets.UTF_8);

        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1,
                status,
                Unpooled.wrappedBuffer(body));

        response.headers().set(
                HttpHeaderNames.CONTENT_TYPE,
                "text/plain; charset=UTF-8");

        response.headers().setInt(
                HttpHeaderNames.CONTENT_LENGTH,
                body.length);

        ctx.writeAndFlush(response)
                .addListener(ChannelFutureListener.CLOSE);
    }

    @Override
    public void exceptionCaught(
            ChannelHandlerContext ctx, Throwable cause) {
        System.err.println(
                "Proxy error: " + cause.getMessage());
        ctx.close();
    }
}
