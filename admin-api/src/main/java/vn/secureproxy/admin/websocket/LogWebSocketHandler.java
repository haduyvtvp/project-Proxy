package vn.secureproxy.admin.websocket;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.web.socket.handler.ConcurrentWebSocketSessionDecorator;
import vn.secureproxy.admin.model.LogEntry;
import vn.secureproxy.admin.service.LogService;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@Component
public class LogWebSocketHandler extends TextWebSocketHandler {

    private static final Logger logger = LoggerFactory.getLogger(LogWebSocketHandler.class);

    private final LogService logService;
    private final ObjectMapper objectMapper;
    private final Map<String, Consumer<LogEntry>> subscribers = new ConcurrentHashMap<>();

    public LogWebSocketHandler(LogService logService, ObjectMapper objectMapper) {
        this.logService = logService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        WebSocketSession safeSession =
                new ConcurrentWebSocketSessionDecorator(session, 10_000, 512 * 1024);
        Consumer<LogEntry> subscriber = entry -> sendLog(safeSession, entry);
        subscribers.put(session.getId(), subscriber);
        logService.subscribe(subscriber);
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        unsubscribe(session.getId());
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        logger.warn("WebSocket transport error for session {}", session.getId(), exception);
        unsubscribe(session.getId());
    }

    private void sendLog(WebSocketSession session, LogEntry entry) {
        if (!session.isOpen()) {
            unsubscribe(session.getId());
            return;
        }

        try {
            session.sendMessage(new TextMessage(objectMapper.writeValueAsString(entry)));
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize access log for WebSocket session {}", session.getId(), e);
            closeSession(session);
        } catch (IOException e) {
            logger.warn("Failed to send access log to WebSocket session {}", session.getId(), e);
            closeSession(session);
        } catch (RuntimeException e) {
            logger.warn("WebSocket session {} rejected an access log message", session.getId(), e);
            closeSession(session);
        }
    }

    private void closeSession(WebSocketSession session) {
        unsubscribe(session.getId());
        try {
            if (session.isOpen()) {
                session.close(CloseStatus.SERVER_ERROR);
            }
        } catch (IOException e) {
            logger.warn("Failed to close WebSocket session {}", session.getId(), e);
        }
    }

    private void unsubscribe(String sessionId) {
        Consumer<LogEntry> subscriber = subscribers.remove(sessionId);
        if (subscriber != null) {
            logService.unsubscribe(subscriber);
        }
    }
}
