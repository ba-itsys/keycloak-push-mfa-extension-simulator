package de.arbeitsagentur.pushmfasim.services;

import de.arbeitsagentur.pushmfasim.model.FcmMessageRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Service
public class SseService {
    private final Logger LOG = org.slf4j.LoggerFactory.getLogger(SseService.class);
    // list of SseEmitters could be added here if needed for broadcasting
    private final List<SseEmitter> emitters = new ArrayList<>();

    public void sendMessageToAllEmitters(FcmMessageRequest request) {
        ExecutorService executorService = Executors.newCachedThreadPool();
        executorService.execute(() -> {
            synchronized (emitters) {
                for (SseEmitter emitter : emitters) {
                    try {
                        emitter.send(SseEmitter.event().name("fcm-message").data(request));
                    } catch (IOException e) {
                        LOG.error("Error sending message to emitter: {}", e.getMessage());
                    }
                }
            }
        });
    }

    public SseEmitter createSseEmitter() {
        SseEmitter sseEmitter = new SseEmitter(Long.MAX_VALUE);
        sseEmitter.onCompletion(() -> removeEmitter(sseEmitter));
        sseEmitter.onTimeout(() -> removeEmitter(sseEmitter));
        synchronized (emitters) {
            emitters.add(sseEmitter);
        }

        return sseEmitter;
    }

    private void removeEmitter(SseEmitter emitter) {
        synchronized (emitters) {
            emitters.remove(emitter);
        }
    }
}
