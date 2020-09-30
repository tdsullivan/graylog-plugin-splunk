package com.graylog.splunk.output.senders;

import org.junit.jupiter.api.Test;
import org.graylog2.plugin.Message;
import org.joda.time.DateTime;
import java.net.MalformedURLException;

// import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestHECSender {

    @Test
    public void testSend() throws MalformedURLException {
        Sender sender = new HECSender(
            "https://localhost:8088/services/collector",
            "87e1bffe-9d89-4add-b163-1ec3494b8937",
            false,
            "main",
            "app:fie:fie",
            "fie"
        );

        for (int i = 1; i < 101; i++) {
            if(!sender.isInitialized()) {
                sender.initialize();
            }
            sender.send(new Message("EA Graylog Test "+i, "EA Graylog Test "+i, new DateTime()));
        }
        
        sender.stop();
    }
}