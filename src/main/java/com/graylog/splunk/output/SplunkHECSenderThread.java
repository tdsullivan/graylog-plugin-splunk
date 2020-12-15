/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.graylog.splunk.output;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.graylog2.plugin.Message;

public class SplunkHECSenderThread {
    private static final int MAX_BATCH_ITEMS = 1000;    // Log messages
    private static final long MAX_BATCH_WAIT = 2000;    // 2 seconds (in MS)
    // private static final long MAX_BATCH_BYTES = 500000; // HEC limit is likely somewhere from 512KB to 1024KB. Using 500KB, to be safe.

    private static final Logger LOG = LoggerFactory.getLogger(SplunkHECSenderThread.class);
    private final AtomicBoolean keepRunning = new AtomicBoolean(true);
    private final Thread senderThread;
    private URL url;
    private String token;
    private String sourcetype;
    private String source;
    private String index;
    private OkHttpClient httpClient;

    public SplunkHECSenderThread(final BlockingQueue<Message> queue) {
        this.senderThread = new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Message> messages = new ArrayList<>();
                long batchStartTime = System.currentTimeMillis();

                while (keepRunning.get()) {
                    long pollTimeout = MAX_BATCH_WAIT - (System.currentTimeMillis() - batchStartTime);
                    if (pollTimeout > 0) {
                        try {
                            Message message = queue.poll(pollTimeout, TimeUnit.MILLISECONDS);
                            if (message != null) {
                                messages.add(message);
                                // If the poll attempt was able to get a message,
                                // and the batch has not reached the max batch size,
                                // try to fill batch with other available messages.
                                if (messages.size() < MAX_BATCH_ITEMS) {
                                    queue.drainTo(messages, MAX_BATCH_ITEMS - messages.size());
                                }
                            }
                        } catch (InterruptedException e) {
                            // ignore, when stopping keepRunning will be set to false outside
                            LOG.info("{}: Received InterruptedException in SplunkHECSenderThread: {}", senderThread.getName(), e.getMessage());
                        }
                    }

                    // Check if it is time to send batch to splunk
                    if (messages.size() >= MAX_BATCH_ITEMS || (System.currentTimeMillis() - batchStartTime) > MAX_BATCH_WAIT) {
                        if (messages.isEmpty()) {
                            batchStartTime = System.currentTimeMillis();
                        } else {
                            try {
                                String requestBody = "";
                                for (Message message : messages) {
                                    requestBody += getHECPayloadFromMessage(message) + "\n";
                                }
                                LOG.info("{}: Sending {} message(s), with a payload size of {} bytes, to splunk", senderThread.getName(), messages.size(), requestBody.getBytes(StandardCharsets.UTF_8).length);
                                sendToHEC(requestBody);
                                messages.clear();
                                batchStartTime = System.currentTimeMillis();
                            } catch (HttpOutputException e) {
                                LOG.info("{}: Call to Splunk HEC endpoint failed! Log messages likely lost.", senderThread.getName());
                                messages.clear();
                                batchStartTime = System.currentTimeMillis();
                            }
                        }
                    }
                }
                messages.clear();
                LOG.debug("{}: exiting!", senderThread.getName());
            }
        });
        this.senderThread.setName("SplunkHECSenderThread-" + senderThread.getId());
    }

    public void start(OkHttpClient httpClient, URL url, String token, String index, String sourcetype, String source) {
        this.httpClient = httpClient;
        this.url = url;
        this.token = token;
        this.index = index;
        this.sourcetype = sourcetype;
        this.source = source;

        keepRunning.set(true);
        senderThread.start();
    }

    public void stop() {
        keepRunning.set(false);
        senderThread.interrupt();
    }

    public String getHECPayloadFromMessage(Message message) {
        final Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ").create();
        Map<String, Object> hecMessage  = new HashMap<String, Object>();
        hecMessage.put("time", message.getTimestamp().toDate().getTime());
        hecMessage.put("host", message.getSource());
        hecMessage.put("source", this.source);
        hecMessage.put("sourcetype", this.sourcetype);
        hecMessage.put("index", this.index);
        hecMessage.put("event", message.getMessage());

        Map<String, Object> fields = new HashMap<String, Object>();
        for (Map.Entry<String, Object> field : message.getFields().entrySet()) {
            if (Message.RESERVED_FIELDS.contains(field.getKey()) || field.getKey().equals(Message.FIELD_STREAMS)) {
                continue;
            }
            fields.put(field.getKey(), field.getValue());
        }
        hecMessage.put("fields", fields);
        return gson.toJson(hecMessage);
    }

    public void sendToHEC(String jsonBody) throws HttpOutputException {
        try {
            final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

            RequestBody body = RequestBody.create(JSON, jsonBody);
            Request request = new Request.Builder().url(this.url).post(body).header("Authorization", "Splunk " + this.token).build();
            Response response = this.httpClient.newCall(request).execute();
            response.close();
            if (response.code() != 200) {
                throw new HttpOutputException("Unexpected HTTP response status " + response.code());
            }
        } catch (IOException e) {
            throw new HttpOutputException("Error while posting stream to HEC endpoint: "+e.toString(), e);
        }
    }

    public class HttpOutputException extends Exception {

        private static final long serialVersionUID = -5301266791901423492L;

        public HttpOutputException(String msg) {
            super(msg);
        }

        public HttpOutputException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }
}
