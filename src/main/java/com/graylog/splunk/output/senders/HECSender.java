package com.graylog.splunk.output.senders;

import com.graylog.splunk.output.SplunkHECSenderThread;
import org.graylog2.plugin.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import okhttp3.OkHttpClient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import java.security.cert.CertificateException;


public class HECSender implements Sender {

    private static final Logger LOG = LoggerFactory.getLogger(HECSender.class);
    private static final long HTTP_TIMEOUT = 4000;    // 4 seconds (in MS)

    private final URL url;
    private final String token;
    private final boolean verifySSL;
    private final String sourcetype;
    private final String source;
    private final String index;
    private final BlockingQueue<Message> queue;

    private SplunkHECSenderThread senderThread;
    private boolean initialized = false;

    public HECSender(String url, String token, boolean verifySSL, String index, String sourcetype, String source) throws MalformedURLException {
        this.url = new URL(url);
        this.token = token;
        this.verifySSL = verifySSL;
        this.index = index;
        this.sourcetype = sourcetype;
        this.source = source;
        
        LOG.info("Splunk Output Plugin has been configured with the following HEC parameters:");
        LOG.info("URL: {}", this.url);
        LOG.info("Token: {}", token);
        LOG.info("Verify SSL: {}", verifySSL);
        LOG.info("Index: {}", index);
        LOG.info("Source Type: {}", sourcetype);
        LOG.info("Source: {}", source);
        LOG.info("Default Timeout: {}", HTTP_TIMEOUT);

        this.queue = new LinkedBlockingQueue<>(1024);
    }

    @Override
    public void initialize() {
        this.senderThread = new SplunkHECSenderThread(this.queue);
        this.senderThread.start(getHttpClient(this.verifySSL), this.url, this.token, this.index, this.sourcetype, this.source);
        initialized = true;
    }

    @Override
    public void stop() {
        senderThread.stop();
    }

    @Override
    public void send(Message message) {
        LOG.debug("Sending message: {}", message);
        try {
            queue.put(message);
        } catch (InterruptedException e) { 
            LOG.warn("Interrupted. Message was most probably lost.");
        }
    }

    @Override
    public boolean isInitialized() {
        return initialized;
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

    private OkHttpClient getHttpClient(boolean verifySSL) {
        OkHttpClient.Builder builder = (verifySSL) ? (new OkHttpClient.Builder()) : getUnsafeOkHttpClient();
        return builder
            .connectTimeout(HTTP_TIMEOUT, TimeUnit.MILLISECONDS)
            .readTimeout(HTTP_TIMEOUT, TimeUnit.MILLISECONDS)
            .writeTimeout(HTTP_TIMEOUT, TimeUnit.MILLISECONDS)
            .retryOnConnectionFailure(false)
            .build();
    }

    private OkHttpClient.Builder getUnsafeOkHttpClient() {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                    // Intentionally empty
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                    // Intentionally empty
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[]{};
                }
                }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });

            return builder;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
