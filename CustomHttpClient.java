
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author m_kor
 * date 12/24/2023
 */
public class CustomHttpClient {
    private Log log = LogFactory.getLog(this.getClass());

    private String truststoreAddr;
    private String truststorePw;
    private String keystoreAddr;
    private String keystorePW;
    private String tlsVersion = "TLSv1.2";

    public CloseableHttpClient getHttpClient() throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        X509TrustManager jreTrustManager = getJreTrustManager();
        X509TrustManager myTrustManager = getMyTrustManager();
        KeyManager[] keyManagers = getKeyManagers();
        X509TrustManager mergedTrustManager = createMergedTrustManager(jreTrustManager, myTrustManager);
        SSLContext sslContext = getSslContext(mergedTrustManager, keyManagers);
        CloseableHttpClient httpClient = createHttpClient(sslContext);
        return httpClient;
    }


    private X509TrustManager getJreTrustManager() throws NoSuchAlgorithmException, KeyStoreException {
        return findDefaultTrustManager(null);
    }

    private X509TrustManager getMyTrustManager() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        // Adapt to load your keystore
        try (FileInputStream myKeys = new FileInputStream(truststoreAddr)) {
            KeyStore myTrustStore = KeyStore.getInstance("jks");
            myTrustStore.load(myKeys, truststorePw.toCharArray());
            return findDefaultTrustManager(myTrustStore);
        }
    }

    private X509TrustManager findDefaultTrustManager(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore); // If keyStore is null, tmf will be initialized with the default trust store

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        return null;
    }

    private X509TrustManager createMergedTrustManager(X509TrustManager jreTrustManager, X509TrustManager customTrustManager) {
        return new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                // If you're planning to use client-cert auth,
                // merge results from "defaultTm" and "myTm".
                return jreTrustManager.getAcceptedIssuers();
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                try {
                    customTrustManager.checkServerTrusted(chain, authType);
                } catch (CertificateException e) {
                    // This will throw another CertificateException if this fails too.
                    jreTrustManager.checkServerTrusted(chain, authType);
                }
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                // If you're planning to use client-cert auth,
                // do the same as checking the server.
                jreTrustManager.checkClientTrusted(chain, authType);
            }

        };
    }

    private KeyManager[] getKeyManagers() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream in = new FileInputStream(keystoreAddr);
        keyStore.load(in, keystorePW.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keystorePW.toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private SSLContext getSslContext(X509TrustManager mergedTrustManager, KeyManager[] keyManagers) throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance(tlsVersion);
        sslContext.init(keyManagers, new TrustManager[] { mergedTrustManager }, null);

        // You don't have to set this as the default context,
        // it depends on the library you're using.
        return sslContext;
    }

    private CloseableHttpClient createHttpClient(SSLContext sslContext) {
        SSLConnectionSocketFactory sslSocketFactory = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(sslContext)
                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();

        HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(sslSocketFactory)
                .build();

        return HttpClients.custom()
                .setConnectionManager(cm)
                .evictExpiredConnections()
                .build();
    }

    public void setTruststoreAddr(String truststoreAddr) {
        this.truststoreAddr = truststoreAddr;
    }

    public void setTruststorePw(String truststorePw) {
        this.truststorePw = truststorePw;
    }

    public void setKeystoreAddr(String keystoreAddr) {
        this.keystoreAddr = keystoreAddr;
    }

    public void setKeystorePW(String keystorePW) {
        this.keystorePW = keystorePW;
    }

    public String getTlsVersion() {
        return tlsVersion;
    }

    public void setTlsVersion(String tlsVersion) {
        this.tlsVersion = tlsVersion;
    }
}
