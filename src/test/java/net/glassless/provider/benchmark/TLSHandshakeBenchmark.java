package net.glassless.provider.benchmark;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

import net.glassless.provider.GlaSSLessProvider;

/**
 * JMH benchmark measuring full TLS 1.3 handshake + data exchange performance.
 *
 * <p>Uses SSLEngine for in-memory handshake (no socket overhead).
 * Compares JDK-only vs GlaSSLess-as-highest-priority provider.
 *
 * <p>Run with: mvn test -Pbenchmarks -Djmh.include=TLSHandshakeBenchmark
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(value = 1, jvmArgs = {"--enable-native-access=ALL-UNNAMED"})
public class TLSHandshakeBenchmark {

   @Param({"EC-P256", "EC-P384", "RSA-2048"})
   private String keyType;

   private SSLContext jdkServerCtx;
   private SSLContext jdkClientCtx;
   private SSLContext glasslessServerCtx;
   private SSLContext glasslessClientCtx;

   private Path tempDir;

   private static final byte[] PAYLOAD = "Hello TLS 1.3 benchmark!".getBytes();

   @Setup(Level.Trial)
   public void setup() throws Exception {
      tempDir = Files.createTempDirectory("tls-bench");
      Path ksPath = tempDir.resolve("server.p12");
      char[] password = "changeit".toCharArray();

      // Generate keystore via keytool (runs once at trial start)
      List<String> cmd = new ArrayList<>(List.of(
         "keytool", "-genkeypair", "-alias", "server",
         "-keyalg", keyType.startsWith("EC") ? "EC" : "RSA"));

      if (keyType.startsWith("EC")) {
         String curve = keyType.equals("EC-P256") ? "secp256r1" : "secp384r1";
         String sigAlg = keyType.equals("EC-P256") ? "SHA256withECDSA" : "SHA384withECDSA";
         cmd.addAll(List.of("-groupname", curve, "-sigalg", sigAlg));
      } else {
         int keySize = Integer.parseInt(keyType.split("-")[1]);
         cmd.addAll(List.of("-keysize", String.valueOf(keySize), "-sigalg", "SHA256withRSA"));
      }

      cmd.addAll(List.of(
         "-validity", "1",
         "-keystore", ksPath.toString(),
         "-storepass", new String(password),
         "-keypass", new String(password),
         "-dname", "CN=localhost,O=Benchmark,C=US",
         "-storetype", "PKCS12"));

      ProcessBuilder pb = new ProcessBuilder(cmd);
      pb.inheritIO();
      int exit = pb.start().waitFor();
      if (exit != 0) {
         throw new RuntimeException("keytool failed: " + exit);
      }

      // Load keystores and init KeyManagerFactory WITHOUT GlaSSLess
      // (PKCS12 private key extraction uses PBE which GlaSSLess doesn't support)
      Security.removeProvider(GlaSSLessProvider.PROVIDER_NAME);

      KeyStore ks = KeyStore.getInstance("PKCS12");
      try (FileInputStream fis = new FileInputStream(ksPath.toFile())) {
         ks.load(fis, password);
      }

      KeyStore ts = KeyStore.getInstance("PKCS12");
      ts.load(null, password);
      ts.setCertificateEntry("server", ks.getCertificate("server"));

      // Init key/trust managers once (PBE-sensitive step)
      KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(ks, password);
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(ks);
      TrustManagerFactory clientTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      clientTmf.init(ts);

      // JDK-only SSLContexts
      jdkServerCtx = SSLContext.getInstance("TLSv1.3");
      jdkServerCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
      jdkClientCtx = SSLContext.getInstance("TLSv1.3");
      jdkClientCtx.init(null, clientTmf.getTrustManagers(), new SecureRandom());

      // GlaSSLess SSLContexts — install provider, then create contexts
      // The SSLContext will resolve crypto operations via GlaSSLess
      Security.insertProviderAt(new GlaSSLessProvider(), 1);

      glasslessServerCtx = SSLContext.getInstance("TLSv1.3");
      glasslessServerCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
      glasslessClientCtx = SSLContext.getInstance("TLSv1.3");
      glasslessClientCtx.init(null, clientTmf.getTrustManagers(), new SecureRandom());
   }

   @TearDown(Level.Trial)
   public void tearDown() throws Exception {
      if (tempDir != null) {
         Files.walk(tempDir)
            .sorted(java.util.Comparator.reverseOrder())
            .forEach(p -> {
               try { Files.deleteIfExists(p); } catch (Exception ignored) { }
            });
      }
   }

   @Benchmark
   public String jdkHandshakeAndTransfer() throws Exception {
      return doHandshakeAndTransfer(jdkServerCtx, jdkClientCtx);
   }

   @Benchmark
   public String glasslessHandshakeAndTransfer() throws Exception {
      return doHandshakeAndTransfer(glasslessServerCtx, glasslessClientCtx);
   }

   /**
    * Performs a full TLS 1.3 handshake + bidirectional data transfer using SSLEngine.
    * Returns the negotiated cipher suite (consumed by JMH to prevent dead code elimination).
    */
   private String doHandshakeAndTransfer(SSLContext serverCtx, SSLContext clientCtx) throws Exception {
      SSLEngine client = clientCtx.createSSLEngine("localhost", 443);
      client.setUseClientMode(true);
      client.setEnabledProtocols(new String[]{"TLSv1.3"});

      SSLEngine server = serverCtx.createSSLEngine();
      server.setUseClientMode(false);
      server.setEnabledProtocols(new String[]{"TLSv1.3"});

      SSLSession session = client.getSession();
      int netBufSize = session.getPacketBufferSize();
      int appBufSize = session.getApplicationBufferSize();

      ByteBuffer clientToServer = ByteBuffer.allocate(netBufSize);
      ByteBuffer serverToClient = ByteBuffer.allocate(netBufSize);
      ByteBuffer clientApp = ByteBuffer.allocate(appBufSize);
      ByteBuffer serverApp = ByteBuffer.allocate(appBufSize);
      ByteBuffer empty = ByteBuffer.allocate(0);

      // Handshake
      client.beginHandshake();
      server.beginHandshake();
      doHandshake(client, server, clientToServer, serverToClient, clientApp, serverApp, empty);

      // Client sends payload
      clientApp.clear();
      clientApp.put(PAYLOAD);
      clientApp.flip();
      clientToServer.clear();
      client.wrap(clientApp, clientToServer);
      clientToServer.flip();

      // Server receives
      serverApp.clear();
      server.unwrap(clientToServer, serverApp);
      serverApp.flip();

      // Server echoes back
      serverToClient.clear();
      server.wrap(serverApp, serverToClient);
      serverToClient.flip();

      // Client receives echo
      clientApp.clear();
      client.unwrap(serverToClient, clientApp);

      String cipherSuite = client.getSession().getCipherSuite();

      client.closeOutbound();
      server.closeOutbound();

      return cipherSuite;
   }

   private void doHandshake(
         SSLEngine client, SSLEngine server,
         ByteBuffer cToS, ByteBuffer sToC,
         ByteBuffer clientApp, ByteBuffer serverApp,
         ByteBuffer empty) throws Exception {

      for (int i = 0; i < 100; i++) {
         SSLEngineResult.HandshakeStatus cs = client.getHandshakeStatus();
         SSLEngineResult.HandshakeStatus ss = server.getHandshakeStatus();

         if (cs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
               && ss == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return;
         }

         if (cs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            runTasks(client);
            continue;
         }
         if (ss == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            runTasks(server);
            continue;
         }

         if (cs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            cToS.clear();
            empty.clear();
            client.wrap(empty, cToS);
            cToS.flip();
         }

         if (cToS.hasRemaining()) {
            serverApp.clear();
            server.unwrap(cToS, serverApp);
            cToS.compact();
         }

         ss = server.getHandshakeStatus();
         if (ss == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            runTasks(server);
            continue;
         }

         if (ss == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            sToC.clear();
            empty.clear();
            server.wrap(empty, sToC);
            sToC.flip();
         }

         if (sToC.hasRemaining()) {
            clientApp.clear();
            client.unwrap(sToC, clientApp);
            sToC.compact();
         }

         if (client.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            runTasks(client);
         }
         if (server.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            runTasks(server);
         }
      }

      throw new RuntimeException("Handshake did not complete");
   }

   private void runTasks(SSLEngine engine) {
      Runnable task;
      while ((task = engine.getDelegatedTask()) != null) {
         task.run();
      }
   }

}
