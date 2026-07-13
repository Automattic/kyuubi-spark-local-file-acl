package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.apache.kyuubi.config.KyuubiConf;
import org.apache.kyuubi.server.KyuubiRestFrontendService;
import org.apache.kyuubi.server.KyuubiServer;
import org.apache.kyuubi.service.AbstractFrontendService;
import org.apache.kyuubi.zookeeper.EmbeddedZookeeper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Boots a real Kyuubi 1.11.1 server (Java port of Kyuubi's {@code WithKyuubiServer} test trait)
 * with this advisor installed and verifies rejection before engine launch / spark-submit.
 * No Spark distribution is required: rejections happen before the process builder runs, and the
 * authorized batch proves advisor pass-through by being accepted (its async spark-submit then
 * fails on the missing SPARK_HOME, which is not an ACL error).
 */
class KyuubiServerITSpec {

  @TempDir
  static Path tempDir;

  private static EmbeddedZookeeper zookeeper;
  private static KyuubiServer server;
  private static String jdbcUrlBase;
  private static String restUrlBase;

  private static Path allowedFile;
  private static Path secretFile;
  private static Path fakeAppJar;

  @BeforeAll
  static void startKyuubiServer() throws Exception {
    Path root = tempDir.toRealPath();
    String workDirRoot = System.getenv("KYUUBI_WORK_DIR_ROOT");
    assertNotNull(workDirRoot, "failsafe must set KYUUBI_WORK_DIR_ROOT (see pom.xml)");
    Path uploadRoot = Files.createDirectories(Path.of(workDirRoot, "upload"));

    allowedFile = Files.writeString(
        Files.createDirectories(root.resolve("res")).resolve("app.conf"), "config");
    secretFile = Files.writeString(root.resolve("secret.keytab"), "secret");
    fakeAppJar = Files.writeString(root.resolve("fake-app.jar"), "not a real jar");

    Path aclFile = root.resolve("kyuubi-local-file-acl.yaml");
    TestSupport.writeAcl(aclFile, """
        version: 1
        users:
          alice:
            allow:
              - '%s/res/*.conf'
          anonymous:
            allow:
              - '%s/res/*.conf'
        """.formatted(root, root));

    System.setProperty(PluginSettings.RULES_FILE_PROP, aclFile.toString());
    System.setProperty(PluginSettings.UPLOAD_ROOT_PROP, uploadRoot.toString());
    System.setProperty(PluginSettings.RELOAD_INTERVAL_PROP, "PT60S");

    KyuubiConf conf = new KyuubiConf(false);
    conf.set("kyuubi.frontend.protocols", "THRIFT_BINARY,REST");
    conf.set("kyuubi.frontend.thrift.binary.bind.port", "0");
    conf.set("kyuubi.frontend.rest.bind.port", "0");
    conf.set("kyuubi.session.conf.advisor", SparkLocalFileAclAdvisor.class.getName());
    // NOT restrict.list: AbstractSession eagerly validates the full batch conf (including the
    // reserved keys Kyuubi itself injects), so restricting them fails every REST batch. The
    // ignore list strips forged keys from interactive sessions and leaves batch conf alone.
    conf.set("kyuubi.session.conf.ignore.list",
        "kyuubi.batch.resource.uploaded,kyuubi.batch.id");
    conf.set("kyuubi.metadata.store.jdbc.url",
        "jdbc:sqlite:" + root.resolve("kyuubi_state_store.db"));

    zookeeper = new EmbeddedZookeeper();
    conf.set("kyuubi.zookeeper.embedded.client.port", "0");
    conf.set("kyuubi.zookeeper.embedded.data.dir", root.resolve("zk").toString());
    zookeeper.initialize(conf);
    zookeeper.start();
    conf.set("kyuubi.ha.addresses", zookeeper.getConnectString());
    conf.set("kyuubi.ha.zookeeper.auth.type", "NONE");

    server = KyuubiServer.startServer(conf);
    for (int i = 0; i < server.frontendServices().size(); i++) {
      AbstractFrontendService frontend = server.frontendServices().apply(i);
      if (frontend instanceof KyuubiRestFrontendService) {
        restUrlBase = "http://" + frontend.connectionUrl();
      } else {
        jdbcUrlBase = "jdbc:kyuubi://" + frontend.connectionUrl() + "/";
      }
    }
    assertNotNull(jdbcUrlBase);
    assertNotNull(restUrlBase);
  }

  @AfterAll
  static void stopKyuubiServer() {
    if (server != null) {
      server.stop();
    }
    if (zookeeper != null) {
      zookeeper.stop();
    }
    System.clearProperty(PluginSettings.RULES_FILE_PROP);
    System.clearProperty(PluginSettings.UPLOAD_ROOT_PROP);
    System.clearProperty(PluginSettings.RELOAD_INTERVAL_PROP);
  }

  @Test
  void interactiveSessionRejectedBeforeEngineLaunch() {
    SQLException e = assertThrows(SQLException.class, () -> DriverManager.getConnection(
        jdbcUrlBase + ";?spark.files=" + secretFile, "alice", ""));
    assertTrue(e.getMessage().contains("Local file access denied"),
        "unexpected error: " + e.getMessage());
    assertTrue(e.getMessage().contains("alice"));
  }

  @Test
  void interactiveSessionCannotForgeReservedUploadKeys() throws Exception {
    // Stage a file where a batch upload would live, then try to reach it from an interactive
    // session with forged exemption keys. The ignore list strips them, so the upload-root path
    // is denied unconditionally instead of being exempted.
    String forgedBatchId = java.util.UUID.randomUUID().toString();
    Path uploadRoot = Path.of(System.getProperty(PluginSettings.UPLOAD_ROOT_PROP));
    Path staged = Files.writeString(
        Files.createDirectories(uploadRoot.resolve(forgedBatchId)).resolve("stolen.jar"), "x");

    SQLException e = assertThrows(SQLException.class, () -> DriverManager.getConnection(
        jdbcUrlBase + ";?kyuubi.batch.resource.uploaded=true;kyuubi.batch.id=" + forgedBatchId
            + ";spark.files=" + staged,
        "alice", ""));
    assertTrue(e.getMessage().contains("Local file access denied"),
        "unexpected error: " + e.getMessage());
  }

  @Test
  void batchRejectedBeforeSparkSubmit() throws Exception {
    HttpResponse<String> response = postBatch(secretFile.toString());
    assertEquals(500, response.statusCode(), "body: " + response.body());
    assertTrue(response.body().contains("Local file access denied"),
        "unexpected body: " + response.body());
  }

  @Test
  void authorizedBatchPassesTheAdvisor() throws Exception {
    HttpResponse<String> response = postBatch(allowedFile.toString());
    // The advisor must pass; without a Spark distribution Kyuubi then fails synchronously on
    // SPARK_HOME while assembling spark-submit, which is precisely the post-advisor stage.
    assertTrue(!response.body().contains("Local file access denied"),
        "advisor rejected an authorized batch: " + response.body());
    if (response.statusCode() != 200) {
      assertEquals(500, response.statusCode(), "body: " + response.body());
      assertTrue(response.body().contains("SPARK_HOME"), "unexpected body: " + response.body());
    }
  }

  private static HttpResponse<String> postBatch(String sparkFilesValue) throws Exception {
    String body = """
        {
          "batchType": "SPARK",
          "name": "local-file-acl-it",
          "resource": "%s",
          "className": "org.example.Main",
          "conf": {"spark.files": "%s"},
          "args": []
        }
        """.formatted(fakeAppJar, sparkFilesValue);
    HttpRequest request = HttpRequest.newBuilder(URI.create(restUrlBase + "/api/v1/batches"))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
  }
}
