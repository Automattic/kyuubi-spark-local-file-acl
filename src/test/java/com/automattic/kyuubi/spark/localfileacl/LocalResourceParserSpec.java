package com.automattic.kyuubi.spark.localfileacl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.automattic.kyuubi.spark.localfileacl.LocalResourceParser.LocalResource;
import com.automattic.kyuubi.spark.localfileacl.PolicedKey.Cardinality;

class LocalResourceParserSpec {

  private static final PolicedKey LIST_KEY = new PolicedKey("spark.files", Cardinality.LIST);
  private static final PolicedKey SCALAR_KEY =
      new PolicedKey("spark.kerberos.keytab", Cardinality.SCALAR);

  @TempDir
  Path tempDir;

  private final LocalResourceParser parser = new LocalResourceParser();
  private Path root;
  private Path file;

  @BeforeEach
  void setUp() throws Exception {
    root = TestSupport.real(tempDir);
    file = Files.writeString(root.resolve("data.conf"), "x");
  }

  @Test
  void acceptsBareAbsolutePathsAndFileUris() {
    assertEquals(file, single(LIST_KEY, file.toString()).realPath());
    assertEquals(file, single(LIST_KEY, "file:" + file).realPath());
    assertEquals(file, single(LIST_KEY, "file://" + file).realPath());
    assertEquals(file, single(LIST_KEY, "file:///" + file.toString().substring(1)).realPath());
  }

  @Test
  void treatsSchemesCaseInsensitively() {
    assertEquals(file, single(LIST_KEY, "FILE:" + file).realPath());
    assertTrue(parser.parse(LIST_KEY, "HDFS://nn/x.jar").isEmpty());
  }

  @Test
  void removesAliasFragmentBeforeResolving() {
    assertEquals(file, single(LIST_KEY, file + "#alias.conf").realPath());
    assertEquals(file, single(LIST_KEY, "file:" + file + "#alias").realPath());
  }

  @Test
  void ignoresRemoteUris() {
    assertTrue(parser.parse(LIST_KEY, "hdfs://nn:8020/user/x.jar").isEmpty());
    assertTrue(parser.parse(LIST_KEY, "s3a://bucket/x.jar").isEmpty());
    assertTrue(parser.parse(LIST_KEY, "http://host/x.jar").isEmpty());
    assertTrue(parser.parse(LIST_KEY, "viewfs://cluster/x.jar").isEmpty());
  }

  @Test
  void mixesLocalAndRemoteEntriesInLists() {
    List<LocalResource> locals =
        parser.parse(LIST_KEY, "hdfs://nn/a.jar," + file + ",s3a://b/c.jar");
    assertEquals(1, locals.size());
    assertEquals(file, locals.get(0).realPath());
  }

  @Test
  void scalarValuesAreNeverCommaSplit() throws Exception {
    Path commaFile = Files.writeString(root.resolve("a,b.keytab"), "x");
    assertEquals(commaFile, single(SCALAR_KEY, commaFile.toString()).realPath());
    // The same value under a LIST key splits and fails on the missing halves.
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, commaFile.toString()));
  }

  @Test
  void rejectsRelativePathsAndAuthorities() {
    assertThrows(IllegalArgumentException.class, () -> parser.parse(LIST_KEY, "relative.jar"));
    assertThrows(IllegalArgumentException.class, () -> parser.parse(LIST_KEY, "file:relative.jar"));
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, "file://somehost" + file));
  }

  @Test
  void rejectsEmptyAndMalformedEntries() {
    assertThrows(IllegalArgumentException.class, () -> parser.parse(SCALAR_KEY, ""));
    assertThrows(IllegalArgumentException.class, () -> parser.parse(SCALAR_KEY, "   "));
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, file + ",," + file));
    assertThrows(IllegalArgumentException.class, () -> parser.parse(LIST_KEY, file + ","));
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, "/path with space.jar"));
  }

  @Test
  void rejectsUriQueries() {
    assertThrows(IllegalArgumentException.class, () -> parser.parse(LIST_KEY, file + "?query=1"));
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, "file:" + file + "?query=1"));
  }

  @Test
  void rejectsSubmittedGlobs() {
    assertThrows(IllegalArgumentException.class, () -> parser.parse(LIST_KEY, root + "/*.conf"));
    assertThrows(IllegalArgumentException.class, () -> parser.parse(SCALAR_KEY, root + "/k?.keytab"));
  }

  @Test
  void rejectsMissingAndNonRegularPaths() throws Exception {
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, root.resolve("missing.jar").toString()));
    Path dir = Files.createDirectory(root.resolve("dir"));
    assertThrows(IllegalArgumentException.class, () -> parser.parse(LIST_KEY, dir.toString()));
  }

  @Test
  void canonicalizesSymlinksToTheirTarget() throws Exception {
    Path link = Files.createSymbolicLink(root.resolve("link.conf"), file);
    assertEquals(file, single(LIST_KEY, link.toString()).realPath());
  }

  private LocalResource single(PolicedKey key, String value) {
    List<LocalResource> locals = parser.parse(key, value);
    assertEquals(1, locals.size());
    return locals.get(0);
  }
}
