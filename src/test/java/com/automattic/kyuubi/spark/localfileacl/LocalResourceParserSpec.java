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

class LocalResourceParserSpec {

  private static final Cardinality LIST_KEY = Cardinality.LIST;
  private static final Cardinality SCALAR_KEY = Cardinality.SCALAR;

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
    assertEquals(file, single(LIST_KEY, file.toString()));
    assertEquals(file, single(LIST_KEY, "file:" + file));
    assertEquals(file, single(LIST_KEY, "file://" + file));
    assertEquals(file, single(LIST_KEY, "file:///" + file.toString().substring(1)));
  }

  @Test
  void treatsSchemesCaseInsensitively() {
    assertEquals(file, single(LIST_KEY, "FILE:" + file));
    assertTrue(parser.parse(LIST_KEY, "HDFS://nn/x.jar").isEmpty());
  }

  @Test
  void removesAliasFragmentBeforeResolving() {
    assertEquals(file, single(LIST_KEY, file + "#alias.conf"));
    assertEquals(file, single(LIST_KEY, "file:" + file + "#alias"));
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
    List<Path> locals =
        parser.parse(LIST_KEY, "hdfs://nn/a.jar," + file + ",s3a://b/c.jar");
    assertEquals(1, locals.size());
    assertEquals(file, locals.get(0));
  }

  @Test
  void scalarValuesAreNeverCommaSplit() throws Exception {
    Path commaFile = Files.writeString(root.resolve("a,b.keytab"), "x");
    assertEquals(commaFile, single(SCALAR_KEY, commaFile.toString()));
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
  void neverAuthorizesAStrippedVariantOfAUnicodeWhitespacePath() throws Exception {
    // A real file whose name ends in Unicode whitespace (EM SPACE, U+2003). Spark trims only
    // ASCII whitespace, so the raw value must not be validated as its stripped sibling - it
    // is rejected outright (illegal URI character) instead of resolving to the wrong file.
    Files.writeString(root.resolve("data.conf\u2003"), "x");
    assertThrows(IllegalArgumentException.class,
        () -> parser.parse(LIST_KEY, file + "\u2003"));
    // ASCII whitespace is trimmed exactly like Spark does.
    assertEquals(file, single(LIST_KEY, "  " + file + "\t"));
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
    assertEquals(file, single(LIST_KEY, link.toString()));
  }

  private Path single(Cardinality key, String value) {
    List<Path> locals = parser.parse(key, value);
    assertEquals(1, locals.size());
    return locals.get(0);
  }
}
