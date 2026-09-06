/*
 * Copyright the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.rasc.hibppasswords.importer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;

class HibpPasswordsImporterTest {

	private static final String PASSWORD_HASH = "7C4A8D09CA3762AF61E59520943DC26494F8941B";

	@TempDir
	Path tempDirectory;

	@Test
	void importsValidPrefixFilesAndSupportsRangeCli() throws IOException {
		Path hashes = this.tempDirectory.resolve("hashes");
		Path database = this.tempDirectory.resolve("database");
		Files.createDirectories(hashes);
		Files.writeString(hashes.resolve("7c4a8.txt"),
				PASSWORD_HASH.substring(5) + ":42\n" + "F".repeat(35) + ":3\n");

		assertEquals(2,
				HibpPasswordsImporter.importHashes(hashes, database, quietOutput()));
		assertEquals(42,
				HibpPasswordsQuery.haveIBeenPwnedPlain(database, "123456"));

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		int exitCode = HibpPasswordsImporter.run(
				new String[] { "query-range", "7C4A8", database.toString() },
				new PrintStream(output), quietOutput());
		assertEquals(0, exitCode);
		assertEquals(PASSWORD_HASH.substring(5) + ":42\n" + "F".repeat(35)
				+ ":3\n", output.toString(StandardCharsets.UTF_8).replace("\r\n", "\n"));
	}

	@Test
	void rejectsMalformedInputWithFileAndLineNumber() throws IOException {
		Path hashes = this.tempDirectory.resolve("hashes");
		Files.createDirectories(hashes);
		Files.writeString(hashes.resolve("7C4A8.txt"), "not-a-hash\n");

		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> HibpPasswordsImporter.importHashes(hashes,
						this.tempDirectory.resolve("database"), quietOutput()));
		assertTrue(exception.getMessage().contains("7C4A8.txt:1"));
	}

	@Test
	void rejectsUnsortedHashesBeforePutRightCanCorruptTheImport() throws IOException {
		Path hashes = this.tempDirectory.resolve("hashes");
		Files.createDirectories(hashes);
		Files.writeString(hashes.resolve("7C4A8.txt"),
				"F".repeat(35) + ":3\n" + PASSWORD_HASH.substring(5) + ":42\n");

		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
				() -> HibpPasswordsImporter.importHashes(hashes,
						this.tempDirectory.resolve("database"), quietOutput()));
		assertTrue(exception.getMessage().contains("sorted in ascending order"));
	}

	@Test
	void rejectsDatabaseNestedInsideHashesDirectory() throws IOException {
		Path hashes = this.tempDirectory.resolve("hashes");
		Files.createDirectories(hashes);
		Files.writeString(hashes.resolve("7C4A8.txt"),
				PASSWORD_HASH.substring(5) + ":42\n");
		Path database = hashes.resolve("database");

		assertThrows(IllegalArgumentException.class, () -> HibpPasswordsImporter
				.importHashes(hashes, database, quietOutput()));
		assertFalse(Files.exists(database));
	}

	@Test
	void rejectsNonEmptyDatabaseDirectory() throws IOException {
		Path hashes = this.tempDirectory.resolve("hashes");
		Path database = this.tempDirectory.resolve("database");
		Files.createDirectories(hashes);
		Files.createDirectories(database);
		Files.writeString(hashes.resolve("7C4A8.txt"),
				PASSWORD_HASH.substring(5) + ":42\n");
		Files.writeString(database.resolve("existing"), "keep me");

		assertThrows(IllegalArgumentException.class, () -> HibpPasswordsImporter
				.importHashes(hashes, database, quietOutput()));
		assertTrue(Files.exists(database.resolve("existing")));
	}

	@Test
	void cliReturnsUsefulExitCodes() {
		ByteArrayOutputStream errors = new ByteArrayOutputStream();
		assertEquals(2, HibpPasswordsImporter.run(new String[] { "unknown", "x", "y" },
				quietOutput(), new PrintStream(errors)));
		assertTrue(errors.toString(StandardCharsets.UTF_8).startsWith("Usage:"));

		errors.reset();
		assertEquals(1, HibpPasswordsImporter.run(
				new String[] { "query-plain", "password",
						this.tempDirectory.resolve("missing").toString() },
				quietOutput(), new PrintStream(errors)));
		assertTrue(errors.toString(StandardCharsets.UTF_8)
				.contains("database directory does not exist"));
	}

	private static PrintStream quietOutput() {
		return new PrintStream(OutputStream.nullOutputStream());
	}

}
