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
package ch.rasc.hibppasswords.query;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;

class HibpPasswordsQueryTest {

	private static final String PASSWORD_HASH = "7C4A8D09CA3762AF61E59520943DC26494F8941B";

	@TempDir
	Path tempDirectory;

	@Test
	void normalizeSha1HashUpperCasesValidHash() {
		assertEquals("7C4A8D09CA3762AF61E59520943DC26494F8941B",
				HibpPasswordsQuery.normalizeSha1Hash(
						"7c4a8d09ca3762af61e59520943dc26494f8941b"));
	}

	@Test
	void normalizeSha1HashRejectsInvalidHash() {
		assertThrows(IllegalArgumentException.class,
				() -> HibpPasswordsQuery.normalizeSha1Hash(
						"7C4A8D09CA3762AF61E59520943DC26494F8941Z"));
	}

	@Test
	void normalizeSha1PrefixUpperCasesValidPrefix() {
		assertEquals("7C4A8", HibpPasswordsQuery.normalizeSha1Prefix("7c4a8"));
	}

	@Test
	void normalizeSha1PrefixRejectsWrongLength() {
		assertThrows(IllegalArgumentException.class,
				() -> HibpPasswordsQuery.normalizeSha1Prefix("7C4A"));
	}

	@Test
	void hexStringToByteArrayConvertsSha1Hash() {
		assertArrayEquals(
				new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
						14, 15, 16, 17, 18, 19 },
				HibpPasswordsQuery.hexStringToByteArray(
						"000102030405060708090A0B0C0D0E0F10111213"));
	}

	@Test
	void queriesImportedDatabaseByPlainTextHashAndRange() {
		Path database = this.tempDirectory.resolve("database");
		createDatabase(database);

		assertEquals(42,
				HibpPasswordsQuery.haveIBeenPwnedPlain(database, "123456"));
		assertEquals(42, HibpPasswordsQuery.haveIBeenPwnedSha1(database,
				PASSWORD_HASH.toLowerCase(Locale.ROOT)));
		assertNull(HibpPasswordsQuery.haveIBeenPwnedPlain(database, "not present"));
		assertEquals(
				List.of(new RangeQueryResult(PASSWORD_HASH.substring(5), 42),
						new RangeQueryResult("F".repeat(35), 3)),
				HibpPasswordsQuery.haveIBeenPwnedRange(database, "7c4a8"));
	}

	@Test
	void opensReusableDatabaseInReadOnlyMode() {
		Path database = this.tempDirectory.resolve("database");
		createDatabase(database);

		try (Environment environment = HibpPasswordsQuery.openDatabase(database)) {
			assertTrue(environment.getEnvironmentConfig().getEnvIsReadonly());
			assertEquals(42, HibpPasswordsQuery.haveIBeenPwnedSha1(environment,
					PASSWORD_HASH));
		}
	}

	@Test
	void missingDatabaseIsRejectedWithoutCreatingIt() {
		Path missingDatabase = this.tempDirectory.resolve("missing");

		assertThrows(IllegalArgumentException.class, () -> HibpPasswordsQuery
				.haveIBeenPwnedPlain(missingDatabase, "123456"));
		assertFalse(missingDatabase.toFile().exists());
	}

	@Test
	void environmentWithoutPasswordsStoreIsRejected() {
		Path emptyDatabase = this.tempDirectory.resolve("empty");
		try (Environment environment = Environments
				.newInstance(emptyDatabase.toFile())) {
			assertThrows(IllegalArgumentException.class, () -> HibpPasswordsQuery
					.haveIBeenPwnedPlain(environment, "123456"));
		}
	}

	private static void createDatabase(Path database) {
		try (Environment environment = Environments.newInstance(database.toFile())) {
			environment.executeInTransaction(transaction -> {
				Store store = environment.openStore("passwords",
						StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, transaction);
				store.put(transaction,
						new ArrayByteIterable(HexFormat.of().parseHex(PASSWORD_HASH)),
						IntegerBinding.intToCompressedEntry(42));
				store.put(transaction,
						new ArrayByteIterable(
								HexFormat.of().parseHex("7C4A8" + "F".repeat(35))),
						IntegerBinding.intToCompressedEntry(3));
			});
		}
	}
}
