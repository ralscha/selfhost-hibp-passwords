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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Function;

import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.ByteIterable;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Cursor;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.EnvironmentConfig;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;
import jetbrains.exodus.env.Transaction;

/**
 * Utility class containing static helper methods to query a self hosted HIBP passwords
 * database
 */
public final class HibpPasswordsQuery {

	private static final HexFormat HEX_FORMAT = HexFormat.of().withUpperCase();

	private static final String PASSWORDS_STORE = "passwords";

	private static final StoreConfig PASSWORDS_STORE_CONFIG =
			StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING;

	private HibpPasswordsQuery() {
	}

	private static MessageDigest sha1Digest() {
		try {
			return MessageDigest.getInstance("SHA-1");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-1 MessageDigest is not available", e);
		}
	}

	/**
	 * Checks if a given plain text password is stored in the database
	 *
	 * @param databaseDirectory Directory of the xodus passwords database
	 * @param password Plain text password
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedPlain(Path databaseDirectory, String password) {
		try (Environment env = openDatabase(databaseDirectory)) {
			return haveIBeenPwnedPlain(env, password);
		}
	}

	/**
	 * Checks if a given plain text password is stored in the database
	 *
	 * @param environment Xodus Environment instance
	 * @param password Plain text password
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedPlain(Environment environment, String password) {
		Objects.requireNonNull(password, "password");
		return haveIBeenPwned(Objects.requireNonNull(environment, "environment"),
				sha1Digest().digest(password.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * Checks if a given password hash is stored in the database
	 *
	 * @param databaseDirectory Directory of the xodus passwords database
	 * @param sha1hash SHA-1 hash of a password (case-insensitive)
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedSha1(Path databaseDirectory, String sha1hash) {
		try (Environment env = openDatabase(databaseDirectory)) {
			return haveIBeenPwnedSha1(env, sha1hash);
		}
	}

	/**
	 * Checks if a given password hash is stored in the database
	 *
	 * @param environment Xodus Environment instance
	 * @param sha1hash SHA-1 hash of a password (case-insensitive)
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedSha1(Environment environment, String sha1hash) {
		return haveIBeenPwned(Objects.requireNonNull(environment, "environment"),
				hexStringToByteArray(normalizeSha1Hash(sha1hash)));
	}

	private static Integer haveIBeenPwned(Environment environment, byte[] key) {
		return environment.computeInReadonlyTransaction(txn -> {
			Store store = openPasswordsStore(environment, txn);
			ByteIterable bi = store.get(txn, new ArrayByteIterable(key));
			if (bi != null) {
				return IntegerBinding.compressedEntryToInt(bi);
			}
			return null;
		});
	}

	/**
	 * Implements the range query API of haveibeenpwned.com. <br>
	 * <a href=
	 * "https://haveibeenpwned.com/API/v3#PwnedPasswords">Searching Pwned
	 * Passwords by range</a>
	 *
	 * Implements a k-Anonymity model that allows a password to be searched for by partial
	 * hash. The method expects the first 5 characters of a SHA-1 hash (case-insensitive).
	 *
	 * When password hashes beginning with the same first 5 characters are found in the
	 * database the method returns a list of these hashes, only including the suffix (last
	 * 35 characters) with the count of how many times it appears in the data set.
	 *
	 * The consumer of the method then has to search the returned list for the presence of
	 * the source hash.
	 *
	 * @param databaseDirectory Directory of the xodus passwords database
	 * @param first5CharactersOfSHA1Hash The first 5 characters of a SHA-1 hash
	 * @return list of hashes that start with the same 5 characters
	 */
	public static List<RangeQueryResult> haveIBeenPwnedRange(Path databaseDirectory,
			String first5CharactersOfSHA1Hash) {

		try (Environment env = openDatabase(databaseDirectory)) {
			return haveIBeenPwnedRange(env, first5CharactersOfSHA1Hash);
		}
	}

	/**
	 * Implements the range query API of haveibeenpwned.com. <br>
	 * <a href=
	 * "https://haveibeenpwned.com/API/v3#PwnedPasswords">Searching Pwned
	 * Passwords by range</a>
	 *
	 * Implements a k-Anonymity model that allows a password to be searched for by partial
	 * hash. The method expects the first 5 characters of a SHA-1 hash (case-insensitive).
	 *
	 * When password hashes beginning with the same first 5 characters are found in the
	 * database the method returns a list of these hashes, only including the suffix (last
	 * 35 characters) with the count of how many times it appears in the data set.
	 *
	 * The consumer of the method then has to search the returned list for the presence of
	 * the source hash.
	 *
	 * @param environment Xodus Environment instance
	 * @param first5CharactersOfSHA1Hash The first 5 characters of a SHA-1 hash
	 * @return list of hashes that start with the same 5 characters
	 */
	public static List<RangeQueryResult> haveIBeenPwnedRange(Environment environment,
			String first5CharactersOfSHA1Hash) {

		Objects.requireNonNull(environment, "environment");
		String hashPrefix = normalizeSha1Prefix(first5CharactersOfSHA1Hash);

		return environment.computeInReadonlyTransaction(txn -> {

			List<RangeQueryResult> queryResult = new ArrayList<>();

			Store store = openPasswordsStore(environment, txn);
			try (Cursor cursor = store.openCursor(txn)) {

				byte[] prefixBytes = HEX_FORMAT.parseHex(hashPrefix + "0");
				if (cursor.getSearchKeyRange(new ArrayByteIterable(prefixBytes)) != null) {
					do {
						ByteIterable key = cursor.getKey();
						byte[] bytes = key.getBytesUnsafe();
						// Five hex characters occupy two bytes and the high nibble of a third.
						if (key.getLength() != 20 || bytes[0] != prefixBytes[0]
								|| bytes[1] != prefixBytes[1]
								|| (bytes[2] & 0xf0) != (prefixBytes[2] & 0xff)) {
							break;
						}
						String suffix = HEX_FORMAT.toLowHexDigit(bytes[2])
								+ HEX_FORMAT.formatHex(bytes, 3, 20);
						queryResult.add(new RangeQueryResult(suffix,
								IntegerBinding.compressedEntryToInt(cursor.getValue())));
					} while (cursor.getNext());
				}
			}

			return queryResult;
		});
	}

	/**
	 * Opens an existing HIBP passwords database in read-only mode. The caller owns the
	 * returned environment and must close it.
	 *
	 * @param databaseDirectory directory containing an imported HIBP database
	 * @return a read-only Xodus environment
	 * @throws IllegalArgumentException if the directory does not exist or does not
	 * contain a passwords store
	 */
	public static Environment openDatabase(Path databaseDirectory) {
		Objects.requireNonNull(databaseDirectory, "databaseDirectory");
		Path normalizedDirectory = databaseDirectory.toAbsolutePath().normalize();
		if (!Files.isDirectory(normalizedDirectory)) {
			throw new IllegalArgumentException(
					"HIBP database directory does not exist: " + normalizedDirectory);
		}

		EnvironmentConfig config = new EnvironmentConfig().setEnvIsReadonly(true);
		Environment environment = Environments.newInstance(normalizedDirectory.toFile(),
				config);
		try {
			environment.executeInReadonlyTransaction(
					txn -> openPasswordsStore(environment, txn));
			return environment;
		}
		catch (RuntimeException e) {
			environment.close();
			throw e;
		}
	}

	private static Store openPasswordsStore(Environment environment,
			Transaction transaction) {
		if (environment.storeExists("import-in-progress", transaction)) {
			throw new IllegalArgumentException(
					"HIBP database import is incomplete; import again into an empty directory");
		}
		if (!environment.storeExists(PASSWORDS_STORE, transaction)) {
			throw new IllegalArgumentException(
					"Xodus environment does not contain an HIBP passwords store");
		}
		return environment.openStore(PASSWORDS_STORE, PASSWORDS_STORE_CONFIG,
				transaction);
	}

	static String normalizeSha1Hash(String sha1hash) {
		return normalizeHex(sha1hash, 40, "SHA-1 hash");
	}

	static String normalizeSha1Prefix(String first5CharactersOfSHA1Hash) {
		return normalizeHex(first5CharactersOfSHA1Hash, 5,
				"first 5 characters of a SHA-1 hash");
	}

	private static String normalizeHex(String value, int expectedLength, String label) {
		if (value == null || value.length() != expectedLength) {
			throw new IllegalArgumentException(
					"The method expects the " + label + " as parameter");
		}

		for (int i = 0; i < value.length(); i++) {
			if (!HexFormat.isHexDigit(value.charAt(i))) {
				throw new IllegalArgumentException(label + " must contain only hex digits");
			}
		}
		return value.toUpperCase(Locale.ROOT);
	}

	static byte[] hexStringToByteArray(String s) {
		return HEX_FORMAT.parseHex(s);
	}

	public static Function<RangeQueryResult, String> stringResultMapper() {
		return RangeQueryResult::toString;
	}

}
