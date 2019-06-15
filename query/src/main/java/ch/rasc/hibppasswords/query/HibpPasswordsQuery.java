/**
 * Copyright 2019-2019 the original author or authors.
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

import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.slf4j.LoggerFactory;

import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.ByteIterable;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Cursor;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;

/**
 * Utility class containing static helper methods to query a self hosted HIBP passwords
 * database
 */
public abstract class HibpPasswordsQuery {

	private static MessageDigest md;
	static {
		try {
			md = MessageDigest.getInstance("SHA-1");
		}
		catch (NoSuchAlgorithmException e) {
			LoggerFactory.getLogger(HibpPasswordsQuery.class)
					.error("error getting SHA-1 instance", e);
		}
	}

	/**
	 * Checks if a given password is stored in the database
	 *
	 * @param databaseDirectory Directory of the xodus passwords database
	 * @param password Plain text password
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedPlain(Path databaseDirectory, String password) {
		try (Environment env = Environments.newInstance(databaseDirectory.toFile())) {
			return haveIBeenPwnedPlain(env, password);
		}
	}

	/**
	 * Checks if a given password is stored in the database
	 *
	 * @param environment Xodus Environment instance
	 * @param password Plain text password
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedPlain(Environment environment, String password) {
		
		return haveIBeenPwned(environment, sha1hash);
		
		return environment.computeInReadonlyTransaction(txn -> {
			Store store = environment.openStore("passwords",
					StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, txn);
			byte[] passwordBytes = md.digest(password.getBytes());
			ByteIterable key = new ArrayByteIterable(passwordBytes);
			ByteIterable bi = store.get(txn, key);
			if (bi != null) {
				return IntegerBinding.compressedEntryToInt(bi);
			}
			return null;
		});
	}
	
	/**
	 * Checks if a given password is stored in the database
	 *
	 * @param databaseDirectory Directory of the xodus passwords database
	 * @param password SHA-1 hash of a password (case-insensitive)
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedSha1(Path databaseDirectory, String sha1hash) {
		try (Environment env = Environments.newInstance(databaseDirectory.toFile())) {
			return haveIBeenPwnedSha1(env, sha1hash);
		}
	}

	/**
	 * Checks if a given password is stored in the database
	 *
	 * @param environment Xodus Environment instance
	 * @param password SHA-1 hash of a password (case-insensitive)
	 * @return number of times the password appeared in a data breach or <code>null</code>
	 * if the password wasn't found in any of the Pwned Passwords loaded into Have I Been
	 * Pwned
	 */
	public static Integer haveIBeenPwnedSha1(Environment environment, String sha1hash) {
		byte[] passwordBytes = hexStringToByteArray(sha1hash.toUpperCase());
		return haveIBeenPwned(environment, sha1hash);
	}	

	private static Integer haveIBeenPwned(Environment environment, byte[] key) {
		return environment.computeInReadonlyTransaction(txn -> {
			Store store = environment.openStore("passwords",
					StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, txn);			
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
	 * "https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange">SearchingPwnedPasswordsByRange</a>
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

		if (first5CharactersOfSHA1Hash == null
				|| first5CharactersOfSHA1Hash.length() != 5) {
			throw new IllegalArgumentException(
					"The method expects the first 5 characters of a SHA-1 hash as parameter");
		}

		try (Environment env = Environments.newInstance(databaseDirectory.toFile())) {
			return haveIBeenPwnedRange(env, first5CharactersOfSHA1Hash);
		}
	}

	/**
	 * Implements the range query API of haveibeenpwned.com. <br>
	 * <a href=
	 * "https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange">SearchingPwnedPasswordsByRange</a>
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

		if (first5CharactersOfSHA1Hash == null
				|| first5CharactersOfSHA1Hash.length() != 5) {
			throw new IllegalArgumentException(
					"The method expects the first 5 characters of a SHA-1 hash as parameter");
		}

		return environment.computeInReadonlyTransaction(txn -> {

			String first5CharactersOfSHA1HashUpperCase = first5CharactersOfSHA1Hash
					.toUpperCase();
			List<RangeQueryResult> queryResult = new ArrayList<>();

			Store store = environment.openStore("passwords",
					StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, txn);
			try (Cursor cursor = store.openCursor(txn)) {

				String padded = first5CharactersOfSHA1HashUpperCase + new String(
						new char[40 - first5CharactersOfSHA1HashUpperCase.length()])
								.replace('\0', '0');
				byte[] keyBytes = hexStringToByteArray(padded);
				ByteIterable key = new ArrayByteIterable(keyBytes);
				final ByteIterable v = cursor.getSearchKeyRange(key);
				if (v != null) {
					byte[] unsafeBytes = cursor.getKey().getBytesUnsafe();
					String hex = bytesToHex(
							Arrays.copyOf(unsafeBytes, cursor.getKey().getLength()));

					if (hex.startsWith(first5CharactersOfSHA1HashUpperCase)) {
						queryResult.add(new RangeQueryResult(hex.substring(5),
								IntegerBinding.compressedEntryToInt(cursor.getValue())));

						while (cursor.getNext()) {
							unsafeBytes = cursor.getKey().getBytesUnsafe();
							hex = bytesToHex(Arrays.copyOf(unsafeBytes,
									cursor.getKey().getLength()));
							if (hex.startsWith(first5CharactersOfSHA1HashUpperCase)) {
								queryResult.add(new RangeQueryResult(hex.substring(5),
										IntegerBinding.compressedEntryToInt(
												cursor.getValue())));
							}
							else {
								break;
							}
						}
					}
				}
			}

			return queryResult;
		});
	}

	private static byte[] hexStringToByteArray(String s) {
		byte[] data = new byte[20];
		for (int i = 0; i < 40; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static Function<? super RangeQueryResult, ? extends String> stringResultMapper() {
		return r -> r.getHashSuffix() + ":" + r.getCount();
	}

}
