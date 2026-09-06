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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Stream;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import ch.rasc.hibppasswords.query.RangeQueryResult;
import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.ExodusException;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;
import jetbrains.exodus.env.Transaction;

public final class HibpPasswordsImporter {

	private static final long FLUSH_INTERVAL = 10_000_000L;

	private static final HexFormat HEX_FORMAT = HexFormat.of();

	private HibpPasswordsImporter() {
	}

	public static void main(String[] args) {
		System.exit(run(args, System.out, System.err));
	}

	static int run(String[] args, PrintStream out, PrintStream err) {
		Objects.requireNonNull(args, "args");
		if (args.length == 1
				&& (args[0].equals("--help") || args[0].equals("-h"))) {
			printUsage(out);
			return 0;
		}
		if (args.length != 3) {
			printUsage(err);
			return 2;
		}

		try {
			Path databaseDirectory = Path.of(args[2]);
			switch (args[0].toLowerCase(Locale.ROOT)) {
				case "import" -> importHashes(Path.of(args[1]), databaseDirectory,
						out);
				case "query-plain" -> printQueryResult(HibpPasswordsQuery
						.haveIBeenPwnedPlain(databaseDirectory, args[1]), out);
				case "query-sha1" -> printQueryResult(HibpPasswordsQuery
						.haveIBeenPwnedSha1(databaseDirectory, args[1]), out);
				case "query-range" -> {
					for (RangeQueryResult result : HibpPasswordsQuery
							.haveIBeenPwnedRange(databaseDirectory, args[1])) {
						out.println(result);
					}
				}
				default -> {
					printUsage(err);
					return 2;
				}
			}
			return 0;
		}
		catch (IOException | IllegalArgumentException | ExodusException e) {
			err.println("Error: " + e.getMessage());
			return 1;
		}
	}

	private static void printQueryResult(Integer result, PrintStream out) {
		out.println(result != null ? result : "not found");
	}

	private static void printUsage(PrintStream out) {
		out.println("Usage:");
		out.println(
				"  java -jar hibp-passwords-importer.jar import <hibp-hashes-directory> <database-directory>");
		out.println(
				"  java -jar hibp-passwords-importer.jar query-plain <password> <database-directory>");
		out.println(
				"  java -jar hibp-passwords-importer.jar query-sha1 <sha1> <database-directory>");
		out.println(
				"  java -jar hibp-passwords-importer.jar query-range <sha1-prefix> <database-directory>");
	}

	static long importHashes(Path hibpHashesDirectory, Path databaseDirectory,
			PrintStream out) throws IOException {
		Objects.requireNonNull(hibpHashesDirectory, "hibpHashesDirectory");
		Objects.requireNonNull(databaseDirectory, "databaseDirectory");
		Objects.requireNonNull(out, "out");

		Path inputDirectory = hibpHashesDirectory.toAbsolutePath().normalize();
		Path targetDirectory = databaseDirectory.toAbsolutePath().normalize();
		if (!Files.isDirectory(inputDirectory)) {
			throw new IllegalArgumentException(
					"HIBP hashes directory does not exist: " + inputDirectory);
		}
		if (targetDirectory.startsWith(inputDirectory)
				|| inputDirectory.startsWith(targetDirectory)) {
			throw new IllegalArgumentException(
					"The hashes and database directories must not contain one another");
		}

		List<HashFile> hashFiles = listHashFiles(inputDirectory);
		if (hashFiles.isEmpty()) {
			throw new IllegalArgumentException(
					"HIBP hashes directory contains no files: " + inputDirectory);
		}
		for (int i = 1; i < hashFiles.size(); i++) {
			if (hashFiles.get(i - 1).prefix().equals(hashFiles.get(i).prefix())) {
				throw new IllegalArgumentException("Multiple files use SHA-1 prefix "
						+ hashFiles.get(i).prefix());
			}
		}

		ensureEmptyTargetDirectory(targetDirectory);
		Files.createDirectories(targetDirectory);

		out.println("Importing " + hashFiles.size() + " hash files ...");
		try (Environment environment = Environments
				.newInstance(targetDirectory.toFile())) {
			try {
				long imported = environment.computeInExclusiveTransaction(transaction -> {
					try {
						return importFiles(environment, transaction, hashFiles, out);
					}
					catch (IOException e) {
						throw new UncheckedIOException(e);
					}
				});
				out.println("Imported " + imported + " password hashes");
				return imported;
			}
			catch (UncheckedIOException e) {
				throw e.getCause();
			}
		}
	}

	private static long importFiles(Environment environment, Transaction transaction,
			List<HashFile> hashFiles, PrintStream out) throws IOException {
		Store store = environment.openStore("passwords",
				StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, transaction);
		byte[] previousHash = null;
		long imported = 0;
		long sinceLastFlush = 0;
		int processedFiles = 0;

		for (HashFile hashFile : hashFiles) {
			try (BufferedReader reader = Files.newBufferedReader(hashFile.path())) {
				String line;
				long lineNumber = 0;
				while ((line = reader.readLine()) != null) {
					lineNumber++;
					PasswordEntry entry = parseLine(hashFile, lineNumber, line);
					if (previousHash != null
							&& Arrays.compareUnsigned(previousHash, entry.hash()) >= 0) {
						throw invalidLine(hashFile, lineNumber,
								"hashes must be unique and sorted in ascending order");
					}
					store.putRight(transaction, new ArrayByteIterable(entry.hash()),
							IntegerBinding.intToCompressedEntry(entry.count()));
					previousHash = entry.hash();
					imported++;
					sinceLastFlush++;

					if (sinceLastFlush == FLUSH_INTERVAL) {
						if (!transaction.flush()) {
							throw new IllegalStateException(
									"Could not flush the import transaction");
						}
						out.println("Imported " + imported + " hashes; processed "
								+ processedFiles + " of " + hashFiles.size() + " files");
						sinceLastFlush = 0;
					}
				}
			}
			processedFiles++;
		}
		return imported;
	}

	private static PasswordEntry parseLine(HashFile hashFile, long lineNumber,
			String line) {
		if (line.length() < 37 || line.charAt(35) != ':') {
			throw invalidLine(hashFile, lineNumber,
					"expected 35 hexadecimal suffix characters, a colon, and a count");
		}

		byte[] hash;
		try {
			hash = HEX_FORMAT.parseHex(hashFile.prefix() + line.substring(0, 35));
		}
		catch (IllegalArgumentException e) {
			throw invalidLine(hashFile, lineNumber,
					"hash suffix must contain only hexadecimal characters");
		}

		int count;
		try {
			count = Integer.parseInt(line.substring(36).trim());
		}
		catch (NumberFormatException e) {
			throw invalidLine(hashFile, lineNumber,
					"breach count must be an integer");
		}
		if (count < 0) {
			throw invalidLine(hashFile, lineNumber,
					"breach count must not be negative");
		}
		return new PasswordEntry(hash, count);
	}

	private static IllegalArgumentException invalidLine(HashFile hashFile,
			long lineNumber, String message) {
		return new IllegalArgumentException(
				hashFile.path() + ":" + lineNumber + ": " + message);
	}

	private static void ensureEmptyTargetDirectory(Path targetDirectory)
			throws IOException {
		if (!Files.exists(targetDirectory)) {
			return;
		}
		if (!Files.isDirectory(targetDirectory)) {
			throw new IllegalArgumentException(
					"Database path is not a directory: " + targetDirectory);
		}
		try (Stream<Path> entries = Files.list(targetDirectory)) {
			if (entries.findAny().isPresent()) {
				throw new IllegalArgumentException(
						"Database directory must be empty: " + targetDirectory);
			}
		}
	}

	private static List<HashFile> listHashFiles(Path inputDirectory)
			throws IOException {
		try (Stream<Path> walker = Files.walk(inputDirectory)) {
			return walker.filter(Files::isRegularFile)
					.map(path -> new HashFile(path, getHashPrefix(path)))
					.sorted(Comparator.comparing(HashFile::prefix)
							.thenComparing(hashFile -> hashFile.path().toString()))
					.toList();
		}
	}

	private static String getHashPrefix(Path inputFile) {
		String fileName = inputFile.getFileName().toString();
		int extensionIndex = fileName.lastIndexOf('.');
		String prefix = extensionIndex == -1 ? fileName
				: fileName.substring(0, extensionIndex);
		if (prefix.length() != 5) {
			throw new IllegalArgumentException(
					"Hash file name must be a 5-character SHA-1 prefix: "
							+ inputFile);
		}
		String normalizedPrefix = prefix.toUpperCase(Locale.ROOT);
		for (int i = 0; i < normalizedPrefix.length(); i++) {
			if (Character.digit(normalizedPrefix.charAt(i), 16) == -1) {
				throw new IllegalArgumentException(
						"Hash file name must be a hexadecimal SHA-1 prefix: "
								+ inputFile);
			}
		}
		return normalizedPrefix;
	}

	private record HashFile(Path path, String prefix) {
	}

	private static final class PasswordEntry {

		private final byte[] hash;

		private final int count;

		private PasswordEntry(byte[] hash, int count) {
			this.hash = hash;
			this.count = count;
		}

		private byte[] hash() {
			return this.hash;
		}

		private int count() {
			return this.count;
		}
	}

}
