/**
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.jetbrains.annotations.NotNull;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.ByteIterable;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;
import jetbrains.exodus.env.Transaction;

public class HibpPasswordsImporter {

	public static void main(String[] args) throws Exception {

		if (args.length == 3) {
			if (args[0].equalsIgnoreCase("import")) {
				Path hibpHashesDirectory = Paths.get(args[1]);
				Path databaseDir = Paths.get(args[2]);

				int exitCode = HibpPasswordsImporter.doImport(hibpHashesDirectory,
						databaseDir);
				System.exit(exitCode);
			}
			else if (args[0].equalsIgnoreCase("query-plain")) {
				Integer result = HibpPasswordsQuery
						.haveIBeenPwnedPlain(Paths.get(args[2]), args[1]);
				if (result != null) {
					System.out.println(result);
				}
				else {
					System.out.println("not found");
				}
			}
			else if (args[0].equalsIgnoreCase("query-sha1")) {
				Integer result = HibpPasswordsQuery.haveIBeenPwnedSha1(Paths.get(args[2]),
						args[1]);
				if (result != null) {
					System.out.println(result);
				}
				else {
					System.out.println("not found");
				}
			}
		}
		else {
			printUsage();
			System.exit(2);
		}
	}

	private static void printUsage() {
		System.out.println(
				"java -jar hibp-passwords-importer.jar import <hibp hashes directory>  <database directory>");
		System.out.println(
				"java -jar hibp-passwords-importer.jar query-plain <plain text password>  <database directory>");
		System.out.println(
				"java -jar hibp-passwords-importer.jar query-sha1 <sha1>  <database directory>");
	}

	private static int doImport(Path hibpHashesDirectory, Path databaseDir)
			throws Exception {

		if (!Files.exists(hibpHashesDirectory)) {
			System.out.println("hibp directory does not exist");
			return 1;
		}

		Files.createDirectories(databaseDir);

		System.out.println("Importing ...");
		try (Environment env = Environments.newInstance(databaseDir.toFile())) {
			return env.computeInExclusiveTransaction((@NotNull final Transaction txn) -> {
				Store store = env.openStore("passwords",
						StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, txn);
				try {


			        final AtomicLong importCounter = new AtomicLong(0L);
			        final AtomicLong fileCounter = new AtomicLong(0L);

					List<String> hashFiles = listAllFiles(hibpHashesDirectory);
					int totalFiles = hashFiles.size();
					for (String hashFile : hashFiles) {
						Path inputFile = Paths.get(hashFile);
						try (var linesReader = Files.lines(inputFile)) {
							linesReader.forEach(line -> {
								long c = importCounter.incrementAndGet();
					              if (c > 10_000_000) {
					                txn.flush();
					                System.out.println(
					                    "Processed no of files " + fileCounter.get() + " of " + totalFiles);
					                importCounter.set(0L);
					              }
					              String hashPrefix = hashFile.substring(0, hashFile.lastIndexOf("."));
								importLine(store, txn, hashPrefix, line);
							});
						}
						
						fileCounter.incrementAndGet();
					}

					txn.commit();
				}
				catch (IOException e) {
					e.printStackTrace();
					return 1;
				}
				return 0;
			});
		}
	}

	private static void importLine(Store store, Transaction txn, String prefix, String line) {
	    String sha1 = line.substring(0, 35);
	    int count = Integer.parseInt(line.substring(36).trim());

	    ByteIterable key = new ArrayByteIterable(hexStringToByteArray(prefix + sha1));
	    store.putRight(txn, key, IntegerBinding.intToCompressedEntry(count));
	}

	private static byte[] hexStringToByteArray(String s) {
		byte[] data = new byte[20];
		for (int i = 0; i < 40; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private static List<String> listAllFiles(Path inputDir) {
		List<String> files = new ArrayList<>();
		try (var walker = Files.walk(inputDir)) {
			walker.forEach(filePath -> {
				if (Files.isRegularFile(filePath)) {
					files.add(filePath.toString());
				}
			});
		}
		catch (IOException e) {
			e.printStackTrace();
		}

		files.sort(String::compareTo);
		return files;
	}

}
