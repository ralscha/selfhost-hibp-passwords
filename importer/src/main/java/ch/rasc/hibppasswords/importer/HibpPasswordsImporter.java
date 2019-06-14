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
package ch.rasc.hibppasswords.importer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicLong;

import org.jetbrains.annotations.NotNull;

import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.ByteIterable;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;
import jetbrains.exodus.env.Transaction;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(description = "Import a HIBP passwords text file into a local Xodus database",
		name = "java -jar hibp-passwords-importer.jar", mixinStandardHelpOptions = true,
		version = "1.0.0")
public class HibpPasswordsImporter implements Callable<Integer> {

	@Option(defaultValue = "pwned-passwords-sha1-ordered-by-hash-v4.txt", required = true,
			names = { "-i", "--input" },
			description = "Path to the uncompressed hibp passwords text file")
	private Path hibpPasswordsFile;

	@Option(defaultValue = "hibp-passwords", required = true,
			names = { "-d", "--database" },
			description = "Directory where the Xodus database will be stored. Directory will be created if it does not exist.")
	private Path databasePath;

	public static void main(String[] args) throws Exception {
		int exitCode = new CommandLine(new HibpPasswordsImporter()).execute(args);
		System.exit(exitCode);
	}

	@Override
	public Integer call() throws Exception {

		if (!Files.exists(this.hibpPasswordsFile)) {
			System.out.println("hibp passwords text file does not exist");
			return CommandLine.ExitCode.SOFTWARE;
		}

		Files.createDirectories(this.databasePath);

		System.out.println("Importing ...");
		try (Environment env = Environments.newInstance(this.databasePath.toFile())) {
			return env.computeInExclusiveTransaction((@NotNull final Transaction txn) -> {
				Store store = env.openStore("passwords",
						StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, txn);
				try {
					AtomicLong counter = new AtomicLong();
					Files.lines(this.hibpPasswordsFile).forEach(line -> {
						long c = counter.incrementAndGet();
						if (c % 10_000_000 == 0) {
							System.out.printf("imported: %d \n", c);
							txn.flush();
						}
						importLine(store, txn, line);
					});

					txn.commit();
				}
				catch (IOException e) {
					e.printStackTrace();
					return CommandLine.ExitCode.SOFTWARE;
				}
				return CommandLine.ExitCode.OK;
			});
		}
	}

	private static void importLine(Store store, Transaction txn, String line) {
		String sha1 = line.substring(0, 40);
		int count = Integer.parseInt(line.substring(41).trim());

		ByteIterable key = new ArrayByteIterable(hexStringToByteArray(sha1));
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

}
