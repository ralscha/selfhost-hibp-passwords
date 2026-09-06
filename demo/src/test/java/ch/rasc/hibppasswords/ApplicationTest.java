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
package ch.rasc.hibppasswords;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import java.util.HexFormat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import jetbrains.exodus.ArrayByteIterable;
import jetbrains.exodus.bindings.IntegerBinding;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;
import jetbrains.exodus.env.Store;
import jetbrains.exodus.env.StoreConfig;

class ApplicationTest {

	private static final String PASSWORD_HASH = "7C4A8D09CA3762AF61E59520943DC26494F8941B";

	@TempDir
	Path tempDirectory;

	private Application application;

	private MockMvc mockMvc;

	@BeforeAll
	static void suppressExpectedXodusReflectionWarning() {
		((Logger) LoggerFactory.getLogger("jetbrains.exodus.io.FileDataWriter"))
				.setLevel(Level.ERROR);
	}

	@BeforeEach
	void setUp() {
		Path database = this.tempDirectory.resolve("database");
		try (Environment environment = Environments.newInstance(database.toFile())) {
			environment.executeInTransaction(transaction -> {
				Store store = environment.openStore("passwords",
						StoreConfig.WITHOUT_DUPLICATES_WITH_PREFIXING, transaction);
				store.put(transaction,
						new ArrayByteIterable(HexFormat.of().parseHex(PASSWORD_HASH)),
						IntegerBinding.intToCompressedEntry(42));
			});
		}

		AppConfig appConfig = new AppConfig();
		appConfig.setHibpDatabaseDir(database.toFile());
		this.application = new Application(appConfig);
		this.mockMvc = MockMvcBuilders.standaloneSetup(this.application).build();
	}

	@AfterEach
	void tearDown() {
		this.application.destroy();
	}

	@Test
	void preservesPlainAndSha1GetEndpoints() throws Exception {
		this.mockMvc.perform(get("/plain/123456"))
				.andExpect(status().isOk()).andExpect(content().string("42"));

		this.mockMvc.perform(get("/sha1/" + PASSWORD_HASH))
				.andExpect(status().isOk()).andExpect(content().string("42"));
	}

	@Test
	void returnsRangeInHibpFormat() throws Exception {
		this.mockMvc.perform(get("/range/7c4a8")).andExpect(status().isOk())
				.andExpect(content().string(PASSWORD_HASH.substring(5) + ":42"));
	}

	@Test
	void reportsInvalidHashesAsBadRequests() throws Exception {
		this.mockMvc.perform(get("/sha1/not-a-sha1"))
				.andExpect(status().isBadRequest())
				.andExpect(content().string(
						"The method expects the SHA-1 hash as parameter"));
	}

}
