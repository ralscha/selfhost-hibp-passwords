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
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class HibpPasswordsQueryTest {

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
}
