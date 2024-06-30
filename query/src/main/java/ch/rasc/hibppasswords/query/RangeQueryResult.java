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

public class RangeQueryResult {
	private final String hashSuffix;
	private final int count;

	public RangeQueryResult(String hashSuffix, int count) {
		this.hashSuffix = hashSuffix;
		this.count = count;
	}

	/**
	 * Last 35 charactres of the SHA-1 hash
	 */
	public String getHashSuffix() {
		return this.hashSuffix;
	}

	/**
	 * Number of times the password appeared in a data breach
	 */
	public int getCount() {
		return this.count;
	}

}
