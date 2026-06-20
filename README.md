# Self-host Have I Been Pwned Passwords

Tool for importing the Have I Been Pwned Passwords list into a local [JetBrains Xodus database](https://github.com/JetBrains/xodus), plus a Java library and Spring Boot demo for querying that database.

## Prerequisites

- Java 25 or newer. A JRE is sufficient for running the released importer; a JDK is required for building this repository.
- Sufficient drive storage. Expect about 57 GB during import and about 24 GB for normal operation.

Java downloads:

- https://adoptium.net/
- https://jdk.java.net/25/
- https://aws.amazon.com/corretto/
- https://www.azul.com/downloads/?package=jdk

## Build

```sh
./mvnw -B clean verify
```

On Windows:

```powershell
.\mvnw.cmd -B clean verify
```

## Import

1. Download the Pwned Passwords. Either use the [official downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) or [hibp-passwords-downloader](https://github.com/ralscha/hibp-passwords-downloader). The importer expects the hashes in individual prefix files.
2. Download [importer](https://github.com/ralscha/selfhost-hibp-passwords/releases/download/importer-1.1.0/hibp-passwords-importer.jar).
3. Run the import tool and point it to the directory that contains the downloaded hash files.

```sh
java -jar hibp-passwords-importer.jar import <hashesdir> <database_directory_name>
```

## Query

### Library

Add the library to your project.

```xml
<!-- Maven -->
<dependency>
  <groupId>ch.rasc.hibppasswords</groupId>
  <artifactId>query</artifactId>
  <version>1.0.1-SNAPSHOT</version>
</dependency>
```

```groovy
// Gradle
dependencies {
  implementation 'ch.rasc.hibppasswords:query:1.0.1-SNAPSHOT'
}
```

An application can query the database with a plain text password or SHA-1 hash. Both methods return how many times a password appears in the data set, or `null` if the password is not found.

`haveIBeenPwnedRange` implements the k-anonymity range-query model and searches by the first 5 characters of a SHA-1 hash:
https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

SHA-1 inputs are case-insensitive, but must contain valid hexadecimal characters and have the expected length: 40 characters for a full SHA-1 hash, 5 characters for a range query prefix.

```java
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import ch.rasc.hibppasswords.query.RangeQueryResult;

Path db = Paths.get("..."); // Path to local database
Integer count = HibpPasswordsQuery.haveIBeenPwnedPlain(db, "123456");
count = HibpPasswordsQuery.haveIBeenPwnedSha1(db, "FFFFFFBFAD0B653BDAC698485C6D105F3C3682B2");

List<RangeQueryResult> result = HibpPasswordsQuery.haveIBeenPwnedRange(db, "FFFFF");
```

These three methods open and close the database for each call. To speed up queries, instantiate the Xodus environment once and pass it as the first argument.

```java
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import ch.rasc.hibppasswords.query.RangeQueryResult;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;

Path db = Paths.get("..."); // Path to local database

try (Environment environment = Environments.newInstance(db.toFile())) {
  Integer count = HibpPasswordsQuery.haveIBeenPwnedPlain(environment, "123456");
  count = HibpPasswordsQuery.haveIBeenPwnedSha1(environment, "FFFFFFBFAD0B653BDAC698485C6D105F3C3682B2");

  List<RangeQueryResult> result = HibpPasswordsQuery.haveIBeenPwnedRange(environment, "FFFFF");
}
```

See the [Spring Boot example](https://github.com/ralscha/selfhost-hibp-passwords/blob/master/demo/src/main/java/ch/rasc/hibppasswords/Application.java).

### Command Line

The local database can also be queried with the import tool.

```sh
java -jar hibp-passwords-importer.jar query-plain 123456 <path_to_database>
java -jar hibp-passwords-importer.jar query-sha1 FFFFFFFEE791CBAC0F6305CAF0CEE06BBE131160 <path_to_database>
```

The command-line queries print the breach count or `not found`.

## HTTP Demo

The repository contains a Spring Boot demo with HTTP endpoints.

```sh
git clone https://github.com/ralscha/selfhost-hibp-passwords.git
cd selfhost-hibp-passwords/demo
JAVA_HOME=<path_to_jdk> ../mvnw spring-boot:run -Dspring-boot.run.arguments=--app.hibp-database-dir=<path_to_database>

# in another shell

curl http://localhost:8080/range/7C4A8
001CE884342580D934A29D94060B3796C30:2
00AD0FC3FA522D0474F9A28FD478C06669D:1
...

curl http://localhost:8080/plain/mypassword
38621

curl http://localhost:8080/sha1/7C4A8D7F20D435D1F9F7FFA96C28E216E98163
13
```
