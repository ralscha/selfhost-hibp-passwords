# Self-host Have I Been Pwned Passwords

Tool for importing the Have I Been Pwned Passwords list into a local [Jetbrain Xodus database](https://github.com/JetBrains/xodus). Java library for querying the database. 


## Prerequisites 
   - Sufficient drive storage. About 57GB during import, 24GB for normal operation.

## Import

   1. Download Java 17 or newer. JRE is sufficient
       - https://adoptium.net/
       - https://jdk.java.net/17/
       - https://aws.amazon.com/corretto/
       - https://www.azul.com/downloads/?package=jdk

   2. Download the Pwned Passwords. Either use the [official downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) or [my downloader](https://github.com/ralscha/hibp-passwords-downloader) written in Go. The importer expects the hashes in individual files. 

   3. Download [importer](https://github.com/ralscha/selfhost-hibp-passwords/releases/download/importer-1.1.0/hibp-passwords-importer.jar)
   4. Run the import tool. Point it to the directory that contains the downloaded hash files        
      `java -jar hibp-passwords-importer.jar import <hashesdir> <database_directory_name>`


## Query

### Library

Add library to your project.

```
<!-- Maven -->
<dependency>
   <groupId>ch.rasc.hibppasswords</groupId>
   <artifactId>query</artifactId>
   <version>1.0.0</version>
</dependency>
```      

```
// Gradle
dependencies {
    compile 'ch.rasc.hibppasswords:query:1.0.0'
}
````

An application can query the database with a plain text password or SHA-1 hash. Both
methods return either how many times a string or SHA-1 hash appears in the data set, or `null` if
the given password is not found.

`haveIBeenPwnedRange` implements a k-Anonymity model that supports searching with a partial hash:    
https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

```java
import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import ch.rasc.hibppasswords.query.RangeQueryResult;
import java.nio.file.Path;

Path db = Paths.get("..."); // Path to local database
Integer count = HibpPasswordsQuery.haveIBeenPwnedPlain(db, "123456");
count = HibpPasswordsQuery.haveIBeenPwnedSha1(db, "FFFFFFBFAD0B653BDAC698485C6D105F3C3682B2");

List<RangeQueryResult> result = HibpPasswordsQuery.haveIBeenPwnedRange(db, "FFFFF");
```
These three methods open and close the database for each call. To speed up queries, an application can instantiate the Xodus environment once and pass it as the first argument. 

```java
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;

Path db = Paths.get("..."); // Path to local database

try (Environment environment = Environments.newInstance(db.toFile())) {
  Integer count = HibpPasswordsQuery.haveIBeenPwnedPlain(environment, "123456");
  count = HibpPasswordsQuery.haveIBeenPwnedSha1(environment, "FFFFFFBFAD0B653BDAC698485C6D105F3C3682B2");

  List<RangeQueryResult> result = HibpPasswordsQuery.haveIBeenPwnedRange(environment, "FFFFF");
}
```
See [Spring Boot example](https://github.com/ralscha/selfhost-hibp-passwords/blob/master/demo/src/main/java/ch/rasc/hibppasswords/Application.java)



### Command Line

The local database can be queried with the import tool.
  - With plain text password:    
    `java -jar hibp-passwords-importer.jar query-plain 123456 <path_to_database>`

  - With SHA1 hash:    
    `java -jar hibp-passwords-importer.jar query-sha1 FFFFFFFEE791CBAC0F6305CAF0CEE06BBE131160 <path_to_database>`


## HTTP Demo

The repository hosts a Spring Boot demo with the HTTP endpoints. 

```sh
$ git clone https://github.com/ralscha/selfhost-hibp-passwords.git
$ cd selfhost-hibp-passwords/demo
$ JAVA_HOME=<path_to_jdk> ../mvnw spring-boot:run -Dspring-boot.run.arguments=--app.hibp-database-dir=<path_to_database>


# in another shell

$ curl http://localhost:8080/range/7C4A8
001CE884342580D934A29D94060B3796C30:2
00AD0FC3FA522D0474F9A28FD478C06669D:1
...

$ curl http://localhost:8080/plain/mypassword
38621

$ curl http://localhost:8080/sha1/7C4A8D7F20D435D1F9F7FFA96C28E216E98163
13
```
