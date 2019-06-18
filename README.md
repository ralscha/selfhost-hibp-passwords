# Self-host Have I Been Pwned Passwords

Tool for importing the Have I Been Pwned Passwords list into a local [Jetbrain Xodus database](https://github.com/JetBrains/xodus). Java library for quering the database. 


## Prerequisites 
   - Sufficient drive storage. About 38GB during import, 15GB for normal operation.

## Import


### With batch

See [`importpasswords.sh`](https://github.com/ralscha/selfhost-hibp-passwords/blob/master/importpasswords.sh), a bash script for Debian/Ubuntu that runs all the
necessary import steps automatically:
   - Download passwords file
   - Download Java
   - Download importer
   - Import passwords file
   - Delete all unnecessary files and directories afterwards

### Manual

   1. Download Java 11 or newer. JRE is sufficient
       - https://adoptopenjdk.net/
       - https://jdk.java.net/12/
       - https://aws.amazon.com/corretto/
       - https://www.azul.com/downloads/zulu/

   2. Download the Pwned Passwords list. The import tool requires the **SHA-1 ordered by hash** version.       
       - https://haveibeenpwned.com/Passwords    

      Download the file with torrent, only download it with the Cloudflare direct link if torrent does not work.
   3. Download [importer](https://github.com/ralscha/selfhost-hibp-passwords/releases/download/query-1.0.0/hibp-passwords-importer.jar)
   4. Extract passwords file with 7z
   5. Run import tool: `java -jar hibp-passwords-importer.jar import pwned-passwords-sha1-ordered-by-hash-v4.txt hibp-passwords`
   6. Delete passwords file. Both files (7z and txt) are no longer needed.


## Query

### Library

Add library to your project

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





### Command Line

The local database can be queried with the import tool.
  - With plain text password:    
    `java -jar hibp-passwords-importer.jar query-plain 123456 <path_to_database>`

  - With SHA1 hash:    
    `java -jar hibp-passwords-importer.jar query-sha1 FFFFFFFEE791CBAC0F6305CAF0CEE06BBE131160 <path_to_database>`
