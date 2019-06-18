# Self-host Have I Been Pwned Passwords

Tool for importing the Have I Been Pwned Passwords list into a local [Jetbrain Xodus database](https://github.com/JetBrains/xodus). Java library for quering the database. 


## Prerequisites 
   - Sufficient drive storage. About 38GB during import, 15GB for normal operation.

## Automatic import 
See importpasswords.sh, a bash script for Debian/Ubuntu that runs all the
necessary import steps automatically:
   - Downloads passwords file
   - Downloads Java
   - Builds importer from source
   - Imports passwords file
   - Deletes all unnecessary files and directories afterwards

## Manual Import

   1. Download Java 11 JVM or newer
       - https://adoptopenjdk.net/
       - https://jdk.java.net/12/
       - https://aws.amazon.com/corretto/
       - https://www.azul.com/downloads/zulu/

   2. Download the Pwned Passwords list. The import tool requires the **ordered by hash** version.       
       - https://haveibeenpwned.com/Passwords    

      Download the file with torrent, only download it with the Cloudflare direct link if torrent does not work.
   3. Download importer: ..........
   4. Extract passwords file with 7z
   5. Run import tool ...
   6. Clean up. Passwords files (7z and txt) are no longer needed after the import and can be deleted. 


## Query

Add library to your project

<!-- in Maven project -->
<dependency>
    <groupId>org.jetbrains.xodus</groupId>
    <artifactId>xodus-openAPI</artifactId>
    <version>1.3.0</version>
</dependency>
// in Gradle project
dependencies {
    compile 'org.jetbrains.xodus:xodus-openAPI:1.3.0'
}

Call.....


The import tool also allows you to query the database 
  - With plain text password
  - With SHA1 hash
