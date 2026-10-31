package ch.rasc.hibppasswords;

import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import jakarta.annotation.PreDestroy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import jetbrains.exodus.env.Environment;

@SpringBootApplication
@RestController
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	private final Environment environment;

	Application(AppConfig appConfig) {
		this.environment = HibpPasswordsQuery
				.openDatabase(appConfig.getHibpDatabaseDir().toPath());
	}

	@PreDestroy
	public void destroy() {
		this.environment.close();
	}

	@GetMapping(path = "/range/{first5HashChars}", produces = "text/plain")
	public String range(@PathVariable("first5HashChars") String first5HashChars) {
		return HibpPasswordsQuery.haveIBeenPwnedRange(this.environment, first5HashChars)
				.stream().map(HibpPasswordsQuery.stringResultMapper())
				.collect(Collectors.joining("\n"));
	}

	@GetMapping(path = "/plain/{plainTextPassword}", produces = "text/plain")
	public ResponseEntity<String> plain(
			@PathVariable("plainTextPassword") String plainTextPassword) {
		return countResponse(HibpPasswordsQuery.haveIBeenPwnedPlain(this.environment,
				plainTextPassword));
	}

	@PostMapping(path = "/plain", consumes = "text/plain", produces = "text/plain")
	public ResponseEntity<String> plainPost(@RequestBody(required = false) byte[] password) {
		String plainTextPassword = password == null ? ""
				: new String(password, StandardCharsets.UTF_8);
		return countResponse(HibpPasswordsQuery.haveIBeenPwnedPlain(this.environment,
				plainTextPassword));
	}

	@GetMapping(path = "/sha1/{sha1Hash}", produces = "text/plain")
	public ResponseEntity<String> sha1(@PathVariable("sha1Hash") String sha1Hash) {
		return countResponse(HibpPasswordsQuery.haveIBeenPwnedSha1(this.environment,
				sha1Hash));
	}

	private static ResponseEntity<String> countResponse(Integer count) {
		return ResponseEntity.ok().cacheControl(CacheControl.noStore())
				.body(count != null ? count.toString() : "0");
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<String> invalidInput(IllegalArgumentException exception) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.cacheControl(CacheControl.noStore()).body(exception.getMessage());
	}
}
