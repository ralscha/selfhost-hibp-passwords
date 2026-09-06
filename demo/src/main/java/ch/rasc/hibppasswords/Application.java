package ch.rasc.hibppasswords;

import java.util.stream.Collectors;

import jakarta.annotation.PreDestroy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseStatus;
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
	public String plain(@PathVariable("plainTextPassword") String plainTextPassword) {
		Integer count = HibpPasswordsQuery.haveIBeenPwnedPlain(this.environment,
				plainTextPassword);
		if (count != null) {
			return count.toString();
		}
		return "0";
	}

	@GetMapping(path = "/sha1/{sha1Hash}", produces = "text/plain")
	public String sha1(@PathVariable("sha1Hash") String sha1Hash) {
		Integer count = HibpPasswordsQuery.haveIBeenPwnedSha1(this.environment, sha1Hash);
		if (count != null) {
			return count.toString();
		}
		return "0";
	}

	@ExceptionHandler(IllegalArgumentException.class)
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public String invalidInput(IllegalArgumentException exception) {
		return exception.getMessage();
	}
}
