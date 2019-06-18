package ch.rasc.hibppasswords;

import java.util.stream.Collectors;

import javax.annotation.PreDestroy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import ch.rasc.hibppasswords.query.HibpPasswordsQuery;
import jetbrains.exodus.env.Environment;
import jetbrains.exodus.env.Environments;

@SpringBootApplication
@RestController
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	private final Environment environment;

	Application(AppConfig appConfig) {
		this.environment = Environments.newInstance(appConfig.getHibpDatabaseDir());
	}

	@PreDestroy
	public void destroy() {
		if (this.environment != null) {
			this.environment.close();
		}
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
}
