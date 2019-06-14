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

	@GetMapping(path = "/range/{first5hashchars}", produces = "text/plain")
	public String range(@PathVariable("first5hashchars") String first5hashchars) {

		return HibpPasswordsQuery.haveIBeenPwnedRange(this.environment, first5hashchars)
				.stream().map(HibpPasswordsQuery.stringResultMapper())
				.collect(Collectors.joining("\n"));

	}
}
