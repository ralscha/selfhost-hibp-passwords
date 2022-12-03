package ch.rasc.hibppasswords;

import java.io.File;

import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app")
@Component
@Validated
public class AppConfig {

	@NotNull
	private File hibpDatabaseDir;

	public File getHibpDatabaseDir() {
		return this.hibpDatabaseDir;
	}

	public void setHibpDatabaseDir(File hibpDatabaseDir) {
		this.hibpDatabaseDir = hibpDatabaseDir;
	}

}
