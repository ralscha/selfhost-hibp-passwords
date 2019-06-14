package ch.rasc.hibppasswords;

import java.io.File;

import javax.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app")
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
