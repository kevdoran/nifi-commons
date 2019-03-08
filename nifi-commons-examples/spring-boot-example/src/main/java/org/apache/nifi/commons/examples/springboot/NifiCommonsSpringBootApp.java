package org.apache.nifi.commons.examples.springboot;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.util.Properties;

@SpringBootApplication(scanBasePackages = "org.apache.nifi.commons")
public class NifiCommonsSpringBootApp {

    public static void main(String[] args) {
        //TODO simplify
        configureApplication(new SpringApplicationBuilder()).run(args);
    }

    private static SpringApplicationBuilder configureApplication(SpringApplicationBuilder applicationBuilder) {
        return applicationBuilder
                .sources(NifiCommonsSpringBootApp.class)
                .properties(new Properties());
    }

}
