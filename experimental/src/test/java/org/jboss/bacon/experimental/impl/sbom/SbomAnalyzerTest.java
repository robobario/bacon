package org.jboss.bacon.experimental.impl.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.junit.jupiter.api.Test;

class SbomAnalyzerTest {

    @Test
    void extractsMavenModulesWithPaths() throws URISyntaxException {
        List<SbomModule> modules = new SbomAnalyzer().analyze(fixture("sbom/sample-spdx.json"));

        assertThat(modules).containsExactlyInAnyOrder(
                new SbomModule(
                        "org.hdrhistogram",
                        "HdrHistogram",
                        "2.2.2",
                        "/opt/cruise-control/libs/HdrHistogram-2.2.2.jar"),
                new SbomModule(
                        "org.apache.kafka",
                        "kafka-clients",
                        "4.2.1",
                        "/opt/kafka/libs/kafka-clients-4.2.1.jar"));
    }

    @Test
    void parsesPurlWithQualifiers() {
        SbomModule module = SbomAnalyzer.parseMavenPurl("pkg:maven/org.apache.kafka/kafka-clients@4.2.1?type=jar");

        assertThat(module.getGroupId()).isEqualTo("org.apache.kafka");
        assertThat(module.getArtifactId()).isEqualTo("kafka-clients");
        assertThat(module.getVersion()).isEqualTo("4.2.1");
    }

    @Test
    void stripsSourceInfoPrefix() {
        String path = SbomAnalyzer
                .extractPath("acquired package info from installed java archive: /opt/kafka/libs/x-1.0.jar");

        assertThat(path).isEqualTo("/opt/kafka/libs/x-1.0.jar");
    }

    private Path fixture(String name) throws URISyntaxException {
        return Paths.get(getClass().getClassLoader().getResource(name).toURI());
    }
}
