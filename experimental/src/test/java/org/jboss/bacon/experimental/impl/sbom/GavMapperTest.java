package org.jboss.bacon.experimental.impl.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.junit.jupiter.api.Test;

class GavMapperTest {

    @Test
    void remapsOnGroupAndArtifactForAnyVersion() throws URISyntaxException {
        SbomModule module = new SbomModule("com.sun", "activation", "1.1.1", "/opt/kafka/libs/activation-1.1.1.jar");

        mapper().apply(List.of(module));

        assertThat(module.getGroupId()).isEqualTo("javax.activation");
        assertThat(module.getArtifactId()).isEqualTo("activation");
        assertThat(module.getVersion()).isEqualTo("1.1.1");
    }

    @Test
    void remapsVersionWhenMappingPinsIt() throws URISyntaxException {
        SbomModule module = new SbomModule("org.example", "legacy", "1.0", "/opt/kafka/libs/legacy-1.0.jar");

        mapper().apply(List.of(module));

        assertThat(module.getGroupId()).isEqualTo("org.example");
        assertThat(module.getArtifactId()).isEqualTo("renamed");
        assertThat(module.getVersion()).isEqualTo("2.0");
    }

    @Test
    void leavesVersionMismatchUntouched() throws URISyntaxException {
        SbomModule module = new SbomModule("org.example", "legacy", "9.9", "/opt/kafka/libs/legacy-9.9.jar");

        mapper().apply(List.of(module));

        assertThat(module.getArtifactId()).isEqualTo("legacy");
        assertThat(module.getVersion()).isEqualTo("9.9");
    }

    @Test
    void leavesUnmatchedModuleUntouched() throws URISyntaxException {
        SbomModule module = new SbomModule("org.apache.kafka", "kafka-clients", "4.2.1", "/opt/kafka/libs/x.jar");

        mapper().apply(List.of(module));

        assertThat(module.getGroupId()).isEqualTo("org.apache.kafka");
        assertThat(module.getArtifactId()).isEqualTo("kafka-clients");
    }

    private GavMapper mapper() throws URISyntaxException {
        return new GavMapper(SbomAnalysisConfig.load(fixture("sbom/sample-config.yaml")));
    }

    private Path fixture(String name) throws URISyntaxException {
        return Paths.get(getClass().getClassLoader().getResource(name).toURI());
    }
}
