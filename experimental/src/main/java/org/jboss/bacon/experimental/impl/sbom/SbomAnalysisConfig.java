package org.jboss.bacon.experimental.impl.sbom;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.jboss.pnc.bacon.common.exception.FatalException;
import org.yaml.snakeyaml.Yaml;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class SbomAnalysisConfig {

    private List<GavMapping> gavMappings = new ArrayList<>();

    public static SbomAnalysisConfig load(Path configFile) {
        Yaml yaml = new Yaml();
        try (BufferedReader reader = Files.newBufferedReader(configFile)) {
            SbomAnalysisConfig config = yaml.loadAs(reader, SbomAnalysisConfig.class);
            return config == null ? new SbomAnalysisConfig() : config;
        } catch (IOException e) {
            throw new FatalException("Unable to load analyze-sbom config file " + configFile, e);
        }
    }

    @Data
    @NoArgsConstructor
    public static class GavMapping {
        private GavCoordinates from;
        private GavCoordinates to;
    }

    @Data
    @NoArgsConstructor
    public static class GavCoordinates {
        private String groupId;
        private String artifactId;
        private String version;
    }
}
