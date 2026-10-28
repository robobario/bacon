package org.jboss.bacon.experimental.impl.sbom;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SbomAnalyzer {

    private static final String MAVEN_PURL_PREFIX = "pkg:maven/";

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<SbomModule> analyze(Path sbomFile) {
        SpdxDocument document = read(sbomFile);
        if (document.getPackages() == null) {
            return List.of();
        }
        return document.getPackages()
                .stream()
                .map(this::toModule)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
    }

    private SpdxDocument read(Path sbomFile) {
        try {
            return objectMapper.readValue(sbomFile.toFile(), SpdxDocument.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Unable to read SBOM file " + sbomFile, e);
        }
    }

    private Optional<SbomModule> toModule(SpdxDocument.SpdxPackage pkg) {
        return mavenPurl(pkg)
                .map(SbomAnalyzer::parseMavenPurl)
                .map(gav -> {
                    gav.setPath(extractPath(pkg.getSourceInfo()));
                    return gav;
                });
    }

    private Optional<String> mavenPurl(SpdxDocument.SpdxPackage pkg) {
        if (pkg.getExternalRefs() == null) {
            return Optional.empty();
        }
        return pkg.getExternalRefs()
                .stream()
                .filter(ref -> "purl".equals(ref.getReferenceType()))
                .map(SpdxDocument.ExternalRef::getReferenceLocator)
                .filter(locator -> locator != null && locator.startsWith(MAVEN_PURL_PREFIX))
                .findFirst();
    }

    static SbomModule parseMavenPurl(String purl) {
        String coordinates = purl.substring(MAVEN_PURL_PREFIX.length());
        coordinates = stripAfter(coordinates, '?');
        coordinates = stripAfter(coordinates, '#');

        int at = coordinates.indexOf('@');
        String version = at >= 0 ? decode(coordinates.substring(at + 1)) : null;
        String groupAndArtifact = at >= 0 ? coordinates.substring(0, at) : coordinates;

        int slash = groupAndArtifact.indexOf('/');
        if (slash < 0) {
            throw new IllegalArgumentException("Malformed maven purl, missing artifact: " + purl);
        }
        String groupId = decode(groupAndArtifact.substring(0, slash));
        String artifactId = decode(groupAndArtifact.substring(slash + 1));

        SbomModule module = new SbomModule();
        module.setGroupId(groupId);
        module.setArtifactId(artifactId);
        module.setVersion(version);
        return module;
    }

    static String extractPath(String sourceInfo) {
        if (sourceInfo == null) {
            return null;
        }
        int separator = sourceInfo.lastIndexOf(": ");
        return separator >= 0 ? sourceInfo.substring(separator + 2).trim() : sourceInfo.trim();
    }

    private static String stripAfter(String value, char marker) {
        int index = value.indexOf(marker);
        return index >= 0 ? value.substring(0, index) : value;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
