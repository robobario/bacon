package org.jboss.bacon.experimental.impl.sbom;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.maven.artifact.versioning.ComparableVersion;
import org.jboss.bacon.da.DaHelper;
import org.jboss.bacon.da.rest.endpoint.LookupApi;
import org.jboss.da.lookup.model.MavenVersionsRequest;
import org.jboss.da.lookup.model.MavenVersionsResult;
import org.jboss.da.model.rest.GAV;
import org.jboss.pnc.api.constants.versions.VersionDistanceRule;
import org.jboss.pnc.api.constants.versions.VersionFilter;
import org.jboss.pnc.common.version.VersionParser;

import lombok.extern.slf4j.Slf4j;

/**
 * Enriches SBOM modules with the latest persistent and temporary DA build that shares their upstream (unsuffixed)
 * version.
 */
@Slf4j
public class DaAvailabilityResolver {

    private static final String MODE_PERSISTENT = "PERSISTENT";
    private static final String MODE_TEMPORARY = "TEMPORARY";

    private final LookupApi lookupApi;
    private final VersionParser versionParser = new VersionParser("redhat", "temporary-redhat");

    public DaAvailabilityResolver() {
        this(DaHelper.createLookupApi());
    }

    DaAvailabilityResolver(LookupApi lookupApi) {
        this.lookupApi = lookupApi;
    }

    public void resolve(List<SbomModule> modules) {
        Set<GAV> gavs = modules.stream().map(DaAvailabilityResolver::toGav).collect(Collectors.toSet());
        if (gavs.isEmpty()) {
            return;
        }
        Map<GAV, List<String>> persistent = findAvailableVersions(gavs, MODE_PERSISTENT);
        Map<GAV, List<String>> temporary = findAvailableVersions(gavs, MODE_TEMPORARY);

        for (SbomModule module : modules) {
            GAV gav = toGav(module);
            module.setLatestPersistentVersion(
                    latestMatching(persistent.getOrDefault(gav, List.of()), module.getVersion()));
            module.setLatestTemporaryVersion(
                    latestMatching(temporary.getOrDefault(gav, List.of()), module.getVersion()));
        }
    }

    private Map<GAV, List<String>> findAvailableVersions(Set<GAV> gavs, String mode) {
        MavenVersionsRequest request = MavenVersionsRequest.builder()
                .mode(mode)
                .filter(VersionFilter.ALL)
                .artifacts(gavs)
                .distanceRule(VersionDistanceRule.CLOSEST_BY_PARTS)
                .build();
        Set<MavenVersionsResult> results = DaHelper
                .executeWithRetry(() -> lookupApi.versionsMaven(request), "versionsMaven " + mode);
        return results.stream()
                .collect(Collectors.toMap(MavenVersionsResult::getGav, MavenVersionsResult::getAvailableVersions));
    }

    private String latestMatching(List<String> availableVersions, String sbomVersion) {
        String upstream = versionParser.parse(sbomVersion).unsuffixedVersion();
        return availableVersions.stream()
                .filter(available -> versionParser.parse(available).unsuffixedVersion().equals(upstream))
                .max(Comparator.comparing(ComparableVersion::new))
                .orElse(null);
    }

    private static GAV toGav(SbomModule module) {
        return new GAV(module.getGroupId(), module.getArtifactId(), module.getVersion());
    }
}
