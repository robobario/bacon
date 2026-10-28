package org.jboss.bacon.experimental.impl.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.jboss.bacon.experimental.impl.sbom.SbomAnalysisConfig.PathFilters;
import org.junit.jupiter.api.Test;

class PathFilterTest {

    private final SbomModule kafka = new SbomModule("g", "a", "1", "/opt/kafka/libs/a-1.jar");
    private final SbomModule cruise = new SbomModule("g", "b", "1", "/opt/cruise-control/libs/b-1.jar");

    @Test
    void excludeDropsMatchingPaths() {
        PathFilters filters = new PathFilters();
        filters.setExclude(List.of("**/cruise-control/**"));

        List<SbomModule> result = new PathFilter(filters).filter(List.of(kafka, cruise));

        assertThat(result).containsExactly(kafka);
    }

    @Test
    void includeKeepsOnlyMatchingPaths() {
        PathFilters filters = new PathFilters();
        filters.setInclude(List.of("/opt/kafka/**"));

        List<SbomModule> result = new PathFilter(filters).filter(List.of(kafka, cruise));

        assertThat(result).containsExactly(kafka);
    }

    @Test
    void excludeWinsOverInclude() {
        PathFilters filters = new PathFilters();
        filters.setInclude(List.of("/opt/**"));
        filters.setExclude(List.of("**/cruise-control/**"));

        List<SbomModule> result = new PathFilter(filters).filter(List.of(kafka, cruise));

        assertThat(result).containsExactly(kafka);
    }

    @Test
    void emptyFiltersKeepEverything() {
        List<SbomModule> result = new PathFilter(new PathFilters()).filter(List.of(kafka, cruise));

        assertThat(result).containsExactlyInAnyOrder(kafka, cruise);
    }
}
