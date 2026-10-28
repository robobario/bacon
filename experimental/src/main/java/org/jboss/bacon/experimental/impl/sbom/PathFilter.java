package org.jboss.bacon.experimental.impl.sbom;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

import org.jboss.bacon.experimental.impl.sbom.SbomAnalysisConfig.PathFilters;

import lombok.extern.slf4j.Slf4j;

/**
 * Keeps only the SBOM modules whose filesystem path passes the configured glob filters. When include patterns are set a
 * path must match at least one; any matching exclude pattern then drops it (exclude wins).
 */
@Slf4j
public class PathFilter {

    private final List<PathMatcher> includes;
    private final List<PathMatcher> excludes;

    public PathFilter(PathFilters filters) {
        this.includes = compile(filters.getInclude());
        this.excludes = compile(filters.getExclude());
    }

    public List<SbomModule> filter(List<SbomModule> modules) {
        return modules.stream().filter(this::keep).collect(Collectors.toList());
    }

    private boolean keep(SbomModule module) {
        Path path = Paths.get(module.getPath() == null ? "" : module.getPath());
        if (!includes.isEmpty() && includes.stream().noneMatch(matcher -> matcher.matches(path))) {
            return false;
        }
        if (excludes.stream().anyMatch(matcher -> matcher.matches(path))) {
            log.debug("Excluding module at {}", module.getPath());
            return false;
        }
        return true;
    }

    private static List<PathMatcher> compile(List<String> globs) {
        return globs.stream()
                .map(glob -> FileSystems.getDefault().getPathMatcher("glob:" + glob))
                .collect(Collectors.toList());
    }
}
