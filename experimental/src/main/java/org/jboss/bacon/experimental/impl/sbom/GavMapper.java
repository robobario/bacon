package org.jboss.bacon.experimental.impl.sbom;

import java.util.List;

import org.jboss.bacon.experimental.impl.sbom.SbomAnalysisConfig.GavCoordinates;
import org.jboss.bacon.experimental.impl.sbom.SbomAnalysisConfig.GavMapping;
import org.jboss.pnc.bacon.common.exception.FatalException;

import lombok.extern.slf4j.Slf4j;

/**
 * Rewrites SBOM module coordinates that syft mis-detects (e.g. com.sun:activation to javax.activation:activation) so
 * that the DA lookup uses the real artifact coordinates.
 */
@Slf4j
public class GavMapper {

    private final List<GavMapping> mappings;

    public GavMapper(SbomAnalysisConfig config) {
        this.mappings = config.getGavMappings();
        this.mappings.forEach(GavMapper::validate);
    }

    public void apply(List<SbomModule> modules) {
        modules.forEach(this::apply);
    }

    private void apply(SbomModule module) {
        for (GavMapping mapping : mappings) {
            if (matches(mapping.getFrom(), module)) {
                GavCoordinates to = mapping.getTo();
                log.debug(
                        "Remapping {}:{}:{} to {}:{}",
                        module.getGroupId(),
                        module.getArtifactId(),
                        module.getVersion(),
                        to.getGroupId(),
                        to.getArtifactId());
                module.setGroupId(to.getGroupId());
                module.setArtifactId(to.getArtifactId());
                if (to.getVersion() != null) {
                    module.setVersion(to.getVersion());
                }
                return;
            }
        }
    }

    private static boolean matches(GavCoordinates from, SbomModule module) {
        return from.getGroupId().equals(module.getGroupId())
                && from.getArtifactId().equals(module.getArtifactId())
                && (from.getVersion() == null || from.getVersion().equals(module.getVersion()));
    }

    private static void validate(GavMapping mapping) {
        if (incomplete(mapping.getFrom()) || incomplete(mapping.getTo())) {
            throw new FatalException("gavMappings entries require from and to with groupId and artifactId");
        }
    }

    private static boolean incomplete(GavCoordinates coordinates) {
        return coordinates == null || coordinates.getGroupId() == null || coordinates.getArtifactId() == null;
    }
}
