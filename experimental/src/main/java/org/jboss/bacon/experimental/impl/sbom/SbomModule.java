package org.jboss.bacon.experimental.impl.sbom;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SbomModule {
    private String groupId;
    private String artifactId;
    private String version;
    private String path;
    private String latestPersistentVersion;
    private String latestTemporaryVersion;

    public SbomModule(String groupId, String artifactId, String version, String path) {
        this(groupId, artifactId, version, path, null, null);
    }
}
