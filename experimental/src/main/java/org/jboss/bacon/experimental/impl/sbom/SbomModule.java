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
}
