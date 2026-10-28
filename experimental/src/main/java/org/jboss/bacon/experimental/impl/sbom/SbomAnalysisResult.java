package org.jboss.bacon.experimental.impl.sbom;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SbomAnalysisResult {
    private List<SbomModule> modules;
}
