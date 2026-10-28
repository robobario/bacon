package org.jboss.bacon.experimental.impl.sbom;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class SpdxDocument {

    private List<SpdxPackage> packages;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SpdxPackage {
        private String name;
        private String versionInfo;
        private String sourceInfo;
        private List<ExternalRef> externalRefs;
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ExternalRef {
        private String referenceType;
        @JsonProperty("referenceLocator")
        private String referenceLocator;
    }
}
