package org.jboss.bacon.experimental.impl.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;

import org.jboss.bacon.da.rest.endpoint.LookupApi;
import org.jboss.da.lookup.model.MavenLatestRequest;
import org.jboss.da.lookup.model.MavenLatestResult;
import org.jboss.da.lookup.model.MavenLookupRequest;
import org.jboss.da.lookup.model.MavenLookupResult;
import org.jboss.da.lookup.model.MavenVersionsRequest;
import org.jboss.da.lookup.model.MavenVersionsResult;
import org.jboss.da.lookup.model.NPMLookupRequest;
import org.jboss.da.lookup.model.NPMLookupResult;
import org.jboss.da.lookup.model.NPMVersionsRequest;
import org.jboss.da.lookup.model.NPMVersionsResult;
import org.jboss.da.model.rest.GAV;
import org.junit.jupiter.api.Test;

class DaAvailabilityResolverTest {

    private static final GAV BAR = new GAV("com.foo", "bar", "0.2.1");
    private static final GAV BAZ = new GAV("com.foo", "baz", "9.9.9");

    @Test
    void picksLatestMatchingUpstreamVersionPerMode() {
        LookupApi lookupApi = new StubLookupApi();

        SbomModule barModule = new SbomModule("com.foo", "bar", "0.2.1", "/opt/kafka/libs/bar.jar");
        SbomModule bazModule = new SbomModule("com.foo", "baz", "9.9.9", "/opt/kafka/libs/baz.jar");

        new DaAvailabilityResolver(lookupApi).resolve(List.of(barModule, bazModule));

        assertThat(barModule.getLatestPersistentVersion()).isEqualTo("0.2.1.redhat-7");
        assertThat(barModule.getLatestTemporaryVersion()).isEqualTo("0.2.1.temporary-redhat-5");
        assertThat(bazModule.getLatestPersistentVersion()).isNull();
        assertThat(bazModule.getLatestTemporaryVersion()).isNull();
    }

    private static class StubLookupApi implements LookupApi {
        @Override
        public Set<MavenVersionsResult> versionsMaven(MavenVersionsRequest request) {
            if ("PERSISTENT".equals(request.getMode())) {
                return Set.of(
                        new MavenVersionsResult(BAR, List.of("0.2.1.redhat-3", "0.2.1.redhat-7", "0.2.0.redhat-1")),
                        new MavenVersionsResult(BAZ, List.of("9.9.8.redhat-1")));
            }
            return Set.of(
                    new MavenVersionsResult(BAR, List.of("0.2.1.temporary-redhat-5")),
                    new MavenVersionsResult(BAZ, List.of()));
        }

        @Override
        public Set<MavenLookupResult> lookupMaven(MavenLookupRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<MavenLatestResult> lookupMaven(MavenLatestRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<NPMLookupResult> lookupNPM(NPMLookupRequest request) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Set<NPMVersionsResult> versionsNPM(NPMVersionsRequest request) {
            throw new UnsupportedOperationException();
        }
    }
}
