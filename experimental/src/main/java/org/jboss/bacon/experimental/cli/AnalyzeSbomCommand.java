package org.jboss.bacon.experimental.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.jboss.bacon.experimental.impl.sbom.DaAvailabilityResolver;
import org.jboss.bacon.experimental.impl.sbom.GavMapper;
import org.jboss.bacon.experimental.impl.sbom.PathFilter;
import org.jboss.bacon.experimental.impl.sbom.SbomAnalysisConfig;
import org.jboss.bacon.experimental.impl.sbom.SbomAnalyzer;
import org.jboss.bacon.experimental.impl.sbom.SbomModule;
import org.jboss.pnc.bacon.common.ObjectHelper;
import org.jboss.pnc.bacon.common.exception.FatalException;

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

@Slf4j
@CommandLine.Command(
        name = "analyze-sbom",
        description = "Lists the maven modules contained in an SPDX SBOM along with their filesystem path")
public class AnalyzeSbomCommand extends ExperimentalCommand {

    @CommandLine.Parameters(description = "SPDX SBOM JSON file to analyze")
    protected Path sbom;

    @CommandLine.Option(
            names = { "--skip-da" },
            description = "Skip the Dependency Analyzer lookup and only list the modules")
    protected boolean skipDa;

    @CommandLine.Option(
            names = { "--config" },
            description = "analyze-sbom configuration file (e.g. GAV mappings for syft mis-detected coordinates)")
    protected Path config;

    @CommandLine.Option(
            names = { "--output", "-O" },
            description = "Write the result to this file instead of stdout")
    protected Path output;

    @Override
    public void run() {
        if (sbom == null || !Files.isRegularFile(sbom)) {
            throw new FatalException("SBOM file does not exist: " + sbom);
        }
        List<SbomModule> modules = new SbomAnalyzer().analyze(sbom);
        log.info("Found {} maven modules in {}", modules.size(), sbom);
        if (config != null) {
            if (!Files.isRegularFile(config)) {
                throw new FatalException("Config file does not exist: " + config);
            }
            SbomAnalysisConfig analysisConfig = SbomAnalysisConfig.load(config);
            modules = new PathFilter(analysisConfig.getPathFilters()).filter(modules);
            new GavMapper(analysisConfig).apply(modules);
            log.info("{} modules remain after applying config", modules.size());
        }
        if (!skipDa) {
            new DaAvailabilityResolver().resolve(modules);
        }
        write(modules);
    }

    private void write(List<SbomModule> modules) {
        try {
            if (output == null) {
                ObjectHelper.print(getJsonOutput(), modules);
            } else {
                Files.writeString(output, ObjectHelper.serialize(getJsonOutput(), modules));
                log.info("Wrote analysis of {} modules to {}", modules.size(), output);
            }
        } catch (JsonProcessingException e) {
            throw new FatalException("Unable to serialize analysis result", e);
        } catch (IOException e) {
            throw new FatalException("Unable to write result to " + output, e);
        }
    }
}
