/*
 * This file is part of dependency-check-core.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.analyzer;

import mockit.Expectations;
import mockit.Mock;
import mockit.MockUp;
import mockit.Mocked;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.dependencycheck.data.central.CentralSearch;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.utils.Settings;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the CentralAnalyzer.
 */
public class CentralAnalyzerTest {

    private static final String SHA1_SUM = "my-sha1-sum";

    @BeforeClass
    public static void beforeClass() {
        doNotSleepBetweenRetries();
    }

    @Test
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsWithoutException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        final List<MavenArtifact> expectedMavenArtifacts = Collections.emptyList();
        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                returns(expectedMavenArtifacts, expectedMavenArtifacts);
            }
        };

        final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

        assertEquals(expectedMavenArtifacts, actualMavenArtifacts);
    }

    @Test
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsWithSporadicIOException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        final List<MavenArtifact> expectedMavenArtifacts = Collections.emptyList();
        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                //result = new IOException("Could not connect to MavenCentral (500): Internal Server Error");
                result = expectedMavenArtifacts;
            }
        };

        final List<MavenArtifact> actualMavenArtifacts = instance.fetchMavenArtifacts(dependency);

        assertEquals(expectedMavenArtifacts, actualMavenArtifacts);
    }

    @Test(expected = FileNotFoundException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsRethrowsFileNotFoundException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                result = new FileNotFoundException("Artifact not found in Central");
            }
        };

        instance.fetchMavenArtifacts(dependency);
    }

    @Test(expected = IOException.class)
    @SuppressWarnings("PMD.NonStaticInitializer")
    public void testFetchMavenArtifactsAlwaysThrowsIOException(@Mocked final CentralSearch centralSearch,
            @Mocked final Dependency dependency)
            throws IOException {

        CentralAnalyzer instance = new CentralAnalyzer();
        instance.setCentralSearch(centralSearch);
        specifySha1SumFor(dependency);

        new Expectations() {
            {
                centralSearch.searchSha1(SHA1_SUM);
                result = new IOException("no internet connection");
            }
        };

        instance.fetchMavenArtifacts(dependency);
    }

    /*
    @Test
    public void testFetchMavenArtifactsThroughConsole() throws IOException {
        // setup
        String sha1 = "a5ef8806b6d79fb2969e5d2b1c68c597b24e9923";
        String consoleURL = "https://localhost:8443/hdiv-console-services";

        // when
        List<MavenArtifact> artifacts = searchThroughConsole(consoleURL, sha1);

        // then
        assertTrue(artifacts != null);
    }

    private static List<MavenArtifact> searchThroughConsole(final String consoleURL, final String sha1) throws IOException {
        Settings settings = new Settings();
        settings.setString(Settings.KEYS.ANALYZER_CENTRAL_URL,
                consoleURL + "/uritemplate/select?_url=https://search.maven.org/solrsearch");
        settings.setString(Settings.KEYS.ANALYZER_CENTRAL_QUERY, "%s&q=1:%%22%s%%22&wt=xml");
        settings.setString(Settings.KEYS.ANALYZER_CENTRAL_SECURE_CONTENT_URL,
                consoleURL + "/uritemplate/remotecontent?_url=https://search.maven.org&filepath=");
        settings.setString(Settings.KEYS.ANALYZER_CENTRAL_INSECURE_CONTENT_URL,
                consoleURL + "/uritemplate/remotecontent?_url=http://search.maven.org&filepath=");
        settings.setArrayIfNotEmpty(Settings.KEYS.SSL_TRUSTED_HOSTS, new String[] { consoleURL });

        // when
        CentralSearch centralSearch = new CentralSearch(settings);
        return centralSearch.searchSha1(sha1);
    }
    */

    /**
     * We do not want to waste time in unit tests.
     */
    private static void doNotSleepBetweenRetries() {
        new MockUp<Thread>() {
            @Mock
            void sleep(long millis) {
                // do not sleep
            }
        };
    }

    /**
     * Specifies the mock dependency's SHA1 sum.
     *
     * @param dependency then dependency
     */
    @SuppressWarnings("PMD.NonStaticInitializer")
    private void specifySha1SumFor(final Dependency dependency) {
        new Expectations() {
            {
                dependency.getSha1sum();
                returns(SHA1_SUM, SHA1_SUM);
            }
        };
    }
}
