package com.driverscanner.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LocalRequestGuardFilterTest {

    private static final int PORT = 8080;
    private static final String GOOD_HOST = "localhost:" + PORT;

    @RestController
    static class Probe {
        @GetMapping("/api/probe") String read() { return "ok"; }
        @PostMapping("/api/probe") String write() { return "done"; }
    }

    private ApiTokenProvider tokens;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        tokens = new ApiTokenProvider();
        LocalRequestGuardFilter filter =
            new LocalRequestGuardFilter(PORT, List.of("localhost", "127.0.0.1"), tokens);
        mvc = MockMvcBuilders.standaloneSetup(new Probe(), new ApiTokenController(tokens))
            .addFilters(filter)
            .build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"evil.com:8080", "localhost.evil.com:8080", "localhost:9999",
        "192.168.1.5:8080", "localhost", "[::1]:8080", "localhost:8080:8080", ""})
    void rejectsForeignOrMalformedHost(String host) throws Exception {
        mvc.perform(get("/api/probe").header("Host", host)).andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost:8080", "LOCALHOST:8080", "127.0.0.1:8080"})
    void allowsLoopbackHostGet(String host) throws Exception {
        mvc.perform(get("/api/probe").header("Host", host)).andExpect(status().isOk());
    }

    @Test
    void ipv6BracketHostAllowedWhenListed() throws Exception {
        MockMvc v6 = MockMvcBuilders.standaloneSetup(new Probe())
            .addFilters(new LocalRequestGuardFilter(PORT, List.of("::1"), tokens))
            .build();
        v6.perform(get("/api/probe").header("Host", "[::1]:8080")).andExpect(status().isOk());
    }

    @Test
    void postWithoutTokenRejected() throws Exception {
        mvc.perform(post("/api/probe").header("Host", GOOD_HOST)).andExpect(status().isForbidden());
    }

    @Test
    void postWithWrongTokenRejected() throws Exception {
        mvc.perform(post("/api/probe").header("Host", GOOD_HOST).header("X-DD-Token", "nope"))
            .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://evil.com", "http://localhost.evil.com:8080",
        "http://localhost:9999", "null"})
    void postWithTokenAndForeignOriginRejected(String origin) throws Exception {
        mvc.perform(post("/api/probe").header("Host", GOOD_HOST)
                .header("X-DD-Token", tokens.token()).header("Origin", origin))
            .andExpect(status().isForbidden());
    }

    @Test
    void postWithTokenAndNoOriginPasses() throws Exception {
        mvc.perform(post("/api/probe").header("Host", GOOD_HOST).header("X-DD-Token", tokens.token()))
            .andExpect(status().isOk());
    }

    @Test
    void postWithTokenAndSameOriginPasses() throws Exception {
        mvc.perform(post("/api/probe").header("Host", GOOD_HOST)
                .header("X-DD-Token", tokens.token()).header("Origin", "http://127.0.0.1:8080"))
            .andExpect(status().isOk());
    }

    @Test
    void tokenEndpointServesTokenOnlyToGoodHost() throws Exception {
        mvc.perform(get("/api/token").header("Host", GOOD_HOST))
            .andExpect(status().isOk())
            .andExpect(header().string("Cache-Control", "no-store"))
            .andExpect(jsonPath("$.token").value(tokens.token()));
        mvc.perform(get("/api/token").header("Host", "evil.com:8080"))
            .andExpect(status().isForbidden());
    }
}
