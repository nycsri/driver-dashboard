package com.driverscanner.service;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ElevationServiceTest {

    private static class Stub extends ElevationService {
        final AtomicInteger calls = new AtomicInteger();
        final String out;
        final boolean fail;

        Stub(String out, boolean fail) {
            super(5);
            this.out = out;
            this.fail = fail;
        }

        @Override
        String runProcess(List<String> command, int timeoutSeconds) throws Exception {
            calls.incrementAndGet();
            if (fail) throw new java.io.IOException("boom");
            return out;
        }
    }

    @Test
    void trueOutputIsElevatedAndCached() {
        Stub s = new Stub("True\r\n", false);
        assertTrue(s.isElevated());
        assertTrue(s.isElevated());
        assertEquals(1, s.calls.get());
    }

    @Test
    void falseOutputExceptionAndTimeoutAreNotElevated() {
        assertFalse(new Stub("False\n", false).isElevated());
        assertFalse(new Stub(null, false).isElevated());
        Stub failing = new Stub(null, true);
        assertFalse(failing.isElevated());
        assertFalse(failing.isElevated());
        assertEquals(1, failing.calls.get());
    }
}
