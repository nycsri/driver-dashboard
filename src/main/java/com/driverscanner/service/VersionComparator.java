package com.driverscanner.service;

import java.math.BigInteger;
import java.util.OptionalInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Segment-wise numeric comparison of dotted driver versions (e.g. 22.110.1.1). */
final class VersionComparator {

    private static final Pattern SEGMENT = Pattern.compile("(\\d+)\\D*");
    // Exactly 3-4 numeric segments, not embedded in a longer dotted run.
    private static final Pattern VERSION_IN_TEXT = Pattern.compile("(?<![\\d.])\\d+(?:\\.\\d+){2,3}(?![\\d.]*\\d)");

    private VersionComparator() {}

    /**
     * Empty when either side is not a dotted numeric version. Missing segments count as 0;
     * a non-numeric tail on a segment (e.g. "4beta") is ignored.
     */
    static OptionalInt compare(String a, String b) {
        BigInteger[] x = parse(a);
        BigInteger[] y = parse(b);
        if (x == null || y == null) return OptionalInt.empty();
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            BigInteger l = i < x.length ? x[i] : BigInteger.ZERO;
            BigInteger r = i < y.length ? y[i] : BigInteger.ZERO;
            int c = l.compareTo(r);
            if (c != 0) return OptionalInt.of(c);
        }
        return OptionalInt.of(0);
    }

    /** Last 3-4 segment dotted version in the text (driver titles end with the version), or null. */
    static String extractVersion(String text) {
        if (text == null) return null;
        Matcher m = VERSION_IN_TEXT.matcher(text);
        String last = null;
        while (m.find()) last = m.group();
        return last;
    }

    private static BigInteger[] parse(String v) {
        if (v == null || v.isBlank()) return null;
        String[] parts = v.trim().split("\\.", -1);
        BigInteger[] out = new BigInteger[parts.length];
        for (int i = 0; i < parts.length; i++) {
            Matcher m = SEGMENT.matcher(parts[i]);
            if (!m.matches()) return null;
            out[i] = new BigInteger(m.group(1));
        }
        return out;
    }
}
