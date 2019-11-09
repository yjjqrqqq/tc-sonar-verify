package com.yjjqrqqq.sonarverify;

/**
 * @author liuyixin
 * @create 2019/11/9
 */
public class VerifyImpl {
    public static class MaxBugs implements Verify {
        private int max;

        public MaxBugs(int max) {
            this.max = max;
        }

        public String verify(String key, String value) {
            if (!"bugs".equalsIgnoreCase(key)) {
                return null;
            }
            if (Integer.parseInt(value) <= max) {
                return null;
            }
            return String.format(value + " bugs number greater than " + max);
        }
    }

    public static class MinCoverage implements Verify {
        private double min;

        public MinCoverage(double min) {
            this.min = min;
        }

        public String verify(String key, String value) {
            if (!"coverage".equalsIgnoreCase(key)) {
                return null;
            }
            if (Double.parseDouble(value) >= min) {
                return null;
            }
            return String.format("Coverage %s less than %.2f", value, min);
        }
    }

    public static class MaxVulnerabilities implements Verify {
        private int max;

        public MaxVulnerabilities(int max) {
            this.max = max;
        }

        public String verify(String key, String value) {
            if (!"vulnerabilities".equalsIgnoreCase(key)) {
                return null;
            }
            if (Integer.parseInt(value) <= max) {
                return null;
            }
            return String.format(value + " vulnerabilities greater than " + max);
        }
    }

}
