package com.yjjqrqqq.sonarverify;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * @author liuyixin
 * @create 2019/11/9
 */
public class Main {
    public static void main(String[] args) throws UnsupportedEncodingException {
//        args = new String[]{"url=http://sonar.jiaozifin.com", "component=com.cashme.openrisk:cashme-open-risk", "maxBugs=-1", "minCoverage=70", "maxVulnerabilities=0"};
        List<KeyPair> pairs = parse(args);
        String url = "";
        String component = "";
        List<String> keys = new ArrayList<String>();
        List<Verify> verifies = new ArrayList<Verify>();
        for (KeyPair pair : pairs) {
            if ("url".equalsIgnoreCase(pair.key)) {
                url = pair.value;
            } else if ("component".equalsIgnoreCase(pair.key)) {
                component = pair.value;
            } else if ("maxBugs".equalsIgnoreCase(pair.key)) {
                keys.add("bugs");
                verifies.add(new VerifyImpl.MaxBugs(Integer.parseInt(pair.value)));
            } else if ("minCoverage".equalsIgnoreCase(pair.key)) {
                keys.add("coverage");
                verifies.add(new VerifyImpl.MinCoverage(Double.parseDouble(pair.value)));
            } else if ("maxVulnerabilities".equalsIgnoreCase(pair.key)) {
                keys.add("vulnerabilities");
                verifies.add(new VerifyImpl.MaxVulnerabilities(Integer.parseInt(pair.value)));
            }
        }
        JSONArray measures = request(url, component, keys);
        for (int i = 0; i < measures.size(); i++) {
            JSONObject measure = measures.getJSONObject(i);
            for (Verify verify : verifies) {
                String verifyResult = verify.verify(measure.getString("metric"), measure.getString("value"));
                if (verifyResult != null && verifyResult.trim().length() > 0) {
                    System.out.println(String.format("##teamcity[buildProblem description='%s' identity='sonarVerifyError']", verifyResult));
                }
            }
        }
    }

    private static JSONArray request(String url, String component, List<String> keys) throws UnsupportedEncodingException {
        String requestUrl = String.format("%s/api/measures/component?component=%s&metricKeys=%s", url, URLEncoder.encode(component, "utf-8"), String.join(",", keys));
        System.out.println("url: " + requestUrl);
        String result = HttpUtils.sendGet(requestUrl);
        JSONObject jsonObject = JSON.parseObject(result);
        return jsonObject.getJSONObject("component").getJSONArray("measures");
    }


    private static class KeyPair {
        private String key;
        private String value;

        public KeyPair(String key, String value) {
            this.key = key;
            this.value = value;
        }
    }

    public static List<KeyPair> parse(String[] args) {
        List<KeyPair> result = new ArrayList<KeyPair>();
        for (String arg : args) {
            String[] array = arg.split("=");
            if (array.length == 2) {
                result.add(new KeyPair(array[0].trim(), array[1].trim()));
            }
        }
        return result;
    }

}
