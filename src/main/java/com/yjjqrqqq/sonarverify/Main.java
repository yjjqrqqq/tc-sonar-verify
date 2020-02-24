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
        List<KeyPair> pairs = parse(new String[]{});
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
                verifies.add((key, value) -> {
                    return ("bugs".equalsIgnoreCase(key) && Double.parseDouble(value) > Double.parseDouble(pair.value))
                            ? String.format("sonar bugs %s 超过 %s ", value, pair.value) : "";
                });
            } else if ("minCoverage".equalsIgnoreCase(pair.key)) {
                keys.add("coverage");
                verifies.add((key, value) -> {
                    return ("coverage".equalsIgnoreCase(key) && Double.parseDouble(value) < Double.parseDouble(pair.value))
                            ? String.format("sonar 代理覆盖率 %s 小于  %s %%", value, pair.value) : "";
                });
            } else if ("maxVulnerabilities".equalsIgnoreCase(pair.key)) {
                keys.add("vulnerabilities");
                verifies.add((key, value) -> {
                    return ("vulnerabilities".equalsIgnoreCase(key) && Double.parseDouble(value) > Double.parseDouble(pair.value))
                            ? String.format("sonar  漏洞数%s超过 %s", value, pair.value) : "";
                });
            } else if ("maxDuplicatedLinesDensity".equalsIgnoreCase(pair.key)) {//最大代码重柊率
                keys.add("duplicated_lines_density");
                verifies.add((key, value) -> {
                    return ("duplicated_lines_density".equalsIgnoreCase(key) && Double.parseDouble(value) > Double.parseDouble(pair.value))
                            ? String.format("sonar 重复行%s %% 超过%s %%", value, pair.value) : "";
                });
            }
        }
        //先检查是否跑完
        {
            int cnt = 60;
            while (true) {
                String json = HttpUtils.sendGet(url + "/api/ce/component?component=" + component);
                JSONObject jsonObject = JSON.parseObject(json);
                if (jsonObject.getJSONArray("queue").size() == 0) {
                    break;
                }
                System.out.println("该构建还有后台任务，等待结束!");
                if (cnt <= 0) {
                    break;
                }
                cnt--;
            }

        }
        JSONArray measures = request(url, component, keys);
        for (int i = 0; i < measures.size(); i++) {
            JSONObject measure = measures.getJSONObject(i);
            for (Verify verify : verifies) {
                try {
                    String verifyResult = verify.verify(measure.getString("metric"), measure.getString("value"));
                    if (verifyResult != null && verifyResult.trim().length() > 0) {
                        System.out.println(String.format("##teamcity[buildProblem description='%s' identity='sonarVerifyError']", verifyResult));
                    }
                } catch (Exception ex) {
                    System.out.println(String.format("##teamcity[buildProblem description='%s' identity='sonarVerifyError']", ex.getMessage()));
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
