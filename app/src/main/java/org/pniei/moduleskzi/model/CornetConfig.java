package org.pniei.moduleskzi.model;

import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

public class CornetConfig {
    public String id;
    public String secret;
    public String phone;
    public String ip_skzi;
    public String ip_ats;
    public String ip_dns;
    public List<AtsServer> ats = new ArrayList<>();
    public String crc32;

    public static class AtsServer {
        public String ip;
        public String login;
        public String password;
    }

    public static CornetConfig fromJson(String jsonStr) throws Exception {
        JSONObject json = new JSONObject(jsonStr);
        CornetConfig config = new CornetConfig();

        config.id = json.optString("id", "");
        config.secret = json.optString("secret", "");
        config.phone = json.optString("phone", "");
        config.ip_skzi = json.optString("ip_skzi", "");
        config.ip_ats = json.optString("ip_ats", "");
        config.ip_dns = json.optString("ip_dns", "");
        config.crc32 = json.optString("crc32", "");

        JSONArray atsArray = json.optJSONArray("ats");
        if (atsArray != null) {
            for (int i = 0; i < atsArray.length(); i++) {
                JSONObject atsObj = atsArray.getJSONObject(i);
                AtsServer server = new AtsServer();
                server.ip = atsObj.optString("ip", "");
                server.login = atsObj.optString("login", "");
                server.password = atsObj.optString("password", "");
                config.ats.add(server);
            }
        }
        return config;
    }

    /**
     * Валидация контрольной суммы CRC32 по всем параметрам
     */
    public boolean isValidCrc() {
        if (crc32 == null || crc32.isEmpty()) return false;

        StringBuilder sb = new StringBuilder();
        sb.append(id != null ? id : "")
                .append(secret != null ? secret : "")
                .append(phone != null ? phone : "")
                .append(ip_skzi != null ? ip_skzi : "")
                .append(ip_ats != null ? ip_ats : "")
                .append(ip_dns != null ? ip_dns : "");

        if (ats != null) {
            for (AtsServer server : ats) {
                sb.append(server.ip != null ? server.ip : "")
                        .append(server.login != null ? server.login : "")
                        .append(server.password != null ? server.password : "");
            }
        }

        CRC32 crc = new CRC32();
        crc.update(sb.toString().getBytes());

        long calculatedCrcValue = crc.getValue();
        try {
            long parsedCrc = Long.parseLong(crc32.trim(), 16);
            return calculatedCrcValue == parsedCrc;
        } catch (NumberFormatException e) {
            String calculatedCrcHex = Long.toHexString(calculatedCrcValue).toLowerCase();
            return calculatedCrcHex.equalsIgnoreCase(crc32.trim());
        }
    }
}