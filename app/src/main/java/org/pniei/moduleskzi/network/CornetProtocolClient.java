package org.pniei.moduleskzi.network;

import android.util.Log;
import org.json.JSONObject;
import org.pniei.moduleskzi.model.CornetConfig;
import org.pniei.moduleskzi.utils.CornetCrypto;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class CornetProtocolClient {
    private static final String TAG = "CornetClient";
    private final CornetConfig config;
    private final String serverUrl;

    public CornetProtocolClient(CornetConfig config, String serverDnsName) {
        this.config = config;
        this.serverUrl = "http://" + serverDnsName;
    }

    // ==========================================
    // МOДУЛЬ: file_storage
    // ==========================================

    /**
     * Сервис: Share (Предоставление публичного доступа к файлу)
     */
    public JSONObject shareFile(String fileId) {
        try {
            URL url = new URL(serverUrl + "/file_storage/api/Share/");
            String salt = CornetCrypto.generateSalt();

            // Хэш для отправки: подписываем связку (id + id_file)
            String hash = CornetCrypto.calculateHash(config.id + fileId, salt, config.secret);

            JSONObject requestJson = new JSONObject();
            requestJson.put("id", config.id);
            requestJson.put("id_file", fileId);
            requestJson.put("salt", salt);
            requestJson.put("hash", hash);

            return executePostRequest(url, requestJson);
        } catch (Exception e) {
            Log.e(TAG, "Ошибка в Share: ", e);
            return createErrorResponse(e.getMessage());
        }
    }

    /**
     * Сервис: UnShare (Закрытие публичного доступа)
     */
    public JSONObject unshareFile(String fileId) {
        try {
            URL url = new URL(serverUrl + "/file_storage/api/UnShare/");
            String salt = CornetCrypto.generateSalt();
            String hash = CornetCrypto.calculateHash(config.id + fileId, salt, config.secret);

            JSONObject requestJson = new JSONObject();
            requestJson.put("id", config.id);
            requestJson.put("id_file", fileId);
            requestJson.put("salt", salt);
            requestJson.put("hash", hash);

            return executePostRequest(url, requestJson);
        } catch (Exception e) {
            Log.e(TAG, "Ошибка в UnShare: ", e);
            return createErrorResponse(e.getMessage());
        }
    }

    /**
     * Сервис: Download (Скачивание файла)
     * Возвращает массив байт файла или кидает Exception в случае ошибки сервера.
     */
    public byte[] downloadFile(String fileId) throws Exception {
        URL url = new URL(serverUrl + "/file_storage/api/Download/");
        String salt = CornetCrypto.generateSalt();
        String hash = CornetCrypto.calculateHash(config.id + fileId, salt, config.secret);

        JSONObject requestJson = new JSONObject();
        requestJson.put("id", config.id);
        requestJson.put("id_file", fileId);
        requestJson.put("salt", salt);
        requestJson.put("hash", hash);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; utf-8");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(requestJson.toString().getBytes("utf-8"));
        }

        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            // Проверим Content-Type: если вернулся JSON вместо файла, значит там ошибка
            String contentType = conn.getContentType();
            if (contentType != null && contentType.contains("application/json")) {
                String errorBody = readStream(conn.getInputStream());
                JSONObject errObj = new JSONObject(errorBody);
                throw new Exception("Сервер вернул ошибку: " + errObj.optString("error", "Unknown"));
            }

            // Читаем бинарный файл
            try (InputStream is = new BufferedInputStream(conn.getInputStream());
                 ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    bos.write(buffer, 0, bytesRead);
                }
                return bos.toByteArray();
            }
        } else {
            String errBody = readStream(conn.getErrorStream());
            throw new Exception("HTTP код ошибки: " + responseCode + " Тело: " + errBody);
        }
    }

    // ==========================================
    // МОДУЛЬ: maps
    // ==========================================

    /**
     * Сервис: GetTile (Запрос тайла карты)
     * Формат GET-запроса: http://dns_имя_сервера/maps/api/GetTile/t/z/y/x/hash/
     * ВНИМАНИЕ: Для GetTile соль не передается отдельно в JSON,
     * поэтому хэш считается от строки параметров "tzyx" (или id + параметров) + secret.
     */
    public byte[] getTile(int t, int z, int y, int x) throws Exception {
        // Формируем базовую строку параметров для подписи
        String paramString = String.format("%d%d%d%d", t, z, y, x);
        // Считаем хэш без соли, используя только секрет из конфига
        String hash = CornetCrypto.calculateHash(paramString, "", config.secret);

        String tileUrl = String.format("%s/maps/api/GetTile/%d/%d/%d/%d/%s/", serverUrl, t, z, y, x, hash);
        URL url = new URL(tileUrl);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        int responseCode = conn.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (InputStream is = new BufferedInputStream(conn.getInputStream());
                 ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    bos.write(buffer, 0, bytesRead);
                }
                return bos.toByteArray();
            }
        } else {
            throw new Exception("Не удалось загрузить тайл карты. HTTP: " + responseCode);
        }
    }

    // ==========================================
    // Вспомогательные методы сетевого обмена
    // ==========================================

    private JSONObject executePostRequest(URL url, JSONObject jsonPayload) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; utf-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = jsonPayload.toString().getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String responseStr = readStream(is);

        return new JSONObject(responseStr);
    }

    private String readStream(InputStream is) throws Exception {
        if (is == null) return "{}";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, "utf-8"))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line.trim());
            }
            return response.toString();
        }
    }

    private JSONObject createErrorResponse(String message) {
        JSONObject json = new JSONObject();
        try {
            json.put("result", "error");
            json.put("error", message);
        } catch (Exception ignored) {}
        return json;
    }
}