package org.pniei.moduleskzi.utils;

import android.os.Environment;
import android.util.Log;
import org.pniei.moduleskzi.model.CornetConfig;
import org.pniei.moduleskzi.network.CornetProtocolClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;

public class CornetManager {
    private static final String TAG = "CornetManager";
    private static CornetManager instance;

    private CornetConfig activeConfig;
    private CornetProtocolClient protocolClient;

    private CornetManager() {}

    public static synchronized CornetManager getInstance() {
        if (instance == null) {
            instance = new CornetManager();
        }
        return instance;
    }

    /**
     * Поиск файла конфигурации на SD-карте и его валидация
     */
    public boolean initializeFromSDCard() {
        try {
            File sdCard = Environment.getExternalStorageDirectory();
            File[] files = sdCard.listFiles();

            if (files == null) return false;

            for (File file : files) {
                if (file.isFile()) {
                    String name = file.getName();
                    // Проверяем формат 8 символов имени + 3 символа расширения
                    if (name.matches("^[a-zA-Z0-9_-]{8}\\.[a-zA-Z0-9]{3}$")) {
                        Log.d(TAG, "Найден потенциальный файл конфигурации: " + name);

                        String content = readFile(file);
                        CornetConfig config = CornetConfig.fromJson(content);

                        if (config.isValidCrc()) {
                            this.activeConfig = config;
                            // Адрес DNS-сервера используем в качестве хоста для подключения
                            this.protocolClient = new CornetProtocolClient(config, config.ip_dns);
                            Log.i(TAG, "Протокол Корнет успешно инициализирован для ID: " + config.id);
                            return true;
                        } else {
                            Log.e(TAG, "Файл " + name + " имеет невалидный CRC32!");
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Ошибка инициализации с SD-карты: ", e);
        }
        return false;
    }

    public CornetProtocolClient getClient() {
        return protocolClient;
    }

    public CornetConfig getConfig() {
        return activeConfig;
    }

    private String readFile(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file);
             BufferedReader reader = new BufferedReader(new InputStreamReader(fis, "utf-8"))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }
}