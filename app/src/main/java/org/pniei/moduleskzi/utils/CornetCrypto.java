package org.pniei.moduleskzi.utils;

import java.security.MessageDigest;
import java.util.Random;

public class CornetCrypto {

    /**
     * Генерация случайной соли (например, 8-значное случайное число или строка)
     */
    public static String generateSalt() {
        Random rand = new Random();
        int saltNum = 10000000 + rand.nextInt(90000000);
        return String.valueOf(saltNum);
    }

    /**
     * Расчет хэша для подписи пакетов взаимодействия
     */
    public static String calculateHash(String baseData, String salt, String secret) {
        try {
            // Согласно ТЗ, хэш формируется от конкатенации данных, соли и секретного ключа
            String targetStr = baseData + salt + secret;

            // Если используешь ГОСТ Стрибог/Магма из твоих С++ либ через JNI:
            // return org.pniei.moduleskzi.utils.CryptUtils.getHash(targetStr.getBytes("UTF-8"));

            // Стандартная реализация SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(targetStr.getBytes("UTF-8"));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}