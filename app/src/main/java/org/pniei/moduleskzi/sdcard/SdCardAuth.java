package org.pniei.moduleskzi.sdcard;

import android.content.Context;
import android.util.Log;

/**
 * Аутентификация по SD-карте.
 *
 * Протокол при старте приложения (вызывать до checkPass в AuthenticationFragment):
 *
 *   1. Открыть блочное устройство (SdCardProtocol.open)
 *   2. Прочитать сектор 0 (заголовок)
 *   3. Проверить MAGIC = 0x53444341
 *   4. Прочитать пароль по смещению HEADER_OFFSET_PASSWORD (4 байта LE uint32)
 *   5. Сравнить с эталоном CARD_PASSWORD_MAGIC = 0xD41FE441
 *   6. Если пароль совпал — проверить CRC64 трёх модулей СПО
 *   7. Если всё ОК — вернуть RESULT_OK, иначе — соответствующий код ошибки
 *
 * Экземпляр создаётся заново при каждой попытке входа (карта могла
 * быть переставлена). Не синглтон.
 */
public class SdCardAuth {

    private static final String TAG = "SdCardAuth";

    /** Эталонный пароль карты (uint32 little-endian = 0xD41FE441) */
    private static final int CARD_PASSWORD_MAGIC = 0xD41FE441;

    // ── коды результата ───────────────────────────────────────────────────────

    public static final int RESULT_OK              = 0;
    public static final int RESULT_NO_CARD         = 1;  // карта не найдена
    public static final int RESULT_BAD_MAGIC       = 2;  // неверный MAGIC в секторе 0
    public static final int RESULT_WRONG_PASSWORD  = 3;  // пароль не совпал
    public static final int RESULT_SPO_MISMATCH    = 4;  // одна или несколько CRC64 не совпали
    public static final int RESULT_IO_ERROR        = 5;  // ошибка чтения

    // ── состояние после проверки ──────────────────────────────────────────────

    private int mLastResult = RESULT_NO_CARD;
    private SdCardChecksums.CheckResult mSpoCheckResult = null;
    private SdCardProtocol mProtocol = null;

    // ── public API ─────────────────────────────────────────────────────────────

    /**
     * Выполняет полную проверку карты (пароль + КС СПО).
     * Закрывает блочное устройство после проверки.
     *
     * @param context  контекст приложения
     * @return один из RESULT_* кодов
     */
    public int verify(Context context) {
        mLastResult      = RESULT_NO_CARD;
        mSpoCheckResult  = null;

        SdCardProtocol protocol = new SdCardProtocol();
        mProtocol = protocol;

        try {
            /* ── шаг 1: открыть устройство ── */
            if (!protocol.open(context)) {
                Log.e(TAG, "verify: карта не найдена");
                mLastResult = RESULT_NO_CARD;
                return mLastResult;
            }
            Log.i(TAG, "verify: открыто " + protocol.getDevicePath());

            /* ── шаг 2: прочитать заголовочный сектор ── */
            byte[] header = protocol.readSector(SdCardLayout.SECTOR_HEADER);
            if (header == null) {
                Log.e(TAG, "verify: не удалось прочитать сектор 0");
                mLastResult = RESULT_IO_ERROR;
                return mLastResult;
            }

            /* ── шаг 3: проверить MAGIC ── */
            int magic = readInt32LE(header, SdCardLayout.HEADER_OFFSET_MAGIC);
            if (magic != SdCardLayout.HEADER_MAGIC) {
                Log.e(TAG, "verify: неверный MAGIC 0x" + Integer.toHexString(magic).toUpperCase()
                        + " (ожидалось 0x" + Integer.toHexString(SdCardLayout.HEADER_MAGIC).toUpperCase() + ")");
                mLastResult = RESULT_BAD_MAGIC;
                return mLastResult;
            }
            Log.i(TAG, "verify: MAGIC OK");

            /* ── шаг 4–5: проверить пароль ── */
            int cardPassword = readInt32LE(header, SdCardLayout.HEADER_OFFSET_PASSWORD);
            if (cardPassword != CARD_PASSWORD_MAGIC) {
                Log.e(TAG, "verify: неверный пароль карты 0x"
                        + Integer.toHexString(cardPassword).toUpperCase());
                mLastResult = RESULT_WRONG_PASSWORD;
                return mLastResult;
            }
            Log.i(TAG, "verify: пароль карты OK");

            /* ── шаг 6: проверить КС СПО ── */
            mSpoCheckResult = SdCardChecksums.verifyAll(protocol);
            if (!mSpoCheckResult.allOk()) {
                Log.e(TAG, "verify: КС СПО — " + mSpoCheckResult.describe());
                mLastResult = RESULT_SPO_MISMATCH;
                return mLastResult;
            }
            Log.i(TAG, "verify: КС СПО OK");

            mLastResult = RESULT_OK;
            return RESULT_OK;

        } finally {
            protocol.close();
        }
    }

    /**
     * Возвращает последний код результата.
     */
    public int getLastResult() {
        return mLastResult;
    }

    /**
     * Возвращает результат проверки КС СПО (null если проверка не дошла до этого шага).
     */
    public SdCardChecksums.CheckResult getSpoCheckResult() {
        return mSpoCheckResult;
    }

    /**
     * Человекочитаемое сообщение для отображения пользователю.
     */
    public String getErrorMessage() {
        switch (mLastResult) {
            case RESULT_OK:             return "Карта верифицирована";
            case RESULT_NO_CARD:        return "SD-карта не обнаружена. Вставьте карту и повторите.";
            case RESULT_BAD_MAGIC:      return "Карта не распознана (неверная разметка).";
            case RESULT_WRONG_PASSWORD: return "Неверный пароль карты. Доступ запрещён.";
            case RESULT_SPO_MISMATCH:
                String detail = (mSpoCheckResult != null) ? mSpoCheckResult.describe() : "";
                return "Ошибка контрольных сумм СПО. " + detail;
            case RESULT_IO_ERROR:       return "Ошибка чтения карты.";
            default:                    return "Неизвестная ошибка карты.";
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Читает int32 little-endian из буфера.
     */
    private static int readInt32LE(byte[] buf, int offset) {
        return  (buf[offset]     & 0xFF)
             | ((buf[offset + 1] & 0xFF) <<  8)
             | ((buf[offset + 2] & 0xFF) << 16)
             | ((buf[offset + 3] & 0xFF) << 24);
    }
}
