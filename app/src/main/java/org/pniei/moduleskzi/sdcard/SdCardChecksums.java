package org.pniei.moduleskzi.sdcard;

import android.util.Log;

/**
 * Эталонные контрольные суммы CRC64 для модулей СПО.
 *
 * Значения получены из файлов:
 *   _spo_zo_crc64.bin  → 0x2A8F09E19B762138L  (uint64 little-endian)
 *   _spo_zz.c64        → 0x91BDB9FC84452DEDL  (uint64 little-endian)
 *   _spo1.c64          → 0xDF6D5D43CD90BB82L  (uint64 little-endian)
 *
 * Проверка вызывается при старте приложения, после того как пароль
 * карты успешно верифицирован.
 */
public final class SdCardChecksums {

    private static final String TAG = "SdCardChecksums";

    private SdCardChecksums() {}

    /* ── эталонные CRC64 (little-endian uint64 из .bin/.c64 файлов) ── */
    public static final long CRC64_SPO_ZO  = 0x2A8F09E19B762138L;
    public static final long CRC64_SPO_ZZ  = 0x91BDB9FC84452DEDL;
    public static final long CRC64_SPO1    = 0xDF6D5D43CD90BB82L;

    /**
     * Результат проверки всех трёх модулей.
     */
    public static final class CheckResult {
        public final boolean spoZoOk;
        public final boolean spoZzOk;
        public final boolean spo1Ok;

        CheckResult(boolean spoZoOk, boolean spoZzOk, boolean spo1Ok) {
            this.spoZoOk = spoZoOk;
            this.spoZzOk = spoZzOk;
            this.spo1Ok  = spo1Ok;
        }

        /** true — все три суммы совпали */
        public boolean allOk() {
            return spoZoOk && spoZzOk && spo1Ok;
        }

        /** Человекочитаемая строка для лога / диалога ошибки */
        public String describe() {
            if (allOk()) return "СПО_ЗО OK, СПО_ЗЗ OK, СПО1 OK";
            StringBuilder sb = new StringBuilder();
            if (!spoZoOk) sb.append("СПО_ЗО: ошибка КС  ");
            if (!spoZzOk) sb.append("СПО_ЗЗ: ошибка КС  ");
            if (!spo1Ok)  sb.append("СПО1: ошибка КС");
            return sb.toString().trim();
        }
    }

    /**
     * Читает CRC64 из секторов карты и сверяет с эталоном.
     *
     * @param protocol  открытый протокол карты (не null)
     * @return результат проверки
     */
    public static CheckResult verifyAll(SdCardProtocol protocol) {
        boolean zoOk  = verifySector(protocol, SdCardLayout.SECTOR_SPO_ZO,  CRC64_SPO_ZO,  "СПО_ЗО");
        boolean zzOk  = verifySector(protocol, SdCardLayout.SECTOR_SPO_ZZ,  CRC64_SPO_ZZ,  "СПО_ЗЗ");
        boolean sp1Ok = verifySector(protocol, SdCardLayout.SECTOR_SPO1,    CRC64_SPO1,    "СПО1");
        return new CheckResult(zoOk, zzOk, sp1Ok);
    }

    // ── private ──────────────────────────────────────────────────────────────

    /**
     * Читает первые 8 байт указанного сектора как uint64 LE и
     * сравнивает с эталоном.
     */
    private static boolean verifySector(SdCardProtocol protocol,
                                        int sectorIndex,
                                        long expected,
                                        String name) {
        try {
            byte[] sector = protocol.readSector(sectorIndex);
            if (sector == null || sector.length < SdCardLayout.SPO_BLOCK_CRC64_SIZE) {
                Log.e(TAG, name + ": не удалось прочитать сектор " + sectorIndex);
                return false;
            }
            long actual = readUint64LE(sector, SdCardLayout.SPO_BLOCK_OFFSET_CRC64);
            boolean ok = (actual == expected);
            if (ok) {
                Log.i(TAG, name + ": CRC64 OK  (0x" + Long.toHexString(actual).toUpperCase() + ")");
            } else {
                Log.e(TAG, name + ": CRC64 MISMATCH"
                        + "  expected=0x" + Long.toHexString(expected).toUpperCase()
                        + "  actual=0x"   + Long.toHexString(actual).toUpperCase());
            }
            return ok;
        } catch (Exception e) {
            Log.e(TAG, name + ": исключение при чтении CRC64: " + e.getMessage());
            return false;
        }
    }

    /** Читает uint64 little-endian из буфера начиная с offset */
    static long readUint64LE(byte[] buf, int offset) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (buf[offset + i] & 0xFFL);
        }
        return v;
    }
}
