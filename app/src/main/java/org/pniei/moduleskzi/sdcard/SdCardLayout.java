package org.pniei.moduleskzi.sdcard;

/**
 * Разметка секторов SD-карты (без файловой системы, прямой доступ).
 *
 * Карта организована как блочное устройство: сектор = 512 байт.
 *
 * Сектор 0  — заголовок + пароль доступа
 * Сектор 1  — блок СПО_ЗО (данные + CRC64)
 * Сектор 2  — блок СПО_ЗЗ (данные + CRC64)
 * Сектор 3  — блок СПО1   (данные + CRC64)
 * Сектор 4+ — зашифрованные данные конфигурации
 */
public final class SdCardLayout {

    private SdCardLayout() {}

    /* ── размер сектора ── */
    public static final int SECTOR_SIZE = 512;

    /* ── индексы секторов ── */
    public static final int SECTOR_HEADER    = 0;
    public static final int SECTOR_SPO_ZO    = 1;
    public static final int SECTOR_SPO_ZZ    = 2;
    public static final int SECTOR_SPO1      = 3;
    public static final int SECTOR_DATA_BASE = 4;   // первый сектор данных

    /* ── Сектор 0: разметка заголовка ──
     *
     *   offs  size  описание
     *   0     4     MAGIC  (0x53444341 = "SDCA")
     *   4     4     пароль (uint32, little-endian)
     *   8     4     версия разметки (uint32 LE)
     *   12    4     зарезервировано
     *   16    496   зарезервировано
     */
    public static final int HEADER_OFFSET_MAGIC    = 0;
    public static final int HEADER_OFFSET_PASSWORD = 4;
    public static final int HEADER_OFFSET_VERSION  = 8;

    public static final int HEADER_MAGIC   = 0x53444341; // "SDCA"
    public static final int HEADER_VERSION = 1;

    /* ── SPO-блок (секторы 1, 2, 3): разметка ──
     *
     *   offs  size  описание
     *   0     8     CRC64 (uint64, little-endian)
     *   8     504   зарезервировано / данные СПО
     */
    public static final int SPO_BLOCK_OFFSET_CRC64 = 0;
    public static final int SPO_BLOCK_CRC64_SIZE   = 8;

    /* ── идентификаторы СПО (используются в SdCardChecksums) ── */
    public static final int SPO_ID_ZO  = 0;
    public static final int SPO_ID_ZZ  = 1;
    public static final int SPO_ID_SP1 = 2;
}
