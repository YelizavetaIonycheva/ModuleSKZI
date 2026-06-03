package org.pniei.moduleskzi.sdcard;

import android.content.Context;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbManager;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Низкоуровневый доступ к SD-карте как к блочному устройству
 * (без файловой системы, через прямое чтение/запись секторов).
 *
 * Карта может быть подключена двумя способами:
 *   1. Через встроенный кардридер → /dev/block/mmcblk1 или /dev/block/sd*
 *   2. Через USB OTG              → /dev/block/sd*
 *
 * Требуются права root или приложение должно быть системным (uid=system)
 * либо устройство поддерживает прямой доступ к блочным устройствам
 * через USB без root (зависит от прошивки).
 *
 * Жизненный цикл:
 *   open() → readSector() / writeSector() → close()
 */
public class SdCardProtocol {

    private static final String TAG = "SdCardProtocol";

    /* кандидаты блочных устройств — перебираем по порядку */
    private static final String[] BLOCK_CANDIDATES = {
        "/dev/block/mmcblk1",
        "/dev/block/mmcblk1p1",
        "/dev/block/sda",
        "/dev/block/sdb",
        "/dev/block/mmcblk0",
    };

    private RandomAccessFile mDevice = null;
    private String           mDevicePath = null;

    // ── public API ────────────────────────────────────────────────────────────

    /**
     * Пытается открыть SD-карту.
     *
     * @param context  контекст приложения
     * @return true — устройство найдено и открыто
     */
    public boolean open(Context context) {
        close();

        /* 1. Ищем через UsbManager (OTG) */
        String usbPath = findUsbBlockDevice(context);
        if (usbPath != null) {
            if (tryOpenDevice(usbPath)) return true;
        }

        /* 2. Перебираем стандартные пути */
        for (String path : BLOCK_CANDIDATES) {
            if (tryOpenDevice(path)) return true;
        }

        Log.e(TAG, "open: SD-карта не найдена");
        return false;
    }

    /**
     * Закрывает блочное устройство.
     */
    public void close() {
        if (mDevice != null) {
            try { mDevice.close(); } catch (IOException ignored) {}
            mDevice = null;
            mDevicePath = null;
        }
    }

    /**
     * Возвращает true, если устройство открыто.
     */
    public boolean isOpen() {
        return mDevice != null;
    }

    /**
     * Путь к блочному устройству (для логов).
     */
    public String getDevicePath() {
        return mDevicePath;
    }

    /**
     * Читает один сектор (512 байт) по его индексу.
     *
     * @param sectorIndex  номер сектора (начиная с 0)
     * @return массив [SECTOR_SIZE] байт или null при ошибке
     */
    public byte[] readSector(int sectorIndex) {
        if (mDevice == null) {
            Log.e(TAG, "readSector: устройство не открыто");
            return null;
        }
        try {
            long offset = (long) sectorIndex * SdCardLayout.SECTOR_SIZE;
            mDevice.seek(offset);
            byte[] buf = new byte[SdCardLayout.SECTOR_SIZE];
            int read = mDevice.read(buf);
            if (read != SdCardLayout.SECTOR_SIZE) {
                Log.e(TAG, "readSector " + sectorIndex + ": прочитано " + read + " из " + SdCardLayout.SECTOR_SIZE);
                return null;
            }
            return buf;
        } catch (IOException e) {
            Log.e(TAG, "readSector " + sectorIndex + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Записывает один сектор (512 байт) по его индексу.
     *
     * @param sectorIndex  номер сектора (начиная с 0)
     * @param data         буфер ровно [SECTOR_SIZE] байт
     * @return true — успешно
     */
    public boolean writeSector(int sectorIndex, byte[] data) {
        if (mDevice == null) {
            Log.e(TAG, "writeSector: устройство не открыто");
            return false;
        }
        if (data == null || data.length != SdCardLayout.SECTOR_SIZE) {
            Log.e(TAG, "writeSector: неверный размер буфера " + (data == null ? "null" : data.length));
            return false;
        }
        try {
            long offset = (long) sectorIndex * SdCardLayout.SECTOR_SIZE;
            mDevice.seek(offset);
            mDevice.write(data);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "writeSector " + sectorIndex + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Читает несколько последовательных секторов.
     *
     * @param startSector  начальный индекс
     * @param count        количество секторов
     * @return буфер [count * SECTOR_SIZE] или null при ошибке
     */
    public byte[] readSectors(int startSector, int count) {
        if (mDevice == null || count <= 0) return null;
        try {
            long offset = (long) startSector * SdCardLayout.SECTOR_SIZE;
            int  totalSize = count * SdCardLayout.SECTOR_SIZE;
            mDevice.seek(offset);
            byte[] buf = new byte[totalSize];
            int read = mDevice.read(buf);
            if (read != totalSize) {
                Log.e(TAG, "readSectors " + startSector + "+" + count + ": прочитано " + read);
                return null;
            }
            return buf;
        } catch (IOException e) {
            Log.e(TAG, "readSectors: " + e.getMessage());
            return null;
        }
    }

    /**
     * Записывает несколько последовательных секторов.
     *
     * @param startSector  начальный индекс
     * @param data         буфер [N * SECTOR_SIZE] байт (N целых секторов)
     * @return true — успешно
     */
    public boolean writeSectors(int startSector, byte[] data) {
        if (mDevice == null || data == null) return false;
        if (data.length % SdCardLayout.SECTOR_SIZE != 0) {
            Log.e(TAG, "writeSectors: размер " + data.length + " не кратен сектору");
            return false;
        }
        try {
            long offset = (long) startSector * SdCardLayout.SECTOR_SIZE;
            mDevice.seek(offset);
            mDevice.write(data);
            return true;
        } catch (IOException e) {
            Log.e(TAG, "writeSectors: " + e.getMessage());
            return false;
        }
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private boolean tryOpenDevice(String path) {
        File f = new File(path);
        if (!f.exists()) return false;
        try {
            RandomAccessFile raf = new RandomAccessFile(f, "rw");
            mDevice     = raf;
            mDevicePath = path;
            Log.i(TAG, "open: открыто " + path);
            return true;
        } catch (FileNotFoundException e) {
            /* нет прав или путь не существует — идём дальше */
            return false;
        }
    }

    /**
     * Пытается найти путь к блочному устройству через UsbManager
     * (USB OTG mass-storage).
     * На Android 8+ устройство появляется в /dev/block/sd* после монтирования,
     * UsbManager даёт нам подтверждение что флешка вставлена.
     */
    private String findUsbBlockDevice(Context context) {
        try {
            UsbManager usbManager = (UsbManager) context.getSystemService(Context.USB_SERVICE);
            if (usbManager == null) return null;

            Map<String, UsbDevice> deviceList = usbManager.getDeviceList();
            if (deviceList == null || deviceList.isEmpty()) return null;

            boolean hasMassStorage = false;
            for (UsbDevice device : deviceList.values()) {
                for (int i = 0; i < device.getInterfaceCount(); i++) {
                    if (device.getInterface(i).getInterfaceClass()
                            == UsbConstants.USB_CLASS_MASS_STORAGE) {
                        hasMassStorage = true;
                        break;
                    }
                }
                if (hasMassStorage) break;
            }

            if (!hasMassStorage) return null;

            /* ищем /dev/block/sd? — берём первый существующий */
            for (char c = 'a'; c <= 'd'; c++) {
                String path = "/dev/block/sd" + c;
                if (new File(path).exists()) {
                    Log.i(TAG, "findUsbBlockDevice: нашли USB-устройство " + path);
                    return path;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "findUsbBlockDevice: " + e.getMessage());
        }
        return null;
    }
}
