package org.pniei.portal.vpn;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;
import org.pniei.moduleskzi.utils.CryptUtils;
import org.pniei.moduleskzi.utils.Utils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.moduleskzi.liveData.ManagerLiveData;

public class VpnClient {


    public native void ikev2init(short netNumber, int lanPort, byte [] lanIPAdr, short serverNetNumber, int wanPort, byte [] wanIPAdr, byte [] nameBlock,
                                 byte [] numSerial, short numKompl, short numOfKeys, int random, byte [] tz, byte [] keyDsch);
    public native byte[] ikev2getikesainit(int [] lenData);
    public native synchronized void vpnprocessingdata(byte[] dataIn, int lenDataIn, byte[] dataOut, int [] lenDataOut, int [] target, int [] err);
    public native int getikev2stage();
    public native int getikev2ipaddr();
    public native int getikev2ipmask();
    public native int checktimesa();
    public native synchronized int espencapsuldata(byte[] dataIn, byte[] dataOut, int lenData, int [] lenProcData);
    public native void ikev2getkeepalive(byte[] dataOut, int [] lenProcData);
    public native void ikev2getdelete(byte[] dataOut, int [] lenProcData);
    public native void ikev2getnetworksettings(byte[] dataOut, int [] lenProcData);
    public native void ikev2clear();
    private static native void setsknkeys(byte [] data);
    private static native byte [] checkkeybyskn(byte [] keyData);
    private static native byte [] decryptkomplkeys(byte [] data_ki_crypted);
    private native byte [] searchanddeletekey(byte [] key_delete, byte [] keys);
    public static native int getcrcsknkeys();
    private static native byte [] setnextkeyaswork(byte [] keyData, byte [] next_data_ki);
    private native byte [] searchandeditkey(byte [] key_edit, byte [] keys);
    private native byte [] addkey(byte [] key_add, byte [] keyData, byte [] keys);

    public static class KeyInf {
        public byte [] kd         = new byte[8];  // Наименование
        public byte [] ser        = new byte[8];  // Номер серии
        public short compl;                       // Номер комплекта ключевого блокнота
        public short numCompl;                    // Количество комплектов в серии
        public byte [] tz           = new byte[64]; // Таблица Узлы замены
        public byte [] dateBegin   = new byte[3];   // Дата начала действия комплекта (год, месяц, день)
        public byte [] dateEnd     = new byte[3];   // Дата конца действия комплекта(год, месяц, день)
        public byte [][] keys;                      // Ключи
        public byte [] key_dsch;                    // Ключ ДСЧ
    }
    private static final String TAG = "VpnClient";
    private static final String KEY_FILE = "/key.bin";
    private static final String SKN_FILE = "/skn.bin";
    private static VpnClient instance;
    private boolean mConnect = false;
    private KeyInf workKey = null;
    private KeyInf connectingKey = null;
    private ArrayList<KeyInf> nextKeys = null;
    private static boolean isWork;
    public static final int REQUST_VPN = 2354;


    static {
        loadOptionalLibrary("magma");
        loadOptionalLibrary("gost28147");
        System.loadLibrary("vpnclient");
    }

    private static boolean loadOptionalLibrary(String s) {
        try {
            System.loadLibrary(s);
            return true;
        } catch (Throwable e) {
            Log.w("VpnClient", "Не удалось загрузить опциональную библиотеку " + s + ": " +e.getMessage());
        }
        return false;
    }

    public static VpnClient ins() {
        if (instance == null) {
            instance = new VpnClient();
        }
        return instance;
    }

    private VpnClient() {
        mConnect = false;
        nextKeys = null;
    }

    public boolean isWork() {
        return isWork;
    }

    public static void setWork(boolean work) {
        isWork = work;
    }

    public KeyInf getWorkKey() {
        return workKey;
    }

    public KeyInf getConnectingKey() {
        return connectingKey;
    }

    public void setConnectingKey(KeyInf connectingKey) {
        this.connectingKey = connectingKey;
    }

    public ArrayList<KeyInf> getNextKeys() {
        return nextKeys;
    }

    public boolean getIndividKey(short numKey, byte[] key) {
        Log.d(TAG, "Запрос ключа " + numKey);
        if(connectingKey != null && connectingKey.keys != null
                && (connectingKey.keys[numKey-1][0] != 0
                || connectingKey.keys[numKey-1][1] != 0
                || connectingKey.keys[numKey-1][2] != 0
                || connectingKey.keys[numKey-1][3] != 0)) {
            System.arraycopy(connectingKey.keys[numKey - 1], 0, key, 0, 32);
            return true;
        }
        return true;
    }

    public boolean isConnected() {
        return mConnect;
    }

    public void setConnected(boolean value) {
        mConnect = value;
    }

    public static boolean startVpnService(Activity activity) {
        // Запуск службы VPN соединения
        if(checkVpnSettings()) {
            Intent intent = android.net.VpnService.prepare(activity);
            if (intent != null) {
                activity.startActivityForResult(intent, REQUST_VPN);
            } else {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    activity.startForegroundService((new Intent(activity, VpnService.class)).setAction(VpnService.ACTION_CONNECT));
                } else {
                    activity.startService((new Intent(activity, VpnService.class)).setAction(VpnService.ACTION_CONNECT));
                }
                isWork = true;
            }
            return true;
        }
        else
            return false;
    }

    public static boolean startVpnServiceWithContext(Context context) {
        // Запуск службы VPN соединения
        if(checkVpnSettings()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService((new Intent(context, VpnService.class)).setAction(VpnService.ACTION_CONNECT));
            } else {
                context.startService((new Intent(context, VpnService.class)).setAction(VpnService.ACTION_CONNECT));
            }
            isWork = true;
            return true;
        }
        else
            return false;
    }

    public static void stopVpnService(Context context) {
        ManagerLiveData.ins().clearVpnInfo();
        context.startService((new Intent(context, VpnService.class)).setAction(VpnService.ACTION_DISCONNECT));
        isWork = false;
    }

    public static boolean restartVpnService(Activity activity) {
        if(checkVpnSettings()) {
            ManagerLiveData.ins().clearVpnInfo();
            Intent intent = android.net.VpnService.prepare(activity);
            if (intent != null) {
                activity.startActivityForResult(intent, REQUST_VPN);
            } else {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    activity.startForegroundService((new Intent(activity, VpnService.class)).setAction(VpnService.ACTION_RECONNECT));
                } else {
                    activity.startService((new Intent(activity, VpnService.class)).setAction(VpnService.ACTION_RECONNECT));
                }
                isWork = true;
            }
            return true;
        }
        else
            return false;
    }

    private static boolean checkVpnSettings() {
        String ipSKZI = PrefsUtils.ins().getIpSkzi();
        ArrayList<String> ipDNSs = new ArrayList<>();
        ipDNSs.add(PrefsUtils.ins().getIpSkzi());

        if(ipSKZI == null || ipSKZI.compareTo("")==0)
            return false;
        if(!Utils.checkIP(ipSKZI))
            return false;
        if(ipDNSs.size() > 0) {
            for (String address : ipDNSs) {
                if (!Utils.checkIP(address))
                    return false;
            }
        }
        return true;
    }

    public static void deleteKeys(Context context) {
        File file = new File(context.getFilesDir() + KEY_FILE);
        if(file.exists()) {
            file.delete();
        }
    }

    /**
     * Функция получения объекта File файла с закрытыми ключами
     */
    public static File getFileKey(Context context) {
        return new File(context.getFilesDir() + KEY_FILE);
    }

    public boolean loadAndRefreshKeys(Context context) {
        byte [] cryptedKeyData, keyData, tempKeyData;
        byte [] hashPassword = PrefsUtils.ins().getHashPass();
        File fileKeys = getFileKey(context);
        if(fileKeys == null)
            return false;
        try {
            // Чтение файла с ключами
            Log.i(TAG, "Чтение файла с ключами");
            FileInputStream fin = new FileInputStream(fileKeys);
            cryptedKeyData = new byte[fin.available()];
            fin.read(cryptedKeyData);
            fin.close();

            // Расшифрование ключевых данных
            Log.i(TAG, "Расшифрование ключевых данных");
            keyData = CryptUtils.decryptData(cryptedKeyData, hashPassword);
            if(keyData == null) {
                Log.e(TAG, "Ошибка расшифрования ключевых данных");
                return false;
            }

            // Сверка со списком СНК, при необходимости переход на новые
            Log.i(TAG, "Сверка со списком СКН");
            byte [] sknKeys = loadSKNKeys(context);
            setsknkeys(sknKeys);
            tempKeyData = checkkeybyskn(keyData);

            Log.i(TAG, "Расшифрование ключевых блокнотов");
            keyData = decryptkomplkeys(tempKeyData);
            if (keyData == null)
                return false;

            Log.i(TAG, "Загрузка ключевых данных в память");
            // Загрузка ключевых данных в память
            setKeyInf(keyData);
        }
        catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public boolean loadAndRefreshKeys(byte [] keyData) {
        byte [] keys;

        Log.i(TAG, "Расшифрование ключевых блокнотов");
        keys = decryptkomplkeys(keyData);
        if (keys == null)
            return false;

        Log.i(TAG, "Загрузка ключевых данных в память");
        setKeyInf(keys);
        return true;
    }

    public static byte [] loadSKNKeys(Context context) {
        File fileData = new File(context.getFilesDir() + SKN_FILE);
        byte [] sknKeys = null;
        if(fileData.exists()) {
            try {
                FileInputStream in = new FileInputStream(fileData);
                sknKeys = new byte[in.available()];
                in.read(sknKeys);
                in.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return sknKeys;
    }

    private void setKeyInf(byte [] data_ki){
        /*  Считывание действующего ключа   */
        workKey = new KeyInf();
        workKey.kd[0]  = data_ki[164];
        workKey.kd[1]  = data_ki[165];
        workKey.kd[2]  = data_ki[167];

        workKey.ser[4]     = data_ki[168];
        workKey.ser[5]     = data_ki[169];
        workKey.ser[6]     = data_ki[170];
        workKey.ser[7]     = data_ki[171];

        workKey.compl = (short)((data_ki[172] & 0xFF) | ((data_ki[173] & 0xFF) << 8));

        workKey.numCompl        = (short)((data_ki[174] & 0xFF) | ((data_ki[175] & 0xFF) << 8));
        System.arraycopy(data_ki, 256, workKey.tz, 0, 64);
        workKey.keys = new byte[workKey.numCompl][32];
        for(int i = 0; i < workKey.numCompl; i++){
            System.arraycopy(data_ki,336 + 48*i, workKey.keys[i],0,32);
        }

        //String key1 = Utils.byteArrayToHexString(workKey.keys[0]);

        workKey.key_dsch = new byte[32];
        System.arraycopy(data_ki,  224, workKey.key_dsch,0,32);

        System.arraycopy(data_ki,  320+workKey.numCompl*48, workKey.dateBegin,0,3);
        System.arraycopy(data_ki,  320+workKey.numCompl*48 + 3, workKey.dateEnd,0,3);

        int sdvig = 320 + workKey.numCompl*48 + 6;

        if(data_ki.length - sdvig > 374)
            nextKeys = new ArrayList<>();
        else
            nextKeys = null;

        while(data_ki.length - sdvig > 374) { // 374 = 320 + 48 + 6
            KeyInf tempKey = new KeyInf();

            /* Очередной ключ присутствует */
            tempKey.kd[0]  = data_ki[164+sdvig];
            tempKey.kd[1]  = data_ki[165+sdvig];
            tempKey.kd[2]  = data_ki[167+sdvig];

            tempKey.ser[4]     = data_ki[168+sdvig];
            tempKey.ser[5]     = data_ki[169+sdvig];
            tempKey.ser[6]     = data_ki[170+sdvig];
            tempKey.ser[7]     = data_ki[171+sdvig];

            tempKey.compl = (short)((data_ki[172+sdvig] & 0xFF) | ((data_ki[173+sdvig] & 0xFF) << 8));

            tempKey.numCompl        = (short)((data_ki[174+sdvig] & 0xFF) | ((data_ki[175+sdvig] & 0xFF) << 8));
            System.arraycopy(data_ki, 256+sdvig, tempKey.tz, 0, 64);
            tempKey.keys = new byte[tempKey.numCompl][32];
            for(int i = 0; i < tempKey.numCompl; i++){
                System.arraycopy(data_ki,336+sdvig + 48*i, tempKey.keys[i],0,32);
            }

            tempKey.key_dsch = new byte[32];
            System.arraycopy(data_ki,  224+sdvig, tempKey.key_dsch,0,32);

            System.arraycopy(data_ki,  320+sdvig+tempKey.numCompl*48, tempKey.dateBegin,0,3);
            System.arraycopy(data_ki,  320+sdvig+tempKey.numCompl*48 + 3, tempKey.dateEnd,0,3);

            sdvig = sdvig + 326 + tempKey.numCompl*48;
            nextKeys.add(tempKey);
        }
    }

    public boolean setNextKeyAsWork(Context context, KeyInf nextKey) {
        byte [] cryptedKeyData, keyData, tempKeyData;
        byte [] hashPassword = PrefsUtils.ins().getHashPass();

        File fileKeys = getFileKey(context);

        try {
            // Чтение файла с ключами
            Log.i(TAG, "Чтение файла с ключами");
            FileInputStream fin = new FileInputStream(fileKeys);
            cryptedKeyData = new byte[fin.available()];
            fin.read(cryptedKeyData);
            fin.close();

            // Расшифрование ключевых данных
            Log.i(TAG, "Расшифрование ключевых данных");
            keyData = CryptUtils.decryptData(cryptedKeyData, hashPassword);
            if(keyData == null) {
                Log.e(TAG, "Ошибка расшифрования ключевых данных");
                return false;
            }

            // Ошибка, сверку срока работы нужно выполнять после синхронизации по времени с СКЗИ
            Log.i(TAG, "Установка очередного ключа в качестве действующего");

            byte [] keyDataNext = new byte[20];
            System.arraycopy(nextKey.kd, 0, keyDataNext, 0, 8);
            System.arraycopy(nextKey.ser, 0, keyDataNext, 8, 8);
            keyDataNext[16] = (byte)(nextKey.compl & 0xFF);
            keyDataNext[17] = (byte)((nextKey.compl >> 8) & 0xFF);
            keyDataNext[18] = (byte)(nextKey.numCompl & 0xFF);
            keyDataNext[19] = (byte)((nextKey.numCompl >> 8) & 0xFF);

            tempKeyData = setnextkeyaswork(keyData, keyDataNext);

            if(keyData != tempKeyData) {
                Log.i(TAG, "Ключевые данные изменились");
                // Если после всех проверок массив ключей изменился, сохраняем его в файл
                cryptedKeyData = CryptUtils.cryptData(tempKeyData, hashPassword);
                if(cryptedKeyData == null)
                    return false;

                FileOutputStream out = new FileOutputStream(fileKeys);
                out.write(cryptedKeyData);
                out.flush();
                out.close();
            }

            Log.i(TAG, "Расшифрование ключевых блокнотов");
            keyData = decryptkomplkeys(tempKeyData);
            Log.i(TAG, "Загрузка ключевых данных в память");
            // Загрузка ключевых данных в память
            setKeyInf(keyData);
        }
        catch (Exception e) {
            e.printStackTrace();
            return true;
        }
        return false;
    }

    public static void saveSKNKeys(Context context, byte [] sknKeys) {
        File fileData = new File(context.getFilesDir() + SKN_FILE);

        try {
            FileOutputStream out = new FileOutputStream(fileData);
            out.write(sknKeys);
            out.flush();
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deleteKey(Context context, byte [] deleteKey) {
        byte [] cryptData;
        byte [] decryptData;
        byte [] hashPassword = PrefsUtils.ins().getHashPass();
        File fileData = new File(context.getFilesDir() + KEY_FILE);

        try {
            FileInputStream in = new FileInputStream(fileData);
            cryptData = new byte [in.available()];
            in.read(cryptData);
            in.close();

            decryptData = CryptUtils.decryptData(cryptData, hashPassword);
            if(decryptData == null)
                return;

            decryptData = searchanddeletekey(deleteKey, decryptData);
            if(decryptData == null)
                return;

            cryptData = CryptUtils.cryptData(decryptData, hashPassword);
            if(cryptData == null)
                return;

            FileOutputStream out = new FileOutputStream(fileData);
            out.write(cryptData);
            out.flush();
            out.close();

            decryptData = decryptkomplkeys(decryptData);

            setKeyInf(decryptData);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void editKeys(Context context, byte [] editKey) {
        byte [] cryptData;
        byte [] decryptData;
        byte [] hashPassword = PrefsUtils.ins().getHashPass();
        File fileData = getFileKey(context);

        try {
            FileInputStream in = new FileInputStream(fileData);
            cryptData = new byte [in.available()];
            in.read(cryptData);
            in.close();

            decryptData = CryptUtils.decryptData(cryptData, hashPassword);
            if(decryptData == null)
                return;

            decryptData = searchandeditkey(editKey, decryptData);
            if(decryptData == null)
                return;

            cryptData = CryptUtils.cryptData(decryptData, hashPassword);
            if(cryptData == null)
                return;

            FileOutputStream out = new FileOutputStream(fileData);
            out.write(cryptData);
            out.flush();
            out.close();

            decryptData = decryptkomplkeys(decryptData);

            setKeyInf(decryptData);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void addKey(Context context, byte [] keyInfo, byte [] keyData) {
        byte [] cryptData;
        byte [] decryptData;

        if(!VpnClient.ins().checkKeyForAdd(keyInfo)) {
            return;
        }

        byte [] hashPassword = PrefsUtils.ins().getHashPass();
        File fileData = getFileKey(context);

        try {
            FileInputStream in = new FileInputStream(fileData);
            cryptData = new byte [in.available()];
            in.read(cryptData);
            in.close();

            decryptData = CryptUtils.decryptData(cryptData, hashPassword);
            if(decryptData == null)
                return;

            decryptData = addkey(keyInfo, keyData, decryptData);
            if(decryptData == null)
                return;

            cryptData = CryptUtils.cryptData(decryptData, hashPassword);
            if(cryptData == null)
                return;

            FileOutputStream out = new FileOutputStream(fileData);
            out.write(cryptData);
            out.flush();
            out.close();

            decryptData = decryptkomplkeys(decryptData);

            setKeyInf(decryptData);
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    private boolean checkKeyForAdd(byte [] addKeyInfo) {
        if(workKey.kd[0]   == addKeyInfo[0] &&
                workKey.kd[1]  == addKeyInfo[1] &&
                workKey.kd[2]  == addKeyInfo[2] &&
                workKey.kd[3]  == addKeyInfo[3] &&
                workKey.kd[4]  == addKeyInfo[4] &&
                workKey.kd[5]  == addKeyInfo[5] &&
                workKey.kd[6]  == addKeyInfo[6] &&
                workKey.kd[7]  == addKeyInfo[7] &&
                workKey.ser[0]     == addKeyInfo[8] &&
                workKey.ser[1]     == addKeyInfo[9] &&
                workKey.ser[2]     == addKeyInfo[10] &&
                workKey.ser[3]     == addKeyInfo[11] &&
                workKey.ser[4]     == addKeyInfo[12] &&
                workKey.ser[5]     == addKeyInfo[13] &&
                workKey.ser[6]     == addKeyInfo[14] &&
                workKey.ser[7]     == addKeyInfo[15])
            return false;

        if(nextKeys != null && nextKeys.size() > 0) {
            for (KeyInf key_inf : nextKeys) {
                if (key_inf.kd[0] == addKeyInfo[0] &&
                        key_inf.kd[1] == addKeyInfo[1] &&
                        key_inf.kd[2] == addKeyInfo[2] &&
                        key_inf.kd[3] == addKeyInfo[3] &&
                        key_inf.kd[4] == addKeyInfo[4] &&
                        key_inf.kd[5] == addKeyInfo[5] &&
                        key_inf.kd[6] == addKeyInfo[6] &&
                        key_inf.kd[7] == addKeyInfo[7] &&
                        key_inf.ser[0]    == addKeyInfo[8] &&
                        key_inf.ser[1]    == addKeyInfo[9] &&
                        key_inf.ser[2]    == addKeyInfo[10] &&
                        key_inf.ser[3]    == addKeyInfo[11] &&
                        key_inf.ser[4]    == addKeyInfo[12] &&
                        key_inf.ser[5]    == addKeyInfo[13] &&
                        key_inf.ser[6]    == addKeyInfo[14] &&
                        key_inf.ser[7]    == addKeyInfo[15])
                    return false;
            }
        }
        return true;
    }
}
