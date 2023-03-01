package org.pniei.portal.services;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.util.Base64;
import android.util.Log;

import org.pniei.moduleskzi.liveData.ManagerLiveData;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.portal.vpn.VpnClient;

import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class MonitoringService extends Service {
    private static final String TAG = "MonitoringService";
    public static final String ACTION_START_MONITORING = "MonitoringService.START";
    public static final String ACTION_STOP_MONITORING = "MonitoringService.STOP";
    private final AtomicReference<Thread> mConnectingThread = new AtomicReference<>();
    private MonitoringConnection mMmtConnection;

    @Override
    public void onCreate() {
        Log.i(TAG, "MonitoringService Create");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_START_MONITORING.equals(intent.getAction())) {
            Log.i(TAG, "START MONITORING SERVICE");

            final String monitoringAddress = PrefsUtils.ins().getIpMon();
            mMmtConnection = new MonitoringConnection(this, monitoringAddress);
            mMmtConnection.isRun = true;
            startMonitoring(mMmtConnection);
            return START_NOT_STICKY;
        } else {
            Log.i(TAG, "STOP MONITORING SERVICE");
            if(mMmtConnection != null) {
                mMmtConnection.isRun = false;
            }
            return START_STICKY;
        }
    }

    private void startMonitoring(final MonitoringConnection connection) {
        final Thread thread = new Thread(connection, "MonitoringThread");
        setConnectingThread(thread);
        thread.start();
    }

    private void setConnectingThread(final Thread thread) {
        final Thread oldThread = mConnectingThread.getAndSet(thread);
        if (oldThread != null) {
            oldThread.interrupt();
        }
    }

    static public void startMonitoringService(Context context) {
        if(!PrefsUtils.ins().getIpMon().equals(""))
            context.startService((new Intent(context, MonitoringService.class)).setAction(MonitoringService.ACTION_START_MONITORING));
    }

    static public void stopMonitoringService(Context context) {
        context.startService((new Intent(context, MonitoringService.class)).setAction(MonitoringService.ACTION_STOP_MONITORING));
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy() ");
    }

    class MonitoringConnection implements Runnable {
        private static final String TAG = "MonitoringService";
        private final long MON_NORMAL_TIME = TimeUnit.SECONDS.toMillis(30);
        private final long MON_FLASH_TIME  = TimeUnit.SECONDS.toMillis(5);
        private final int  MON_TIMESYNC_FLAG    = 0x00000001;
        private final int  MON_KEYLISTSYNC_FLAG = 0x00000002;
        private final int  MON_DELETEKEYS_FLAG  = 0x00000004;
        private final int  MAX_TIME_DIFFERENCE  = 30000; // 30 seconds
        private final String URL_MONITORING         = "/monitoring.php";
        private final String RESPONSE_OK            = "ResponseOK";
        private final String RESPONSE_SET_TIME_DATA = "SetTimeDate";
        private final String RESPONSE_SET_KEY_LIST  = "SetKeyList";
        private final String RESPONSE_DELETE_KEY    = "DeleteKey";
        private final String RESPONSE_EDIT_KEY      = "EditKey";
        private final String RESPONSE_ADD_KEY       = "AddKey";

        public boolean isRun = false, isPaused = false;
        private final String mConnectingAddress;
        private long lastTimeSync, monTimeSleep;
        private Context mContext;
        private boolean isResponseTimeError = false;
        private String currentTime;

        public MonitoringConnection(Context context, final String monitoringAddress) {
            mContext = context;
            mConnectingAddress = monitoringAddress;
        }

        @Override
        public void run() {
            long timeNow;
            int flagRequest;
            monTimeSleep = MON_FLASH_TIME;
            lastTimeSync = 0;

        /*Intent intent = new Intent(VPNFragment.BROADCAST_ACTION);
        intent.putExtra(VPNFragment.TYPE_MESSAGE, VPNFragment.TIME_SKZI_DIF_MESSAGE);
        intent.putExtra(VPNFragment.DIF_TIME, (long)0);
        mContext.sendBroadcast(intent);*/

            while(isRun && !Thread.interrupted()) {
                //Если соединение с VPN-сервером активно
                if(VpnClient.ins().isConnected() && !isPaused) {
                    timeNow = System.currentTimeMillis();
                    flagRequest = 0;

                    if(lastTimeSync + monTimeSleep <= timeNow) {
                        flagRequest = MON_TIMESYNC_FLAG | MON_KEYLISTSYNC_FLAG | MON_DELETEKEYS_FLAG;
                    }

                    if(flagRequest > 0) {
                        Log.i(TAG, "Взаимодействие с сервисом мониторинга. FLAG = " + flagRequest);
                        communicatSKZI(flagRequest);
                        lastTimeSync = timeNow;
                        continue;
                    }
                }
                try {Thread.sleep(1000);} catch (Exception e) {}
            }
        }

        private void communicatSKZI(final int flagRequest) {
            isPaused = true;
            Thread thread = new Thread(() -> {
                URL url;
                int responseCode = 0;
                HttpURLConnection conn = null;
                currentTime = getCurrentMoscowTimeString();

                try {
                    url = new URL(new StringBuilder().append("http://").append(mConnectingAddress).append(URL_MONITORING).toString());
                    conn = (HttpURLConnection)url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Accept", "*/*");
                    conn.setRequestProperty("Referer", new StringBuilder().append("http:/").append(URL_MONITORING).append("/").toString());
                    conn.setRequestProperty("Host", "SMP PORTAL");
                    conn.setRequestProperty("Content-Type","application/json;charset=utf-8");
                    conn.setRequestProperty("MonRequest-Type", "Request");
                    conn.setRequestProperty("Mon-Flags", new StringBuilder().append("0x").append(int32ToHexString(flagRequest)).toString());
                    conn.setRequestProperty("TimeDate", currentTime);
                    conn.setRequestProperty("KeyList-CRC", new StringBuilder().append("0x").append(int32ToHexString(VpnClient.getcrcsknkeys())).toString());
                    byte [] buf_KEY = getBufKey();

                    String strKey = Base64.encodeToString(buf_KEY, Base64.NO_WRAP);
                    conn.setRequestProperty("KeysStruct-Length", Integer.toString(strKey.length()));
                    conn.setRequestProperty("KeysStruct-Content", strKey);
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(2000);
                    conn.connect();
                    responseCode = conn.getResponseCode();
                    Log.i(TAG, "communicatSKZI responseCode = " + responseCode);

                    if(responseCode == 200) {
                        processingResponse(conn.getHeaderFields(), flagRequest); // Обработка принятого ответа
                    }
                }catch (Exception e) {
                    e.printStackTrace();
                }
                finally {
                    if(conn != null)
                        conn.disconnect();
                    isPaused = false;
                }
            });
            thread.start();
        }

        private void processingResponse(Map<String, List<String>> responseHeader, int flagRequest) throws RequestTypeError {
            VpnClient vpnClient = VpnClient.ins();
            List<String> requestType = responseHeader.get("MonRequest-Type");
            if(requestType == null)
                throw new RequestTypeError("Нет поля MonRequest-Type");

            String response = requestType.get(0);

            monTimeSleep = MON_FLASH_TIME;

            if(response.equals(RESPONSE_OK)) {
                Log.i(TAG, "Response - OK");
                monTimeSleep = MON_NORMAL_TIME;
                if(!isResponseTimeError) { // Проверка ключей только если не было ошибки синхронизации времени
                    // Меняем местами действующий и очередной, если соединение установлено на очередном
                    // удалять действующий не имеет смыла, т.к. он может быть не удален на сервере и он его отправит нам
                    if(vpnClient.getConnectingKey() != vpnClient.getWorkKey() && vpnClient.getNextKeys() != null) {
                        vpnClient.setNextKeyAsWork(mContext, vpnClient.getConnectingKey());
                    }

                    ManagerLiveData.ins().setSkziTimeError("");
                }
                isResponseTimeError = false;
            }
            else if(response.equals(RESPONSE_SET_TIME_DATA)) {
                Log.e(TAG, "Response - RESPONSE_SET_TIME_DATA");
                if(responseHeader.get("TimeDate")== null)
                    throw new RequestTypeError("Нет поля TimeDate");

                String timeSKZIStr = responseHeader.get("TimeDate").get(0);
                StringBuilder sb = new StringBuilder();
                sb.append("Время на устройстве: ").append(currentTime).append("\n")
                        .append("Время на СКЗИ: ").append(timeSKZIStr).append("\n");
                ManagerLiveData.ins().setSkziTimeError(sb.toString());
                isResponseTimeError = true;
            }
            else if(response.equals(RESPONSE_SET_KEY_LIST)) {
                String content;
                Log.e(TAG, "Response - RESPONSE_SET_KEY_LIST");
                if(responseHeader.get("KeyList-Content")== null)
                    throw new RequestTypeError("Нет поля KeyList-Content");
                content = responseHeader.get("KeyList-Content").get(0);
                byte [] contentBuf = Base64.decode(content, Base64.NO_WRAP);
                VpnClient.saveSKNKeys(mContext, contentBuf);
                vpnClient.loadAndRefreshKeys(mContext);
            }
            else if(response.equals(RESPONSE_DELETE_KEY)) {
                String content;
                Log.e(TAG, "Response - RESPONSE_DELETE_KEY");
                if(responseHeader.get("KeysStruct-Content")== null)
                    throw new RequestTypeError("Нет поля KeysStruct-Content");

                content = responseHeader.get("KeysStruct-Content").get(0);
                byte [] contentBuf = Base64.decode(content, Base64.NO_WRAP);
                if(contentBuf.length < 64)
                    throw new RequestTypeError("contentBuf.length < 64");

                vpnClient.deleteKey(mContext, contentBuf);
            }
            else if(response.equals(RESPONSE_EDIT_KEY)) {
                String content;
                Log.e(TAG, "Response - RESPONSE_EDIT_KEY");
                if(responseHeader.get("KeysStruct-Content")== null)
                    throw new RequestTypeError("Нет поля KeysStruct-Content");

                content = responseHeader.get("KeysStruct-Content").get(0);
                byte [] contentBuf = Base64.decode(content, Base64.NO_WRAP);
                if(contentBuf.length < 64)
                    throw new RequestTypeError("contentBuf.length < 64");

                vpnClient.editKeys(mContext, contentBuf);
            }
            else if(response.equals(RESPONSE_ADD_KEY)) {
                String content;
                int lenKeyM, lenKeyC;

                Log.e(TAG, "Response - RESPONSE_ADD_KEY");
                if(responseHeader.get("KeysStruct-Content")== null)
                    throw new RequestTypeError("Нет поля KeysStruct-Content");
                if(responseHeader.get("Key-Content")== null)
                    throw new RequestTypeError("Нет поля Key-Content");
                if(responseHeader.get("KeyM-Length")== null)
                    throw new RequestTypeError("Нет поля KeyM-Length");
                if(responseHeader.get("KeyC-Length")== null)
                    throw new RequestTypeError("Нет поля KeyC-Length");

                content = responseHeader.get("KeysStruct-Content").get(0);
                byte [] keyInfo = Base64.decode(content,  Base64.NO_WRAP);
                if(keyInfo.length < 64)
                    throw new RequestTypeError("keyInfo.length < 64");

                lenKeyM = Integer.valueOf(responseHeader.get("KeyM-Length").get(0));
                lenKeyC = Integer.valueOf(responseHeader.get("KeyC-Length").get(0));
                content = responseHeader.get("Key-Content").get(0);
                byte [] bufKeyM = Base64.decode(content.getBytes(), 0, lenKeyM,  Base64.NO_WRAP);
                byte [] bufKeyC = Base64.decode(content.getBytes(), lenKeyM, lenKeyC,  Base64.NO_WRAP);
                byte [] addKeys = new byte[bufKeyM.length + bufKeyC.length];
                System.arraycopy(bufKeyM, 0, addKeys, 0,  bufKeyM.length);
                System.arraycopy(bufKeyC, 0, addKeys,  bufKeyM.length,  bufKeyC.length);

                vpnClient.addKey(mContext, keyInfo, addKeys);
                // Данный ответ является не целевым ответом на запрос, поэтому повторяем целевой запрос сбросив время
            }
        }

        private String getCurrentMoscowTimeString() {
            Calendar mCalendar = new GregorianCalendar();
            mCalendar.setTimeZone(TimeZone.getTimeZone("GMT+03:00"));
            DateFormat df = new SimpleDateFormat("HH:mm:ss dd-MM-yyyy");
            return df.format(mCalendar.getTime());
        }

        private long convertStringDataToLong(String timeStr) {
            DateFormat format = new SimpleDateFormat("HH:mm:ss dd-MM-yyyy");
            try {
                Date date = format.parse(timeStr);
                return date.getTime();
            } catch (ParseException e) {
                e.printStackTrace();
                return 0;
            }
        }

        private byte [] getBufKey() {
            byte [] buf;
            final int sizeKeyStruct = 64;
            VpnClient vpnClient = VpnClient.ins();
            ArrayList<VpnClient.KeyInf> nextKeys = vpnClient.getNextKeys();

            if(nextKeys != null && nextKeys.size() > 0 ) {
                buf = new byte[sizeKeyStruct * (1 + vpnClient.getNextKeys().size())];
                VpnClient.KeyInf workKey = vpnClient.getWorkKey();
                System.arraycopy(workKey.kd, 0, buf, 0, 8);
                System.arraycopy(workKey.ser, 0, buf, 8, 8);
                buf[16] = (byte)(workKey.compl & 0xFF);
                buf[17] = (byte)(workKey.compl >> 8 & 0xFF);
                buf[18] = (byte)(workKey.numCompl & 0xFF);
                buf[19] = (byte)(workKey.numCompl >> 8 & 0xFF);
                System.arraycopy(workKey.dateBegin, 0, buf, 20, 3);
                System.arraycopy(workKey.dateEnd, 0, buf, 23, 3);

                int count = 0, sdvig;

                for(VpnClient.KeyInf nextKey: nextKeys) {
                    sdvig = count*64;
                    System.arraycopy(nextKey.kd, 0, buf, sizeKeyStruct + sdvig, 8);
                    System.arraycopy(nextKey.ser, 0, buf, sizeKeyStruct + 8 + sdvig, 8);
                    buf[sizeKeyStruct + 16 + sdvig] = (byte) (nextKey.compl & 0xFF);
                    buf[sizeKeyStruct + 17 + sdvig] = (byte) (nextKey.compl >> 8 & 0xFF);
                    buf[sizeKeyStruct + 18 + sdvig] = (byte) (nextKey.numCompl & 0xFF);
                    buf[sizeKeyStruct + 19 + sdvig] = (byte) (nextKey.numCompl >> 8 & 0xFF);
                    System.arraycopy(nextKey.dateBegin, 0, buf, sizeKeyStruct + 20 + sdvig, 3);
                    System.arraycopy(nextKey.dateEnd, 0, buf, sizeKeyStruct + 23 + sdvig, 3);
                    count++;
                }
            }
            else {
                buf = new byte[sizeKeyStruct];
                VpnClient.KeyInf workKey = vpnClient.getWorkKey();
                System.arraycopy(workKey.kd, 0, buf, 0, 8);
                System.arraycopy(workKey.ser, 0, buf, 8, 8);
                buf[16] = (byte)(workKey.compl & 0xFF);
                buf[17] = (byte)(workKey.compl >> 8 & 0xFF);
                buf[18] = (byte)(workKey.numCompl & 0xFF);
                buf[19] = (byte)(workKey.numCompl >> 8 & 0xFF);
                System.arraycopy(workKey.dateBegin, 0, buf, 20, 3);
                System.arraycopy(workKey.dateEnd, 0, buf, 23, 3);
            }
            return buf;
        }

        private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        private String int32ToHexString(int value) {
            char[] hexChars = new char[8];
            int i,j;

            for(i = 0, j = 0; i < 4; i++, j++) {
                int v = value >> 24 & 0xFF;
                value = value << 8;
                hexChars[j * 2] = HEX_ARRAY[v >>> 4];
                hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            }
            return new String(hexChars);
        }

        public class RequestTypeError extends Exception {
            String errStr;

            public RequestTypeError(String errStr) {
                this.errStr = errStr;
            }

            @Override
            public void printStackTrace() {
                System.err.println(errStr);
            }
        }
    }
}
