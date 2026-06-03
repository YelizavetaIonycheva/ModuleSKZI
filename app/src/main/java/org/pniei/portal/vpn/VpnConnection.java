package org.pniei.portal.vpn;

import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.pniei.portal.R;
import org.pniei.moduleskzi.utils.Logger;
import org.pniei.moduleskzi.liveData.ManagerLiveData;
import org.pniei.moduleskzi.utils.PrefsUtils;

public class VpnConnection implements Runnable {

    public interface OnEstablishListener {
        void onEstablish(ParcelFileDescriptor tunInterface);
        void updateMessageForeground(final int message, int signal);
        void restartClient();
        void onEstablishOnReserveKey();
    }

    private static final int MAX_PACKET_SIZE = 4500;
    private static final long KEEPALIVE_IKEV2_INTERVAL_MS1 = TimeUnit.SECONDS.toMillis(40);
    private static final long KEEPALIVE_IKEV2_INTERVAL_MS2 = TimeUnit.SECONDS.toMillis(30);
    private static final long KEEPALIVE_IKEV2_INTERVAL_MS3 = TimeUnit.SECONDS.toMillis(20);
    private static long KEEPALIVE_IKEV2_INTERVAL_MS = KEEPALIVE_IKEV2_INTERVAL_MS1;
    private static final int MAX_HANDSHAKE_ATTEMPTS = 3;
    private static final int KEEPALIVE_IKEV2_MAX = 5;
    private final VpnService mService;
    private final int mConnectionId;
    private final String mSkziAdress;
    private final ArrayList<String> mDnsAddresses;
    private final int mSkziPort;
    private final short serverNetNumber = (short)0xF2D2;
    private boolean isConnect = false;
    private boolean isWork;
    private OnEstablishListener mOnEstablishListener;
    private ConnectivityManager mConManager;
    private DatagramChannel tunnel;
    private FileInputStream in = null;
    private FileOutputStream out = null;
    private Event event;
    private int countDataIn = 0, countDataOut = 0;
    private long lastTimeSendKeepAlive;
    private int counterSendKeepalive = 0;
    private final LinkedBlockingQueue<byte []> localPackages = new LinkedBlockingQueue<>();
    private final LinkedBlockingQueue<byte []> skziPackages = new LinkedBlockingQueue<>();

    private enum Event {
        OK,                 // Нет ошибок
        ERROR,              // Любая ошибка соединения
        NOT_CONNECT,        // неудалось подключиться к серверу (ошибка аутентификации)
        SERVER_NOT_RESP,    // Сервер не отвечает
        SERVER_DISCONNECT,  // Сервер разорвал соединение
        CLIENT_DISCONNECT   // Клиент разорвал соединение
    }


    public VpnConnection(final VpnService service, final int connectionId,
                         final String skziAddress, final ArrayList<String> dnsAddresses,
                         final int skziPort, ConnectivityManager cM) {
        mService = service;
        mConnectionId = connectionId;
        mSkziAdress = skziAddress;
        mDnsAddresses = dnsAddresses;
        mSkziPort = skziPort;
        mConManager = cM;
    }

    public void setOnEstablishListener(OnEstablishListener listener) {
        mOnEstablishListener = listener;
    }

    public void stopConnection() {
         isWork = false;
         VpnClient.setWork(false);
    }

    public class CheckTimeSaThread extends Thread {
        @Override
        public void run() {
            byte [] buffer;
            short netNum;
            int [] lengthOut = new int [1];
            VpnClient vpnClient = VpnClient.ins();
            VpnClient.KeyInf workKey;
            ByteBuffer packet = ByteBuffer.allocate(MAX_PACKET_SIZE);
            Log.i(getTag(), "CheckTimeSaThread START");
            while(isWork && (event == Event.OK)) {
                try {
                    Thread.sleep(1000);

                    if (vpnClient.checktimesa() == 1) {
                        workKey = vpnClient.getWorkKey();

                        if (workKey != null) {
                            netNum = workKey.compl;

                            /** Попытка установки соединения на основном ключе **/
                            vpnClient.ikev2init(netNum, tunnel.socket().getLocalPort(), tunnel.socket().getLocalAddress().getAddress(),
                                    serverNetNumber, tunnel.socket().getPort(), tunnel.socket().getInetAddress().getAddress(),
                                    workKey.kd, workKey.ser, workKey.compl,
                                    workKey.numCompl, new Random().nextInt(), null, null);

                            int countConnection = 0;
                            while (vpnClient.getikev2stage() != 4) {
                                if (countConnection == 3) {
                                    event = Event.SERVER_NOT_RESP;
                                    break;
                                }

                                buffer = vpnClient.ikev2getikesainit(lengthOut);
                                vpnClient.setConnectingKey(workKey);
                                packet.put(buffer).flip();
                                packet.position(0);
                                packet.limit(lengthOut[0]);
                                tunnel.write(packet);
                                packet.clear();
                                countConnection++;
                                Log.d(getTag(), "NEW IKE_SA_INIT --> . count - " + countConnection);
                                Thread.sleep(15000); // 15 секунд на установку соединения
                            }
                        }
                    }
                } catch (InterruptedException | IOException e) {
                    e.printStackTrace();
                }
            }
            Log.i(getTag(), "CheckTimeSaThread END");
        }
    }

    public class PingThread extends Thread {

        public boolean ping(String addr) {
                try {
                    Runtime runtime = Runtime.getRuntime();
                    try {
                        Process ipProcess = runtime.exec("/system/bin/ping -c 1 " + addr);
                        if(ipProcess.waitFor() == 0) {
                            return true;
                        } else {
                            return false;
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        return false;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
        }

        @Override
        public void run() {
            Log.i(getTag(), "PingThread START");
            while(isWork && (event == Event.OK)) {
                if (!PrefsUtils.ins().isAppBackground()) {
                    long start = System.currentTimeMillis();
                    if (ping(PrefsUtils.ins().getIpMon())) {
                        long end = System.currentTimeMillis();
                        checkQuality(end - start);
                        try { Thread.sleep(5000); } catch (InterruptedException ignored) { }
                    } else {
                        if (isWork) {
                            checkQuality(0xFFFFFF);
                            try {
                                Thread.sleep(1000);
                            } catch (InterruptedException ignored) {
                            }
                        }
                    }
                } else {
                    try { Thread.sleep(5000); } catch (InterruptedException ignored) { }
                }
            }
            Log.i(getTag(), "PingThread END");
        }
    }

    public class FromSkziDataThread extends Thread {
        @Override
        public void run() {
            byte [] buffer;
            byte [] dataOut = new byte[MAX_PACKET_SIZE];
            int [] lengthOut = new int [1];
            int [] target  = new int [1];
            int [] err = new int [1];
            VpnClient vpnClient = VpnClient.ins();
            ByteBuffer packet = ByteBuffer.allocate(MAX_PACKET_SIZE);

            Log.d(getTag(), "SkziDataThread START");

            while(isWork && (event == Event.OK)) {
                try {
                    buffer = skziPackages.take();
                    vpnClient.vpnprocessingdata(buffer, buffer.length, dataOut, lengthOut, target, err);
                    Log.d(getTag(), "vpnClient.vpnprocessingdata");
                    buffer = null;
                    switch(err[0]) {
                        case 0: {
                            //printFromTo(dataOut);
                            countDataIn += lengthOut[0];
                            if(target[0] == 2) {
                                //Log.i(getTag(), "Send to LOCAL. len = " + lengthOut[0]);
                                out.write(dataOut, 0, lengthOut[0]);
                            }
                            else if(target[0] == 1) {
                                Log.i(getTag(), "Send to SKZI");
                                packet.clear();
                                packet.put(dataOut).flip();
                                packet.limit(lengthOut[0]);
                                packet.position(0);
                                tunnel.write(packet);
                                packet.clear();
                            }
                            break;
                        }
                        case 1: {
                            Log.d(getTag(), "Packet break from WAN");
                            break;
                        }
                        case 2: {
                            counterSendKeepalive = 0;
                            Log.d(getTag(), "Keepalive IKEv2 get Response");
                            break;
                        }
                        case 3: {
                            Log.d(getTag(), "Keepalive Additional IKEv2 get");
                            break;
                        }
                        case 4: {
                            Log.d(getTag(), "Server Delete get");
                            vpnClient.ikev2getdelete(dataOut, lengthOut);
                            if(lengthOut[0] != 0) {
                                packet.clear();
                                packet.put(dataOut).flip();
                                packet.limit(lengthOut[0]);
                                packet.position(0);
                                tunnel.write(packet);
                                packet.clear();
                            }
                            event = Event.SERVER_DISCONNECT;
                            break;
                        }
                        default: {
                            Log.e(getTag(), "libVpnClient err = " + err[0]);
                        }
                    }
                    packet.clear();
                } catch (InterruptedException | IOException | BufferOverflowException e) {
                    e.printStackTrace();
                }
            }
            Log.i(getTag(), "SkziDataThread END");
        }
    }

    public class FromLocalDataThread extends Thread {
        @Override
        public void run() {
            int result;
            byte [] buffer;
            byte dataOut [] = new byte[MAX_PACKET_SIZE];
            int [] lengthOut = new int [1];
            VpnClient vpnClient = VpnClient.ins();
            ByteBuffer packet = ByteBuffer.allocate(MAX_PACKET_SIZE);

            Log.i(getTag(), "LocalDataThread START");
            while(isWork && (event == Event.OK)) {
                try {
                    buffer = localPackages.take();
                    result = vpnClient.espencapsuldata(buffer, dataOut, buffer.length, lengthOut);
                    buffer = null;
                    if((result == 0) && (lengthOut[0] > 0) && (lengthOut[0] <= MAX_PACKET_SIZE)) {
                        packet.put(dataOut).flip();
                        packet.limit(lengthOut[0]);
                        packet.position(0);
                        tunnel.write(packet);
                        packet.clear();
                        countDataOut += lengthOut[0];
                    } else {
                        Log.e(getTag(), "Send to SKZI result = " + result);
                    }
                } catch (InterruptedException | IOException | BufferOverflowException e) {
                    e.printStackTrace();
                }
            }
            Log.i(getTag(), "LocalDataThread END");
        }
    }

    @Override
    public void run() {
        final SocketAddress serverAddress = new InetSocketAddress(mSkziAdress, mSkziPort);
        NetworkInfo networkInfo;
        isWork = true;
        VpnClient.setWork(true);
        Log.i(getTag(), "Starting + " + serverAddress.toString());
        while(isWork && !Thread.currentThread().isInterrupted()) {
            try {
                // Проверка на активность Wi-Fi и Сети
                networkInfo = mConManager.getActiveNetworkInfo();

                if (networkInfo == null) {
                    // Если сетевые адаптеры не включены
                    mOnEstablishListener.updateMessageForeground(R.string.vpn_wifi_mobdata_not_active, 0);
                    Thread.sleep(1000);
                    continue;
                }
                mOnEstablishListener.updateMessageForeground(R.string.vpn_connecting, 1);
                Log.i(getTag(), "Устанавливается VPN соединение...");
                Event event = connectionProcess(serverAddress);

                switch (event) {
                    case CLIENT_DISCONNECT: {
                        isConnect = false;
                        Log.i(getTag(), "CLIENT_DISCONNECT");
                        ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.VPN_DISABLE);
                        ManagerLiveData.ins().setVpnInfoStatus(R.string.vpn_not_connecting);
                        break;
                    }
                    case ERROR:{
                        mOnEstablishListener.updateMessageForeground(R.string.vpn_faild_connect_to_server,0);
                        isConnect = false;
                        Thread.sleep(500);
                        if (isWork) {
                            mOnEstablishListener.restartClient();
                        }
                        Log.i(getTag(), "ERROR");
                        break;
                    }
                    case NOT_CONNECT: {
                        Log.i(getTag(), "NOT_CONNECT");
                        Logger.inc().write(getTag(), "NOT_CONNECT");
                        if (isWork)
                            mOnEstablishListener.restartClient();
                        break;
                    }
                    case SERVER_NOT_RESP: {
                        mOnEstablishListener.updateMessageForeground(R.string.vpn_server_not_available, 0);
                        isConnect = false;
                        if (isWork)
                            mOnEstablishListener.restartClient();
                        Log.i(getTag(), "SERVER_NOT_RESP");
                        break;
                    }
                    case SERVER_DISCONNECT: {
                        mOnEstablishListener.updateMessageForeground(R.string.vpn_server_disconnected, 0);
                        isConnect = false;
                        if (isWork)
                            mOnEstablishListener.restartClient();
                        Log.i(getTag(), "SERVER_DISCONNECT");
                        break;
                    }
                }
            } catch (Exception e) {
                Log.e(getTag(), "Connection failed, exiting", e);
                Logger.inc().write(getTag(), e.getMessage());
            }
        }
        Log.i(getTag(), "Stop");
    }

    /**
    *   Возвращает номер события завершившего выполнение функции:
    *   0 - ошибка
    *   1 - неудалось подключиться к серверу (ошибка аутентификации)
    *   2 - сервер не отвечает
    *   3 - сервер разорвал соединение
    *   4 - клиент разорвал соединение
     */

    private Event connectionProcess(SocketAddress server) {
        long nowTime, measureTime, timeSleep;
        int  lenIn;

        boolean sendKeepAliveIKEv2 = true;
        long lastTimeResponse;
        ParcelFileDescriptor iface = null;
        VpnClient vpnClient = VpnClient.ins();
        FromLocalDataThread localDataThread = new FromLocalDataThread();
        FromSkziDataThread skziDataThread = new FromSkziDataThread();
        PingThread pingThread = new PingThread();
        //CheckTimeSaThread checkTimeSaThread = new CheckTimeSaThread();

        event = Event.OK;
        try {
            tunnel = DatagramChannel.open();
            if (!mService.protect(tunnel.socket())) {
                throw new IllegalStateException("Cannot protect the tunnel");
            }

            tunnel.connect(server);
            tunnel.configureBlocking(false);

            ManagerLiveData.ins().setVpnInfoWanIp(tunnel.socket().getLocalAddress().toString().substring(1));
            ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.VPN_ENABLE);

            iface = handshake(tunnel);
            if(iface == null) {
                if (!isWork)
                    return Event.CLIENT_DISCONNECT;
                else
                	return Event.NOT_CONNECT;
            }

            ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.QUALITY_HIGH);

            in = new FileInputStream(iface.getFileDescriptor());
            out = new FileOutputStream(iface.getFileDescriptor());
            lastTimeResponse = System.currentTimeMillis();
            measureTime = System.currentTimeMillis();

            // Запуск потока обработки данных из локальной сети
            localDataThread.start();
            // Запуск потока обработки данных от СКЗИ
            skziDataThread.start();
            // Запуск потока проверки качества соединения
            pingThread.start();
            // Запуск потока установки новых соединений
            //checkTimeSaThread.start();
            ByteBuffer packet = ByteBuffer.allocate(MAX_PACKET_SIZE);
            vpnClient.setConnected(true);
            lastTimeSendKeepAlive = System.currentTimeMillis();

            while (isWork && (event == Event.OK)) {
                sendKeepAliveIKEv2 = true;
                nowTime = System.currentTimeMillis();

                // Чтение данных из локальной сети
                lenIn = in.read(packet.array());
                if (lenIn > 0) {
                    byte[] inBuffer = new byte[lenIn];
                    System.arraycopy(packet.array(), 0, inBuffer, 0, lenIn);
                    //printFromTo(inBuffer);
                    //Log.d(getTag(), "Local data size = " + lenIn);
                    localPackages.offer(inBuffer);
                    packet.clear();
                    lastTimeResponse = nowTime;
                }

                // Чтение данных от СКЗИ
                lenIn = tunnel.read(packet);
                if (lenIn > 0) {
                    byte[] inBuffer = new byte[lenIn];
                    System.arraycopy(packet.array(), 0, inBuffer, 0, lenIn);
                    //Log.d(getTag(), "SKZI data size = " + lenIn);
                    skziPackages.offer(inBuffer);
                    packet.clear();
                    lastTimeSendKeepAlive = lastTimeResponse = nowTime;
                    sendKeepAliveIKEv2 = false;
                }

                nowTime = System.currentTimeMillis();
                if(nowTime - measureTime > 1000) {
                    double speedIn = countDataIn / (double)(nowTime - measureTime) * 0.9765625f;
                    double speedOut = countDataOut / (double)(nowTime - measureTime) * 0.9765625f;
                    ManagerLiveData.ins().setVpnInfoSpeed(speedIn, speedOut); // kB/s
                    countDataIn = countDataOut = 0;
                    measureTime = System.currentTimeMillis();
                }

                if(sendKeepAliveIKEv2) {
                    switch(counterSendKeepalive) {
                        case 0: KEEPALIVE_IKEV2_INTERVAL_MS = KEEPALIVE_IKEV2_INTERVAL_MS1; break;
                        case 1: KEEPALIVE_IKEV2_INTERVAL_MS = KEEPALIVE_IKEV2_INTERVAL_MS2; break;
                        default: KEEPALIVE_IKEV2_INTERVAL_MS = KEEPALIVE_IKEV2_INTERVAL_MS3; break;
                    }

                    if (lastTimeSendKeepAlive + KEEPALIVE_IKEV2_INTERVAL_MS <= nowTime) {
                        if(counterSendKeepalive == KEEPALIVE_IKEV2_MAX) {
                            event = Event.SERVER_NOT_RESP;
                            break;
                        }
                        int [] lengthOut = new int [1];
                        byte dataOut [] = new byte[MAX_PACKET_SIZE];

                        vpnClient.ikev2getkeepalive(dataOut, lengthOut);
                        if(lengthOut[0] != 0) {
                            packet.clear();
                            packet.put(dataOut).flip();
                            packet.limit(lengthOut[0]);
                            packet.position(0);
                            tunnel.write(packet);
                            packet.clear();
                            counterSendKeepalive++;
                        }
                        lastTimeSendKeepAlive = nowTime;
                        Log.d(getTag(), "Keepalive IKEv2 send");
                    }
                }

                //if(SpoConfig.ins().isEnergySave()) {
                    long time = nowTime - lastTimeResponse;
                    if (time < 250) {
                        continue;
                    } else if (time < 500) {
                        timeSleep = 10;
                    } else if (time < 1000) {
                        timeSleep = 100;
                    } else {
                        timeSleep = 250;
                    }
                    //Log.i(getTag(), "Sleep = " + timeSleep);
                    Thread.sleep(timeSleep);
                //}
            }
        } catch (IOException | InterruptedException | IllegalStateException | IllegalArgumentException e) {
            event = Event.ERROR;
            Log.e(getTag(), "Cannot use socket", e);
            e.printStackTrace();
        } finally {
            if (iface != null) {
                try {
                    iface.close();
                } catch (IOException e) {
                    Log.e(getTag(), "Unable to close interface", e);
                }
            }
            skziPackages.clear();
            localPackages.clear();
            localDataThread.interrupt();
            skziDataThread.interrupt();
            pingThread.interrupt();
            //checkTimeSaThread.interrupt();
            ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.VPN_ENABLE);
            VpnClient.ins().setConnected(false);
        }

        if (!isWork)
            event = Event.CLIENT_DISCONNECT;

        Log.e(getTag(), "connectionProcess END event = " + event);
        return event;
    }

    private int index = 0;
    private long [] buf_time_delay = new long [3];
    private void checkQuality(long timeDelay) {
        new Thread(() -> {
            int idStringQuality;
            long meanTimeDelay = 0;
            buf_time_delay[index] = timeDelay;
            index = (index + 1) % buf_time_delay.length;

            for(long value : buf_time_delay)
                meanTimeDelay += value;

            meanTimeDelay /= buf_time_delay.length;
            if (!isWork) {
                if (meanTimeDelay <= 150) {
                    ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.QUALITY_HIGH);
                    idStringQuality = R.string.connection_quality_high;
                } else if (meanTimeDelay <= 400) {
                    ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.QUALITY_MIDL);
                    idStringQuality = R.string.connection_quality_middle;
                } else {
                    ManagerLiveData.ins().setVpnQuality(ManagerLiveData.VpnQuality.QUALITY_LOW);
                    idStringQuality = R.string.connection_quality_low;
                }
                ManagerLiveData.ins().setVpnInfoQuality(idStringQuality);
            }


        }).start();
    }

    private ParcelFileDescriptor handshake(DatagramChannel tunnel) throws IOException, InterruptedException {
        long lastSendTime;
        byte [] ikesainit;
        byte [] dataOut = new byte[1500];
        int [] lenData = new int[1];
        int [] target  = new int[1];
        int [] err  = new int[1];
        int length;
        short netNum;
        final int TIME_WAIT = 5000;
        final int TIME_SLEEP = 100;

        ByteBuffer packet = ByteBuffer.allocate(1500);
        VpnClient vpnClient = VpnClient.ins();
        VpnClient.KeyInf workKey = vpnClient.getWorkKey();
        ArrayList<VpnClient.KeyInf> nextKeys = vpnClient.getNextKeys();

        if (workKey != null) {
            netNum = workKey.compl;

            /** Попытка установки соединения на основном ключе **/
            vpnClient.ikev2clear();
            vpnClient.ikev2init(netNum, tunnel.socket().getLocalPort(), tunnel.socket().getLocalAddress().getAddress(),
                    serverNetNumber, tunnel.socket().getPort(), tunnel.socket().getInetAddress().getAddress(),
                    workKey.kd, workKey.ser, workKey.compl,
                    workKey.numCompl, new Random().nextInt(), workKey.tz, workKey.key_dsch);
            ikesainit = vpnClient.ikev2getikesainit(lenData);

            vpnClient.setConnectingKey(workKey);
            // Совершаем 3 попытки установления соединения
            for (int i = 0; i < MAX_HANDSHAKE_ATTEMPTS && isWork; i++) {
                packet.put(ikesainit).flip();
                packet.position(0);
                packet.limit(lenData[0]);
                tunnel.write(packet);
                packet.clear();
                lastSendTime = System.currentTimeMillis();
                Log.i(getTag(), "IKE_SA_INIT -->");
                // 3 секунды на принятие правильного пакета только потом повторная передача
                while ((System.currentTimeMillis() - lastSendTime) < 3000 && isWork) {
                    Thread.sleep(100);
                    length = tunnel.read(packet);
                    if (length > 0) {
                        Log.i(getTag(), "IKE_SA_INIT <--");
                        vpnClient.vpnprocessingdata(packet.array(), length, dataOut, lenData, target, err); // Обработка ответа на IKE_SA_INIT
                        // Добавить проверку стадии
                        if (err[0] == 0) {
                            for (int j = 0; j < MAX_HANDSHAKE_ATTEMPTS && isWork; j++) {
                                packet.clear();
                                packet.put(dataOut).flip();
                                packet.position(0);
                                packet.limit(lenData[0]);
                                tunnel.write(packet);
                                packet.clear();
                                lastSendTime = System.currentTimeMillis();
                                Log.i(getTag(), "IKE_SA_AUTH -->");
                                // 3 секунды на принятие правильного пакета только потом повторная передача
                                while ((System.currentTimeMillis() - lastSendTime) < 3000 && isWork) {
                                    Thread.sleep(100);
                                    length = tunnel.read(packet);
                                    if (length > 0) {
                                        Log.i(getTag(), "IKE_SA_AUTH <--");
                                        vpnClient.vpnprocessingdata(packet.array(), length, dataOut, lenData, target, err); // Обработка ответа на IKE_AUTH
                                        if (err[0] == 0) {
                                            int ipAddr = vpnClient.getikev2ipaddr();
                                            int ipMask = vpnClient.getikev2ipmask();
                                            StringBuilder sb = new StringBuilder();
                                            sb.append("a,");
                                            sb.append(((ipAddr & 0xff000000) >> 24) & 0xff);
                                            sb.append(".");
                                            sb.append(((ipAddr & 0x00ff0000) >> 16) & 0xff);
                                            sb.append(".");
                                            sb.append(((ipAddr & 0x0000ff00) >> 8) & 0xff);
                                            sb.append(".");
                                            sb.append(ipAddr & 0x000000ff);
                                            sb.append(",");
                                            sb.append(ipMask);
                                            sb.append(" r,0.0.0.0,0");
                                            isConnect = true;
                                            Log.d(getTag(), sb.toString());
                                            Log.d(getTag(), "ip server = " + mSkziAdress);
                                            return configure(sb.toString(), false);
                                        } else {
                                            Log.e(getTag(), "ERR = " + err[0]);
                                            break;
                                        }
                                    } else {
                                        Log.i(getTag(), "length ="+ length);
                                    }
                                }
                            }
                        } else {
                            Log.i(getTag(), "err[0] ="+ err[0]);
                        }
                        break;
                    }
                }
            }
        }

        /** Попытка установки соединения на очередных ключах **/
        /** НЕ ОБРАЩАЯ ВНИМАНИЯ НА ДАТУ НАЧАЛА **/
        if(nextKeys == null)
            return null;

        for(VpnClient.KeyInf keyInf : nextKeys) {
            netNum = keyInf.compl;

            /** Попытка установки соединения на резервном ключе **/
            vpnClient.ikev2clear();
            vpnClient.ikev2init(netNum, tunnel.socket().getLocalPort(), tunnel.socket().getLocalAddress().getAddress(),
                    serverNetNumber, tunnel.socket().getPort(), tunnel.socket().getInetAddress().getAddress(),
                    keyInf.kd, keyInf.ser, keyInf.compl,
                    keyInf.numCompl, new Random().nextInt(), workKey.tz, keyInf.key_dsch);
            ikesainit = vpnClient.ikev2getikesainit(lenData);

            vpnClient.setConnectingKey(keyInf);
            // Совершаем 3 попытки установления соединения
            for (int i = 0; i < MAX_HANDSHAKE_ATTEMPTS && isWork; i++) {
                packet.put(ikesainit).flip();
                packet.position(0);
                packet.limit(lenData[0]);
                tunnel.write(packet);
                packet.clear();
                lastSendTime = System.currentTimeMillis();
                Log.i(getTag(), "IKE_SA_INIT -->");
                // 3 секунды на принятие правильного пакета только потом повторная передача
                while ((System.currentTimeMillis() - lastSendTime) < TIME_WAIT && isWork) {
                    Thread.sleep(TIME_SLEEP);
                    length = tunnel.read(packet);
                    if (length > 0) {
                        Log.i(getTag(), "IKE_SA_INIT <--");
                        vpnClient.vpnprocessingdata(packet.array(), length, dataOut, lenData, target, err); // Обработка ответа на IKE_SA_INIT
                        // Добавить проверку стадии
                        if (err[0] == 0) {
                            for (int j = 0; j < MAX_HANDSHAKE_ATTEMPTS && isWork; j++) {
                                packet.clear();
                                packet.put(dataOut).flip();
                                packet.position(0);
                                packet.limit(lenData[0]);
                                tunnel.write(packet);
                                packet.clear();
                                lastSendTime = System.currentTimeMillis();
                                Log.i(getTag(), "IKE_SA_AUTH -->");
                                // 3 секунды на принятие правильного пакета только потом повторная передача
                                while ((System.currentTimeMillis() - lastSendTime) < TIME_WAIT && isWork) {
                                    Thread.sleep(TIME_SLEEP);
                                    length = tunnel.read(packet);
                                    if (length > 0) {
                                        Log.i(getTag(), "IKE_SA_AUTH <--");
                                        vpnClient.vpnprocessingdata(packet.array(), length, dataOut, lenData, target, err); // Обработка ответа на IKE_AUTH
                                        if (err[0] == 0) {
                                            int ipAddr = vpnClient.getikev2ipaddr();
                                            int ipMask = vpnClient.getikev2ipmask();
                                            StringBuilder sb = new StringBuilder();
                                            sb.append("a,");
                                            sb.append(((ipAddr & 0xff000000) >> 24) & 0xff);
                                            sb.append(".");
                                            sb.append(((ipAddr & 0x00ff0000) >> 16) & 0xff);
                                            sb.append(".");
                                            sb.append(((ipAddr & 0x0000ff00) >> 8) & 0xff);
                                            sb.append(".");
                                            sb.append(ipAddr & 0x000000ff);
                                            sb.append(",");
                                            sb.append(ipMask);
                                            sb.append(" r,0.0.0.0,0");
                                            isConnect = true;
                                            Log.i(getTag(), sb.toString());
                                            Log.i(getTag(), "ip server = " + mSkziAdress);
                                            return configure(sb.toString(), true);
                                        } else {
                                            Log.e(getTag(), "ERR = " + err[0]);
                                            break;
                                        }
                                    } else {
                                        Log.i(getTag(), "length2 ="+ length);
                                    }
                                }
                            }
                        }else {
                            Log.i(getTag(), "err[0] ="+ err[0]);
                        }
                        break;
                    }
                }
            }
        }

        return null;
    }

    private ParcelFileDescriptor configure(String parameters, boolean isReserveKey) throws IllegalArgumentException, UnknownHostException {
        StringBuilder sb = new StringBuilder();
        VpnService.Builder builder = mService.new Builder();
        for (String parameter : parameters.split(" ")) {
            String[] fields = parameter.split(",");
            try {
                switch (fields[0].charAt(0)) {
                    case 'a':
                        if (Integer.parseInt(fields[2]) == 0) {
                            builder.addAddress(fields[1], 24);
                        } else {
                            builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                        }
                        ManagerLiveData.ins().setVpnInfoLanIp(fields[1]);
                        sb.append("VPN interface Created. LanIp:").append(fields[1]);
                        break;
                    case 'r':
                        builder.addRoute(fields[1], Integer.parseInt(fields[2]));
                        /*builder.addRoute("172.16.10.230", 32);F
                        builder.addRoute("172.16.10.1", 32);
                        builder.addRoute("10.0.7.40", 32);*/

                        break;
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Bad parameter: " + parameter);
            }
        }

        if(mDnsAddresses != null) {
            for (String address : mDnsAddresses)
                builder.addDnsServer(address);
        }

        if (!PrefsUtils.ins().isCaptureAll()) {
            try {
                builder.addAllowedApplication(mService.getPackageName());
                //builder.addAllowedApplication("com.android.chrome");
                for(String packageApp: PrefsUtils.ins().getVpnApps()) {
                    try {
                        builder.addAllowedApplication(packageApp);
                    }
                    catch (Exception e){}
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        builder.setMtu(1300);

        final ParcelFileDescriptor vpnInterface;
        synchronized (mService) {
            vpnInterface = builder.establish();
            if (mOnEstablishListener != null) {
                mOnEstablishListener.onEstablish(vpnInterface);
            }
            if (isReserveKey)
                mOnEstablishListener.onEstablishOnReserveKey();
        }
        // Исключаем 192.168.0.0/16 для доступа к IP-камере
        /*if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            byte[] ipv4Bytes = new byte[]{(byte) 192, (byte) 168, (byte) 101, (byte) 0};
            IpPrefix ipecac = new IpPrefix( InetAddress.getByAddress(ipv4Bytes)    , 24);
            try {
                builder.excludeRoute(ipecac);

                Log.d(getTag(), "Excluded network: " + ipecac);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }*/
        Logger.inc().write(getTag(), sb.toString());
        return vpnInterface;
    }

    private final String getTag() {
        return VpnConnection.class.getSimpleName() + "[" + mConnectionId + "]";
    }

    private void printFromTo(byte [] ipPacket) {
        StringBuilder sb = new StringBuilder();
        sb.append("Packet from ");
        sb.append(ipPacket[12] & 0xFF);
        sb.append(".");
        sb.append(ipPacket[13] & 0xFF);
        sb.append(".");
        sb.append(ipPacket[14] & 0xFF);
        sb.append(".");
        sb.append(ipPacket[15] & 0xFF);
        sb.append(" to ");
        sb.append(ipPacket[16] & 0xFF);
        sb.append(".");
        sb.append(ipPacket[17] & 0xFF);
        sb.append(".");
        sb.append(ipPacket[18] & 0xFF);
        sb.append(".");
        sb.append(ipPacket[19] & 0xFF);
        Log.i(getTag(), sb.toString());
    }
}

