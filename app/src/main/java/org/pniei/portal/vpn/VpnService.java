package org.pniei.portal.vpn;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.notification.SpoNotificationsManager;
import org.pniei.moduleskzi.utils.Logger;
import org.pniei.moduleskzi.liveData.ManagerLiveData;
import org.pniei.moduleskzi.utils.PrefsUtils;

public class VpnService extends android.net.VpnService {
    private static final String TAG = "VpnService";

    public static final String ACTION_CONNECT = "CONNECT";
    public static final String ACTION_DISCONNECT = "DISCONNECT";
    public static final String ACTION_RECONNECT = "RECONNECT";
    private VpnConnection vpnConnection;
    private SpoNotificationsManager mSpoNotificationsManager;
    private boolean isStarting = false;

    private AtomicInteger mNextConnectionId = new AtomicInteger(1);

    @Override
    public void onCreate() {
        super.onCreate();
        mSpoNotificationsManager = SpoNotificationsManager.ins(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            switch (intent.getAction()) {
                case ACTION_CONNECT : {
                    if (!isStarting)
                        connect();
                    Log.i(TAG, "onStartCommand ACTION_CONNECT VpnService:" + this + " vpnConnection:" + vpnConnection);
                    return START_STICKY;
                }
                case ACTION_DISCONNECT : {
                    Log.i(TAG, "onStartCommand ACTION_DISCONNECT VpnService:" + this + " vpnConnection:" + vpnConnection);
                    disconnect();
                    stopSelf();
                    return START_NOT_STICKY;
                }
                case ACTION_RECONNECT : {
                    disconnect();
                    if (!isStarting)
                        connect();
                    Log.i(TAG, "onStartCommand ACTION_RECONNECT VpnService:" + this + " vpnConnection:" + vpnConnection);
                    return START_STICKY;
                }
            }
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "onDestroy VpnService:" + this + " vpnConnection:" + vpnConnection);
        disconnect();
    }

    private void connect() {
        final String ipSKZI = PrefsUtils.ins().getIpSkzi();
        final ArrayList<String> ipDNSs = new ArrayList<>();
        ipDNSs.add(PrefsUtils.ins().getIpDns());

        String secDns = PrefsUtils.ins().getIpDnsSecond();
        if (secDns != null && !secDns.equals("")) {
            ipDNSs.add(secDns);
        }

        SpoNotificationsManager.CreateChannel(this);
        mSpoNotificationsManager.startForeground(this);

        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        vpnConnection = new VpnConnection(this, mNextConnectionId.getAndIncrement(), ipSKZI, ipDNSs, 4500, cm);
        startConnection(vpnConnection);
        isStarting = true;
    }

    private void disconnect() {
        if(vpnConnection != null) {
            vpnConnection.stopConnection();
        }
        mSpoNotificationsManager.stopForeground(this);
        isStarting = false;
    }

    private void startConnection(final VpnConnection connection) {
        final Thread thread = new Thread(connection, "VpnThread");
        connection.setOnEstablishListener(new VpnConnection.OnEstablishListener() {
            public void onEstablish(ParcelFileDescriptor tunInterface) {
                updateMessageForeground(R.string.vpn_connected, 2);
            }

            public void updateMessageForeground(final int message, int signal) {
                if(message != R.string.vpn_wifi_mobdata_not_active)
                    Logger.inc().write(TAG, getString(message));
                ManagerLiveData.ins().setVpnInfoStatus(message);
            }

            public void restartClient() {
                disconnect();
                connect();
            }

            @Override
            public void onEstablishOnReserveKey() {
                // Остановка всех сервисов

            }
        });

        thread.start();
    }

}