package org.pniei.portal.vpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class VpnClientReceiver extends BroadcastReceiver {
    public final static String VPN_CLIENT_BROADCAST_ACTION = "vpn_client_broadcast_action";
    public final static String TYPE_MESSAGE = "type_message";
    public final static String IP_ADDRESS = "ip_address";
    public final static String VPN_STATUS = "vpn_status";
    public final static String VPN_QUALITY = "vpn_quality";
    public final static String DIF_TIME = "dif_time";
    public final static String SPEED_IN = "speed_in";
    public final static String SPEED_OUT = "speed_out";
    public final static String NUMBER_KOMPL = "number_kompl";
    public final static String NUMBER_SERIAL = "number_serial";

    public final static int SHOW_WAN_IP = 1;
    public final static int SHOW_LAN_IP = 2;
    public final static int SHOW_STATUS = 3;
    public final static int SHOW_TIME_ERROR = 4;
    public final static int SHOW_SPEED = 5;
    public final static int KOMPL_SERIAL_NUMBER = 6;
    public final static int SHOW_QUALITY = 7;

    public interface VpnClientReceiverCommands {
        void showWanIP(String wanIp);
        void showLanIP(String lanIp);
        void showStatusString(int idString);
        void showTimeError(long serverTime);
        void showSpeed(double speedIn, double speedOut);
        void showKeyInfo(int numberKompl, int numberSerial);
        void showQuality(int idString);
    }

    private VpnClientReceiverCommands mVpnClientReceiverCommands;

    public void setListener(VpnClientReceiverCommands listener) {
        mVpnClientReceiverCommands = listener;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if(mVpnClientReceiverCommands == null)
            return;

        int type_message = intent.getIntExtra(TYPE_MESSAGE, 0);
        switch (type_message) {
            case SHOW_WAN_IP: {
                mVpnClientReceiverCommands.showWanIP(intent.getStringExtra(IP_ADDRESS));
                break;
            }
            case SHOW_LAN_IP: {
                mVpnClientReceiverCommands.showLanIP(intent.getStringExtra(IP_ADDRESS));
                break;
            }
            case SHOW_STATUS: {
                mVpnClientReceiverCommands.showStatusString(intent.getIntExtra(VPN_STATUS, 0));
                break;
            }
            case SHOW_TIME_ERROR: {
                mVpnClientReceiverCommands.showTimeError(intent.getLongExtra(DIF_TIME, 0));
                break;
            }
            case SHOW_SPEED: {
                mVpnClientReceiverCommands.showSpeed(intent.getDoubleExtra(SPEED_IN, 0), intent.getDoubleExtra(SPEED_OUT, 0));
                break;
            }
            case KOMPL_SERIAL_NUMBER : {
                mVpnClientReceiverCommands.showKeyInfo(intent.getIntExtra(NUMBER_KOMPL, 0), intent.getIntExtra(NUMBER_SERIAL, 0));
                break;
            }
            case SHOW_QUALITY : {


                mVpnClientReceiverCommands.showQuality(intent.getIntExtra(VPN_QUALITY, 0));
                break;
            }
        }
    }
}
