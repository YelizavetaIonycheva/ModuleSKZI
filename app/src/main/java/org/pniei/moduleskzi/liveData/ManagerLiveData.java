package org.pniei.moduleskzi.liveData;

import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import org.pniei.moduleskzi.R;

public class ManagerLiveData {
    private static ManagerLiveData instance;

    private VpnInfo mVpnInfo;

    private MutableLiveData<Integer> gpsEvent;
    private MutableLiveData<Integer> vpnQuality;
    private MutableLiveData<VpnInfo> vpnInfoLiveData;
    private MutableLiveData<String> skziTimeError;

    private ManagerLiveData() {
        mVpnInfo = new VpnInfo();
        gpsEvent = new MutableLiveData<>();
        vpnQuality = new MutableLiveData<>();
        vpnInfoLiveData = new MutableLiveData<>();
        skziTimeError = new MutableLiveData<>();
    }

    public static ManagerLiveData ins() {
        if (instance == null) {
            instance = new ManagerLiveData();
        }
        return instance;
    }

    public static final class GpsEvent {
        public static final int NOT_USE = -1;
        public static final int PROVIDER_DISABLE = 0;
        public static final int PROVIDER_ENABLE = 1;
        public static final int LOCATION_NOT_FIXED = 2;
        public static final int LOCATION_FIXED = 3;
    }

    public static final class VpnQuality {
        public static final int VPN_DISABLE = -1;
        public static final int VPN_ENABLE = 0;
        public static final int QUALITY_HIGH = 1;
        public static final int QUALITY_MIDL = 2;
        public static final int QUALITY_LOW = 3;
    }

    public class VpnInfo {
        private int idStrStatus;
        private String wanIP;
        private String lanIP;
        private double speedIN;
        private double speedOUT;
        private int idStrQuality;

        public VpnInfo() {
            idStrStatus = R.string.vpn_not_connecting;
            wanIP = "";
            lanIP = "";
            idStrQuality = R.string.connection_quality_non;
        }

        public int getIdStrStatus() {
            return idStrStatus;
        }

        public void setIdStrStatus(int idStrStatus) {
            this.idStrStatus = idStrStatus;
        }

        public String getWanIP() {
            return wanIP;
        }

        public void setWanIP(String wanIP) {
            this.wanIP = wanIP;
        }

        public String getLanIP() {
            return lanIP;
        }

        public void setLanIP(String lanIP) {
            this.lanIP = lanIP;
        }

        public double getSpeedIN() {
            return speedIN;
        }

        public void setSpeedIN(double speedIN) {
            this.speedIN = speedIN;
        }

        public double getSpeedOUT() {
            return speedOUT;
        }

        public void setSpeedOUT(double speedOUT) {
            this.speedOUT = speedOUT;
        }

        public int getIdStrQuality() {
            return idStrQuality;
        }

        public void setIdStrQuality(int idStrQuality) {
            this.idStrQuality = idStrQuality;
        }
    }


    public LiveData<Integer> getGpsEvent() {
        return gpsEvent;
    }

    public void setGpsEvent(int event) {
        gpsEvent.postValue(event);
    }

    public LiveData<Integer> getVpnQuality() {
        return vpnQuality;
    }

    public void setVpnQuality(int quality) {
        vpnQuality.postValue(quality);
    }

    public LiveData<VpnInfo> getVpnInfo() {
        return vpnInfoLiveData;
    }

    public void setVpnInfoStatus(int id) {
        mVpnInfo.setIdStrStatus(id);
        vpnInfoLiveData.postValue(mVpnInfo);
    }

    public void setVpnInfoWanIp(String wanIp) {
        mVpnInfo.setWanIP(wanIp);
        vpnInfoLiveData.postValue(mVpnInfo);
    }

    public void setVpnInfoLanIp(String lanIp) {
        mVpnInfo.setLanIP(lanIp);
        vpnInfoLiveData.postValue(mVpnInfo);
    }

    public void setVpnInfoSpeed(double speedIn, double speedOut) {
        mVpnInfo.setSpeedIN(speedIn);
        mVpnInfo.setSpeedOUT(speedOut);
        vpnInfoLiveData.postValue(mVpnInfo);
    }

    public void setVpnInfoQuality(int id) {
        mVpnInfo.setIdStrQuality(id);
        vpnInfoLiveData.postValue(mVpnInfo);
    }

    public void clearVpnInfo() {
        mVpnInfo.setIdStrStatus(R.string.vpn_not_connecting);
        mVpnInfo.setLanIP("");
        mVpnInfo.setWanIP("");
        mVpnInfo.setSpeedIN(0.0);
        mVpnInfo.setSpeedOUT(0.0);
        mVpnInfo.setIdStrQuality(R.string.connection_quality_non);
    }
    
    public LiveData<String> getSkziTimeError() {
        return skziTimeError;
    }

    public void setSkziTimeError(String strError) {
        skziTimeError.postValue(strError);
    }
}
