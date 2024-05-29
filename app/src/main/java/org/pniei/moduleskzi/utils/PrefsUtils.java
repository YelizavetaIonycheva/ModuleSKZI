package org.pniei.moduleskzi.utils;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

public class PrefsUtils {
    private final String TAG = "PrefsUtils";
    private static PrefsUtils instance;
    private boolean isLicenseReg;
    private boolean isPrefsSet;
    private boolean isAuth = false;
    private String mHashPass;           // Хэш на пароль пользователя
    private String mHashLoginPass;      // Хэш на пароль пользователя для авторизации
    private String mIpDns;              // IP-адрес DNS в режиме Портал
    private String mIpDnsSecond;        // IP-адрес DNS дополнительный в режиме Портал
    private String mIpSkzi;             // IP-адрес СКЗИ
    private String mIpMon;              // IP-адрес сервера мониторинга ключей
    private boolean isAppBackground;    // Признак работы в фоне (Не сохраняется в файл)
    private Set<String> app_vpn_list;   // Список браузеров работающих через VPN
    private boolean isVpnEnable;        // Признак работы VPN в режиме Портал
    private boolean isCaptureAll;       // Признак захвата всего трафика
    private boolean isNetworkAvailable;

    public interface Prefs {
        String NAME =               "moduleskzi_settings";
        String IS_LEC_REG =         "is_lec_reg";
        String IS_PREFS_SET =       "is_prefs_set";
        String HASH_PASS =          "hash_pass";
        String IP_DNS =             "ip_dns";
        String IP_DNS_SECOND =      "ip_dns_second";
        String IP_SKZI =            "ip_skzi";
        String IP_MON =             "ip_mon";
        String VPN_APP_LIST =       "vpn_app_list";
        String VPN_ENABLE =         "vpn_enable";
        String VPN_CAPTURE_ALL =    "vpn_capture_all";
        String HASH_LOGIN_PASS =    "hash_login_pass";
    }
    SharedPreferences prefs = null;

    public interface JsonPrefs {
        String IP_DNS =     "ip_dns";
        String IP_SKZI =    "ip_skzi";
        String IP_MON =     "ip_mon";
    }

    private PrefsUtils() { }

    public static final synchronized PrefsUtils ins() {
        if (instance == null) {
            instance = new PrefsUtils();
        }
        return instance;
    }

    public boolean isAuth() {
        return isAuth;
    }

    public void setAuth(boolean auth) {
        isAuth = auth;
    }

    public byte[] getHashPass() {
        if (mHashPass == null)
            return null;
        return Utils.hexStringToByteArray(mHashPass);
    }

    public void setHashPass(byte[] hashPass) {
        mHashPass = Utils.byteArrayToHexString(hashPass);
        prefs.edit().putString(Prefs.HASH_PASS, mHashPass).apply();
    }
    public byte[] getHashLoginPass() {
        return Utils.hexStringToByteArray(mHashLoginPass);
    }
    public void setHashLoginPass(byte[] hashLoginPass){
        mHashLoginPass = Utils.byteArrayToHexString(hashLoginPass);
        prefs.edit().putString(Prefs.HASH_LOGIN_PASS, mHashLoginPass).apply();
    }

    public boolean isLicenseReg() {
        return isLicenseReg;
    }

    public void setLicenseReg(boolean licenseReg) {
        isLicenseReg = licenseReg;
        prefs.edit().putBoolean(Prefs.IS_LEC_REG, isLicenseReg).apply();
    }

    public String getIpDns() {
        return mIpDns;
    }

    public void setIpDns(String ipDns) {
        mIpDns = ipDns;
        prefs.edit().putString(Prefs.IP_DNS, mIpDns).apply();
    }

    public String getIpDnsSecond() {
        return mIpDnsSecond;
    }

    public void setIpDnsSecond(String ipDnsSecond) {
        mIpDnsSecond = ipDnsSecond;
        prefs.edit().putString(Prefs.IP_DNS_SECOND, mIpDnsSecond).apply();
    }

    public String getIpSkzi() {
        return mIpSkzi;
    }

    public void setIpSkzi(String ipSkzi) {
        mIpSkzi = ipSkzi;
        prefs.edit().putString(Prefs.IP_SKZI, mIpSkzi).apply();
    }

    public String getIpMon() {
        return mIpMon;
    }

    public void setIpMon(String ipMon) {
        mIpMon = ipMon;
        prefs.edit().putString(Prefs.IP_MON, mIpMon).apply();
    }

    public void setVpnApps(Set<String> appList) {
        app_vpn_list.clear();
        app_vpn_list = appList;
        prefs.edit()
                .putStringSet(Prefs.VPN_APP_LIST, app_vpn_list)
                .apply();
    }

    public Set<String> getVpnApps() {
        return app_vpn_list;
    }

    public boolean isPrefsSet() {
        return isPrefsSet;
    }

    public void setPrefsSet(boolean prefsSet) {
        isPrefsSet = prefsSet;
        prefs.edit().putBoolean(Prefs.IS_PREFS_SET, isPrefsSet).apply();
    }

    public void setAppBackground(boolean value) {
        isAppBackground = value;
    }

    public boolean isAppBackground() {
        return isAppBackground;
    }

    public void setEnableVpn(boolean enable) {
        isVpnEnable = enable;
        prefs.edit().putBoolean(Prefs.VPN_ENABLE, isVpnEnable).apply();
    }

    public boolean isVpnEnable() {
        return isVpnEnable;
    }

    public boolean isCaptureAll() {
        return isCaptureAll;
    }

    public void setCaptureAll(boolean captureAll) {
        isCaptureAll = captureAll;
        prefs.edit().putBoolean(Prefs.VPN_CAPTURE_ALL, isCaptureAll).apply();
    }

    public boolean isNetworkAvailable() {
        return isNetworkAvailable;
    }

    public void setNetworkAvailable(boolean networkAvailable) {
        isNetworkAvailable = networkAvailable;
    }

    public void load(Context context) {
        prefs = context.getApplicationContext().getSharedPreferences(Prefs.NAME, Context.MODE_PRIVATE);
        //mServerAddress = prefs.getString(Prefs.SERVER_ADDRESS, "31.173.180.106:8080");
        isLicenseReg = prefs.getBoolean(Prefs.IS_LEC_REG, false);
        isPrefsSet = prefs.getBoolean(Prefs.IS_PREFS_SET, false);

        mHashPass           = prefs.getString(Prefs.HASH_PASS, null);
        mHashLoginPass      = prefs.getString(Prefs.HASH_LOGIN_PASS, null);
        isAppBackground     = false;
        mIpDns               = prefs.getString(Prefs.IP_DNS, "");
        mIpDnsSecond        = prefs.getString(Prefs.IP_DNS_SECOND, "");
        mIpSkzi             = prefs.getString(Prefs.IP_SKZI, "");
        mIpMon              = prefs.getString(Prefs.IP_MON, "");
        isVpnEnable         = prefs.getBoolean(Prefs.VPN_ENABLE, true);
        isCaptureAll        = prefs.getBoolean(Prefs.VPN_CAPTURE_ALL, true);
        app_vpn_list        = prefs.getStringSet(Prefs.VPN_APP_LIST, null);
        isNetworkAvailable = false;
        if (app_vpn_list != null)
            app_vpn_list    = new HashSet<>(app_vpn_list);
        else
            app_vpn_list    = new HashSet <>();
    }

    public void reset() {
        if(prefs != null) {
            prefs.edit().clear().commit();
        }
    }
}