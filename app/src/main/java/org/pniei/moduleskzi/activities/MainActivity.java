package org.pniei.moduleskzi.activities;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkRequest;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;
import org.jetbrains.annotations.NotNull;
import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.databinding.ActivityMainBinding;
import org.pniei.moduleskzi.liveData.ManagerLiveData;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.portal.services.MonitoringService;
import org.pniei.portal.vpn.VpnClient;
import static org.pniei.moduleskzi.liveData.ManagerLiveData.VpnQuality.*;

public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding mBinding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mBinding = ActivityMainBinding.inflate(getLayoutInflater());
        View view = mBinding.getRoot();
        setContentView(view);

        if (VpnClient.ins().isWork()) {
            mBinding.btnStartVpn.setText(getText(R.string.vpn_stop));
        } else {
            mBinding.btnStartVpn.setText(getText(R.string.vpn_start));
        }

        mBinding.btnStartVpn.setOnClickListener(v -> {
            if (VpnClient.ins().isWork()) {
                mBinding.btnStartVpn.setText(getText(R.string.vpn_start));
                VpnClient.stopVpnService(this);
                MonitoringService.stopMonitoringService(this);
                PrefsUtils.ins().setEnableVpn(false);
            } else {
                if (PrefsUtils.ins().isNetworkAvailable()) {
                    if (!VpnClient.startVpnService(this)) {
                        // Toast с сообщением о некорректных IP адресах
                        Toast.makeText(this, R.string.bad_ip_skzi_address, Toast.LENGTH_SHORT).show();
                    } else {
                        mBinding.btnStartVpn.setText(getText(R.string.vpn_stop));
                        MonitoringService.startMonitoringService(this);
                        PrefsUtils.ins().setEnableVpn(true);
                    }
                } else {
                    Toast.makeText(this, R.string.vpn_wifi_mobdata_not_active, Toast.LENGTH_SHORT).show();
                }
            }
        });

        ManagerLiveData.ins().getVpnInfo().observe(this, vpnInfo -> updateVpnInfo(vpnInfo));
        initMenu();

        registerNetworkCallback();
    }

    @Override
    protected void onPause() {
        PrefsUtils.ins().setAppBackground(true);
        ManagerLiveData.ins().getVpnQuality().removeObservers(this);
        ManagerLiveData.ins().getVpnInfo().removeObservers(this);
        super.onPause();
    }

    @Override
    protected void onResume() {
        PrefsUtils.ins().setAppBackground(false);
        ManagerLiveData.ins().getVpnQuality().observe(this, integer -> updateVpnQualityIcon(integer));
        ManagerLiveData.ins().getVpnInfo().observe(this, vpnInfo -> updateVpnInfo(vpnInfo));
        super.onResume();
    }

    private void updateVpnInfo(@NotNull ManagerLiveData.VpnInfo vpnInfo) {
        mBinding.textVpnStatus.setText(vpnInfo.getIdStrStatus());
        mBinding.textVpnInSpeed.setText(String.format("%.0f", vpnInfo.getSpeedIN()));
        mBinding.textVpnOutSpeed.setText(String.format("%.0f", vpnInfo.getSpeedOUT()));
    }

    private void updateVpnQualityIcon(int quality) {
        switch (quality) {
            case VPN_DISABLE 	:
               /* mBinding.vpnQuality.setVisibility(View.INVISIBLE);
                break;*/
            case VPN_ENABLE 	:
                mBinding.vpnQuality.setVisibility(View.VISIBLE);
                mBinding.vpnQuality.setImageResource(R.drawable.ic_vpn_quality_off);
                break;
            case QUALITY_HIGH 	:
                mBinding.vpnQuality.setVisibility(View.VISIBLE);
                mBinding.vpnQuality.setImageResource(R.drawable.ic_vpn_quality_high);
                break;
            case QUALITY_MIDL 	:
                mBinding.vpnQuality.setVisibility(View.VISIBLE);
                mBinding.vpnQuality.setImageResource(R.drawable.ic_vpn_quality_midle);
                break;
            case QUALITY_LOW 	:
                mBinding.vpnQuality.setVisibility(View.VISIBLE);
                mBinding.vpnQuality.setImageResource(R.drawable.ic_vpn_quality_low);
                break;
        }
    }

    private void initMenu() {
        mBinding.topBar.setOnMenuItemClickListener(item -> {
            int id = item.getItemId();

            if (id == R.id.menu_settings) {
                Intent intent = new Intent(this, SecondaryActivity.class);
                intent.putExtra(SecondaryActivity.TYPE_FRAGMENT_KEY, SecondaryActivity.SETTINGS_FRAGMENT);
                startActivity(intent);
            } else if (id == R.id.menu_about) {
                Intent intent = new Intent(this, SecondaryActivity.class);
                intent.putExtra(SecondaryActivity.TYPE_FRAGMENT_KEY, SecondaryActivity.ABOUT_FRAGMENT);
                startActivity(intent);
            }
            return true;
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VpnClient.REQUST_VPN && resultCode == RESULT_OK) {
            if (!VpnClient.startVpnService(this)) {
                // Toast с сообщением о некорректных IP адресах
                Toast.makeText(this, R.string.bad_ip_skzi_address, Toast.LENGTH_SHORT).show();
            } else {
                mBinding.btnStartVpn.setText(getText(R.string.vpn_stop));
                MonitoringService.startMonitoringService(this);
                PrefsUtils.ins().setEnableVpn(true);
            }
        }
    }

    // Network Check
    public void registerNetworkCallback() {
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkRequest.Builder builder = new NetworkRequest.Builder();

            connectivityManager.registerNetworkCallback(builder.build(), new ConnectivityManager.NetworkCallback(){
                       @Override
                       public void onAvailable(Network network) {
                           PrefsUtils.ins().setNetworkAvailable(true);
                           if (PrefsUtils.ins().isVpnEnable()) {
                               if (!VpnClient.ins().isWork()) {
                                   if (!VpnClient.startVpnService(MainActivity.this)) {
                                       // Toast с сообщением о некорректных IP адресах
                                       Toast.makeText(MainActivity.this, R.string.bad_ip_skzi_address, Toast.LENGTH_SHORT).show();
                                   } else {
                                       mBinding.btnStartVpn.setText(getText(R.string.vpn_stop));
                                       MonitoringService.startMonitoringService(MainActivity.this);
                                   }
                               }
                           }
                       }
                       @Override
                       public void onLost(Network network) {
                           PrefsUtils.ins().setNetworkAvailable(false);
                           if (VpnClient.ins().isWork()) {
                               VpnClient.stopVpnService(MainActivity.this);
                               mBinding.btnStartVpn.setText(getText(R.string.vpn_start));
                           }
                       }
                }
            );
        }catch (Exception e){
        }
    }
}