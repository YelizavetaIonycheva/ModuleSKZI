package org.pniei.moduleskzi.fragments;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import com.google.android.material.textfield.TextInputLayout;
import org.json.JSONException;
import org.json.JSONObject;
import org.pniei.portal.R;
import org.pniei.moduleskzi.activities.LoginActivity;
import org.pniei.portal.databinding.FragmentEnterConfigBinding;
import org.pniei.moduleskzi.utils.CryptUtils;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.moduleskzi.utils.Utils;
import org.pniei.portal.vpn.VpnClient;
import java.io.File;
import java.io.FileOutputStream;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.documentfile.provider.DocumentFile;
import androidx.fragment.app.Fragment;

public class EnterConfigFragment extends Fragment implements View.OnClickListener {
    private ActivityResultLauncher<Intent> selectConfigResultLauncher;
    private static Context mContext;
    private Handler mHandler;
    private FragmentEnterConfigBinding mBinding;
    private DocumentFile selectedKeyFile = null;
    private DocumentFile selectedConfFile = null;
    private boolean checkFileConfig = false;

    public static EnterConfigFragment newInstance(Context context) {
        mContext = context;
        return new EnterConfigFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mBinding = FragmentEnterConfigBinding.inflate(inflater);//DataBindingUtil.inflate(inflater, R.layout.enter_config_fragment, container, false);
        mHandler = new Handler(Looper.getMainLooper());

        mBinding.confFile.setOnClickListener(this);
        mBinding.btnEnter.setOnClickListener(this);
        registerForSelectFileResult();
        return mBinding.getRoot();
    }

    @Override
    public void onClick(View view) {
        long id = view.getId();

        if (id == R.id.confFile) {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            selectConfigResultLauncher.launch(intent);
        } else if (id == R.id.btnEnter) {
            mBinding.progressPar.setVisibility(View.VISIBLE);
            checkConfig();

        }
    }

    private void checkConfig() {
        new Thread(() -> {
            if (selectedConfFile == null) {
                showError(getString(R.string.err_file_not_select), mBinding.confFileLayout);
                return;
            }

            byte [] bufConfig = Utils.readFileFromZip(mContext, selectedConfFile, ".cfg");
            if (bufConfig == null) {
                showError(getString(R.string.err_file_cfg_not_found), mBinding.confFileLayout);
                return;
            }

            if (!checkConfigFile(new String(bufConfig))) {
                showError(getString(R.string.init_config_error), mBinding.confFileLayout);
                return;
            }

            byte [] keyM = Utils.readFileFromZip(mContext, selectedConfFile, ".key");

            if (keyM == null) {
                showError(getString(R.string.err_file_key_not_found), mBinding.confFileLayout);
                return;
            }

            if (!saveVpnKey(keyM)) {
                showError(getString(R.string.err_key_save), mBinding.confFileLayout);
                return;
            }
            PrefsUtils.ins().setPrefsSet(true);

            ((LoginActivity)getActivity()).loginOk();
        }).start();

    }


    private void showError(final String error, View view) {
        mHandler.post(() -> {
            mBinding.progressPar.setVisibility(View.INVISIBLE);
            if (view instanceof TextInputLayout) {
                ((TextInputLayout)view).setError(error);
            }
        });
    }

    private boolean checkConfigFile(String strConfig) {
        if (strConfig != null) {
            try {
                JSONObject jsonObject = new JSONObject(strConfig);
                String ipSkzi = jsonObject.getString(PrefsUtils.JsonPrefs.IP_SKZI);
                String ipMon = jsonObject.getString(PrefsUtils.JsonPrefs.IP_MON);
                String ipDns = jsonObject.getString(PrefsUtils.JsonPrefs.IP_DNS);
                String KS = jsonObject.getString("ks");


                StringBuilder sb = new StringBuilder();
                sb.append(ipSkzi)
                        .append(ipMon)
                        .append(ipDns);
                byte [] configs = sb.toString().getBytes();
                int crc = CryptUtils.CRC32(configs, configs.length);
                if(!(KS.equalsIgnoreCase(Utils.intToHexString(crc)))) {
                    return false;
                }

                PrefsUtils.ins().setIpSkzi(ipSkzi);
                PrefsUtils.ins().setIpMon(ipMon);
                PrefsUtils.ins().setIpDns(ipDns);

                return true;
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    private boolean saveVpnKey(byte [] keyData) {
        byte [] cryptKeyData;

        cryptKeyData = CryptUtils.cryptData(keyData, PrefsUtils.ins().getHashPass());
        if(cryptKeyData == null)
            return true;

        try {
            File fileKey = VpnClient.getFileKey(mContext);
            FileOutputStream fout = new FileOutputStream(fileKey);
            fout.write(cryptKeyData);
            fout.flush();
            fout.close();
            return VpnClient.ins().loadAndRefreshKeys(mContext);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void registerForSelectFileResult() {
        selectConfigResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        if (resultData != null) {
                            Uri fileUri = resultData.getData();
                            selectedConfFile = DocumentFile.fromSingleUri(mContext, fileUri);
                            if (selectedConfFile != null) {
                                mBinding.confFile.setText(selectedConfFile.getName());
                                mBinding.confFileLayout.setError(null);
                            }
                        }
                    }
                });
    }
}
