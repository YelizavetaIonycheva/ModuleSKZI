package org.pniei.moduleskzi.fragments;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import com.google.android.material.textfield.TextInputLayout;

import org.pniei.dwface.biometry.BiometryActivity;
import org.pniei.dwface.biometry.BiometryPrefs;
import org.pniei.dwface.biometry.BiometryUtils;
import org.pniei.portal.R;
import org.pniei.moduleskzi.activities.LoginActivity;
import org.pniei.portal.databinding.FragmentAuthenticationBinding;
import org.pniei.moduleskzi.utils.CryptUtils;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.moduleskzi.utils.Utils;
import org.pniei.portal.vpn.VpnClient;

import java.util.ArrayList;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.fragment.app.Fragment;

public class AuthenticationFragment extends Fragment {
    private static Context mContext;
    private FragmentAuthenticationBinding mBinding;
    private ActivityResultLauncher<Intent> biometryAuthResultLauncher;
    private Handler mHandler;

    public static AuthenticationFragment newInstance(Context context) {
        mContext = context;
        return new AuthenticationFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mBinding = FragmentAuthenticationBinding.inflate(inflater);//DataBindingUtil.inflate(inflater, R.layout.authentication_fragment, container, false);
        mHandler = new Handler(Looper.getMainLooper());
        mBinding.btnEnter.setOnClickListener(v -> {
            String enterPass = mBinding.password.getText().toString();
            String hashEnterPass = Utils.byteArrayToHexString(CryptUtils.getHash(enterPass.getBytes()));
            checkPass(hashEnterPass);
        });

        mBinding.password.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void afterTextChanged(Editable editable) {
                mBinding.passwordLayout.setError(null);
            }
        });

        mBinding.password.setOnKeyListener((v, i, keyEvent) -> {
            if (keyEvent.getAction() == KeyEvent.ACTION_DOWN) {
                switch (i) {
                    case KeyEvent.KEYCODE_DPAD_CENTER:
                    case KeyEvent.KEYCODE_ENTER: {
                        String enterPass = mBinding.password.getText().toString();
                        String hashEnterPass = Utils.byteArrayToHexString(CryptUtils.getHash(enterPass.getBytes()));
                        checkPass(hashEnterPass);
                        return true;
                    }
                    default:
                        break;
                }
            }
            return false;
        });

        if (BiometryPrefs.ins().isBiometryBind()) {
            regBiometryAuthResult();
            mBinding.btnBiometry.setVisibility(View.VISIBLE);

            mBinding.btnBiometry.setOnClickListener(v -> {
                mBinding.passwordLayout.setError(null);
                openCameraFragment();
            });
        }

        return mBinding.getRoot();
    }

    @Override
    public void onResume() {
        super.onResume();

        mBinding.password.setText("");
        PrefsUtils.ins().setAuth(false);
    }

    private void checkPass(String passHash) {
        mBinding.password.setEnabled(false);
        mBinding.btnEnter.setEnabled(false);
        mBinding.passwordLayout.setError(null);
        mBinding.progressPar.setVisibility(View.VISIBLE);

        new Thread(() -> {
            if (!(passHash.equals(Utils.byteArrayToHexString(PrefsUtils.ins().getHashLoginPass())))) {
                showError(getString(R.string.pass_error), mBinding.passwordLayout);
                return;
            }

            if (PrefsUtils.ins().isPrefsSet()) {
                if (!decryptKeyFile()) {
                    showError(getString(R.string.pass_error), mBinding.passwordLayout);
                } else {
                    ((LoginActivity) requireActivity()).loginOk();
                }
            } else {
                ((LoginActivity) requireActivity()).displayFragment(EnterConfigFragment.newInstance(mContext), false);
            }
        }).start();
    }

    private boolean decryptKeyFile() {
        return VpnClient.ins().loadAndRefreshKeys(mContext);
    }

    private void showError(final String error, View view) {
        mHandler.post(() -> {
            if (view instanceof TextInputLayout) {
                ((TextInputLayout) view).setError(error);
            }
            mBinding.password.setEnabled(true);
            mBinding.btnEnter.setEnabled(true);
            mBinding.progressPar.setVisibility(View.GONE);
        });
    }

    private void openCameraFragment() {
        new Thread(() -> {
            Intent newIntent = new Intent(mContext, BiometryActivity.class);
            newIntent.putExtra(BiometryActivity.REGIME, BiometryActivity.REGIME_AUT);
            biometryAuthResultLauncher.launch(newIntent);
        }).start();
    }

    public void regBiometryAuthResult() {
        biometryAuthResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        if (resultData != null) {
                            int res = resultData.getIntExtra(BiometryActivity.RESULT, BiometryActivity.ERROR);
                            if (res == BiometryActivity.AUT_OK) {
                                byte[] biometryData = resultData.getByteArrayExtra(BiometryActivity.DATA + "0");
                                ArrayList<byte[]> dataArray = BiometryUtils.dataHandling(biometryData);
                                mBinding.password.setEnabled(false);
                                mBinding.btnEnter.setEnabled(false);
                                mBinding.progressPar.setVisibility(View.VISIBLE);
                                checkPass(Utils.byteArrayToHexString(dataArray.get(0)));
                            } else if (res == BiometryActivity.TIME_OUT) {
                                Toast.makeText(mContext, org.pniei.dwface.R.string.error_biometry_timeout, Toast.LENGTH_SHORT).show();
                            } else {
                                Toast.makeText(mContext, org.pniei.dwface.R.string.error_biometry, Toast.LENGTH_SHORT).show();
                            }
                        }
                    }
                });
    }
}