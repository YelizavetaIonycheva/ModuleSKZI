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
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputLayout;
import java.util.ArrayList;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.databinding.DataBindingUtil;
import androidx.fragment.app.Fragment;
import org.pniei.dwface.biometry.BiometryActivity;
import org.pniei.dwface.biometry.BiometryPrefs;
import org.pniei.dwface.biometry.BiometryUtils;
import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.activities.LoginActivity;
import org.pniei.moduleskzi.databinding.FragmentRegistrationBinding;
import org.pniei.moduleskzi.utils.CryptUtils;
import org.pniei.moduleskzi.utils.PrefsUtils;

public class RegistrationFragment extends Fragment {
    private ActivityResultLauncher<Intent> biometryResultLauncher;
    private static Context mContext;
    private FragmentRegistrationBinding mBinding;
    private Handler mHandler;
    private String mPassTemp;

    public static RegistrationFragment newInstance(Context context) {
        mContext = context;
        return new RegistrationFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mHandler = new Handler(Looper.getMainLooper());
        mBinding = FragmentRegistrationBinding.inflate(inflater);//DataBindingUtil.inflate(inflater, R.layout.registration_fragment, container, false);

        mBinding.repeatPassword.setOnKeyListener((v, i, keyEvent) -> {
            if (keyEvent.getAction() == KeyEvent.ACTION_DOWN) {
                switch (i) {
                    case KeyEvent.KEYCODE_DPAD_CENTER:
                    case KeyEvent.KEYCODE_ENTER: {
                        checkPass();
                        return true;
                    }
                    default:
                        break;
                }
            }
            return false;
        });

        mBinding.password.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) { }
            @Override public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) { }
            @Override
            public void afterTextChanged(Editable editable) { mBinding.passwordLayout.setError(null);}
        });

        mBinding.repeatPassword.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) { }
            @Override public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) { }
            @Override
            public void afterTextChanged(Editable editable) { mBinding.repeatPasswordLayout.setError(null);}
        });

        mBinding.btnEnter.setOnClickListener(v -> checkPass());

        registerForBiometryResult();
        return mBinding.getRoot();
    }

    @Override
    public void onResume() {
        super.onResume();
        mBinding.password.setText("");
    }

    private void checkPass() {
        mBinding.password.setEnabled(false);
        mBinding.repeatPassword.setEnabled(false);
        mBinding.btnEnter.setEnabled(false);
        mBinding.passwordLayout.setError(null);
        mBinding.repeatPasswordLayout.setError(null);

        String pas1 = mBinding.password.getText().toString();
        String pas2 = mBinding.repeatPassword.getText().toString();

        if (pas1.length() == 0) {
            showError(getString(R.string.err_empty_password), mBinding.passwordLayout);
            return;
        } else if (pas1.length() < 4) {
            showError(getString(R.string.err_lenght_password), mBinding.passwordLayout);
            return;
        } else if (pas1.length() != pas2.length() || !pas1.equals(pas2)) {
            showError(getString(R.string.err_not_match_password), mBinding.repeatPasswordLayout);
            return;
        }

        if (BiometryPrefs.ins().isInitBiometryLib()) {
            mPassTemp = pas1;
            showBiometryDialog();
        } else {
            PrefsUtils.ins().setHashPass(CryptUtils.getHash(pas1.getBytes()));
            ((LoginActivity) requireActivity()).displayFragment(EnterConfigFragment.newInstance(mContext), false);
        }
    }

    private void showBiometryDialog() {
        new MaterialAlertDialogBuilder(mContext)
                .setTitle(R.string.biometry_settings)
                .setMessage(R.string.biometry_train_info)
                .setNegativeButton(getString(R.string.no), (dialog, which) -> {
                    PrefsUtils.ins().setHashPass(CryptUtils.getHash(mPassTemp.getBytes()));
                    ((LoginActivity) requireActivity()).displayFragment(EnterConfigFragment.newInstance(mContext), false);
                })
                .setPositiveButton(getString(R.string.yes), (dialog, which) -> {
                    byte [] hashPass = CryptUtils.getHash(mPassTemp.getBytes());
                    ArrayList<byte[]> dataArray = new ArrayList<>();
                    dataArray.add(hashPass);
                    byte [] data = BiometryUtils.dataGeneration(dataArray);
                    BiometryPrefs.ins().setKeyDecryptImage(hashPass);
                    BiometryPrefs.ins().setKeyEncryptImage(hashPass);
                    Intent newIntent = new Intent(mContext, BiometryActivity.class);
                    newIntent.putExtra(BiometryActivity.REGIME, BiometryActivity.REGIME_COLLECT_ALL);
                    newIntent.putExtra(BiometryActivity.DATA, data);
                    biometryResultLauncher.launch(newIntent);
                })
                .show();
    }

    private void showError(final String error, View view) {
        mHandler.post(() ->  {
            if (view instanceof TextInputLayout) {
                ((TextInputLayout)view).setError(error);
            }
            mBinding.password.setEnabled(true);
            mBinding.repeatPassword.setEnabled(true);
            mBinding.btnEnter.setEnabled(true);
        });
    }

    public void registerForBiometryResult() {
        biometryResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        if (resultData != null) {
                            int res = resultData.getIntExtra(BiometryActivity.RESULT, BiometryActivity.ERROR);

                            if (res == BiometryActivity.REG_OK) {
                                byte [] nbcc = resultData.getByteArrayExtra(BiometryActivity.NBCC);
                                if (nbcc != null) {
                                    PrefsUtils.ins().setHashPass(CryptUtils.getHash(mPassTemp.getBytes()));
                                    BiometryUtils.saveNBCC(mContext, nbcc);
                                    BiometryPrefs.ins().setBiometryBind(true);
                                    ((LoginActivity) requireActivity()).displayFragment(EnterConfigFragment.newInstance(mContext), false);
                                } else {
                                    Toast.makeText(mContext, org.pniei.dwface.R.string.error_biometry_data, Toast.LENGTH_SHORT).show();
                                }
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
