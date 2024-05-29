package org.pniei.portal.fragments;

import android.content.Context;
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

import androidx.databinding.DataBindingUtil;
import androidx.fragment.app.Fragment;

import com.google.android.material.textfield.TextInputLayout;

import org.pniei.portal.R;
import org.pniei.portal.databinding.ChangePassFragmentBinding;
import org.pniei.moduleskzi.utils.CryptUtils;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.moduleskzi.utils.Utils;

public class ChangePassFragment extends Fragment {
    private static Context mContext;
    private ChangePassFragmentBinding mBinding;
    private Handler mHandler;

    public static ChangePassFragment newInstance(Context context) {
        mContext = context;
        return new ChangePassFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mHandler = new Handler(Looper.getMainLooper());
        mBinding = DataBindingUtil.inflate(inflater, R.layout.change_pass_fragment, container, false);
        mBinding.btnEnter.setOnClickListener(v -> {
            String enterPass = mBinding.oldPassword.getText().toString();
            String hashEnterPass = Utils.byteArrayToHexString(CryptUtils.getHash(enterPass.getBytes()));
            checkPass(hashEnterPass);
        });

        mBinding.repeatPassword.setOnKeyListener((v, i, keyEvent) -> {
            if (keyEvent.getAction() == KeyEvent.ACTION_DOWN) {
                switch (i) {
                    case KeyEvent.KEYCODE_DPAD_CENTER:
                    case KeyEvent.KEYCODE_ENTER: {
                        String enterPass = mBinding.oldPassword.getText().toString();
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
        mBinding.oldPassword.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void afterTextChanged(Editable editable) {
                mBinding.oldPasswordLayout.setError(null);
            }
        });

        mBinding.password.setOnKeyListener((v, i, keyEvent) -> {
            if (keyEvent.getAction() == KeyEvent.ACTION_DOWN) {
                switch (i) {
                    case KeyEvent.KEYCODE_DPAD_CENTER:
                    case KeyEvent.KEYCODE_ENTER: {
                        String enterPass = mBinding.oldPassword.getText().toString();
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

        mBinding.repeatPassword.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) {
            }

            @Override
            public void afterTextChanged(Editable editable) {
                mBinding.repeatPasswordLayout.setError(null);
            }
        });



        return mBinding.getRoot();
    }

    @Override
    public void onResume() {
        super.onResume();
        mBinding.password.setText("");
        PrefsUtils.ins().setAuth(false);
    }

    private void checkPass(String passHash) {
        mBinding.oldPassword.setEnabled(false);
        mBinding.oldPasswordLayout.setError(null);
        mBinding.password.setEnabled(false);
        mBinding.repeatPassword.setEnabled(false);
        mBinding.btnEnter.setEnabled(false);
        mBinding.passwordLayout.setError(null);
        mBinding.repeatPasswordLayout.setError(null);

        String pas1 = mBinding.password.getText().toString();
        String pas2 = mBinding.repeatPassword.getText().toString();

            if (!(passHash.equals(Utils.byteArrayToHexString(PrefsUtils.ins().getHashLoginPass())))) {
                showError(getString(R.string.pass_error), mBinding.oldPasswordLayout);
            } else if (pas1.length() == 0) {
                showError(getString(R.string.err_empty_password), mBinding.passwordLayout);
                return;
            } else if (pas1.length() < 4) {
                showError(getString(R.string.err_lenght_password), mBinding.passwordLayout);
                return;
            } else if (pas1.length() != pas2.length() || !pas1.equals(pas2)) {
                showError(getString(R.string.err_not_match_password), mBinding.repeatPasswordLayout);
                return;
            } else {
                PrefsUtils.ins().setHashLoginPass(CryptUtils.getHash(pas1.getBytes()));
                Toast.makeText(mContext, "Пароль изменен", Toast.LENGTH_SHORT).show();}
    }

    private void showError(final String error, View view) {
        mHandler.post(() -> {
            if (view instanceof TextInputLayout) {
                ((TextInputLayout) view).setError(error);
            }
            mBinding.oldPassword.setEnabled(true);
            mBinding.password.setEnabled(true);
            mBinding.repeatPassword.setEnabled(true);
            mBinding.btnEnter.setEnabled(true);
        });
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }

}
