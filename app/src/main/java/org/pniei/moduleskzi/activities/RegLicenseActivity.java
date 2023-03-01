package org.pniei.moduleskzi.activities;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.documentfile.provider.DocumentFile;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import org.json.JSONException;
import org.json.JSONObject;
import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.databinding.ActivityRegLicenseBinding;
import org.pniei.moduleskzi.qrcode.QRCodeScanActivity;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.moduleskzi.utils.Signature;
import org.pniei.moduleskzi.utils.Utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class RegLicenseActivity extends AppCompatActivity implements View.OnClickListener {
    private ActivityResultLauncher<Intent> selectFileResultLauncher;
    private ActivityResultLauncher<Intent> qrcodeActivityResultLauncher;
    private ActivityRegLicenseBinding mBinding;
    private String mDeviceId = null;
    private Handler mHandler;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mHandler = new Handler(Looper.getMainLooper());
        mBinding = ActivityRegLicenseBinding.inflate(getLayoutInflater());
        View view = mBinding.getRoot();
        setContentView(view);

        mDeviceId = android.provider.Settings.Secure.getString(getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        mBinding.deviceId.setText("id: " + mDeviceId);

        mBinding.btnCheck.setOnClickListener(this);
        mBinding.btnCodeFromFile.setOnClickListener(this);
        mBinding.btnCodeFromQRcode.setOnClickListener(this);

        mBinding.licenseNumber.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence charSequence, int i, int i1, int i2) { }
            @Override public void onTextChanged(CharSequence charSequence, int i, int i1, int i2) { }
            @Override
            public void afterTextChanged(Editable editable) { mBinding.licenseNumber.setError(null);}
        });

        registerForSelectFileResult();
        registerQRCodeScanResult();
    }

    @Override
    public void onClick(View view) {
        long id = view.getId();

        if (id == R.id.btnCheck) {
            checkLicenseCode(mBinding.licenseNumber.getText().toString());
        } else if (id == R.id.btnCodeFromFile) {
            new MaterialAlertDialogBuilder(RegLicenseActivity.this)
                    .setTitle(getString(R.string.import_code_from_file))
                    .setMessage(getString(R.string.import_code_from_file_info))
                    .setNegativeButton(getString(R.string.cancel), null)
                    .setPositiveButton(getString(R.string.enter), (dialog, which) -> {
                        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                        intent.setType("*/*");
                        selectFileResultLauncher.launch(intent);
                    })
                    .show();
        } else if (id == R.id.btnCodeFromQRcode) {
            new MaterialAlertDialogBuilder(RegLicenseActivity.this)
                    .setTitle(getString(R.string.import_code_qr_code))
                    .setMessage(getString(R.string.import_code_from_qr_code_info))
                    .setNegativeButton(getString(R.string.cancel), null)
                    .setPositiveButton(getString(R.string.enter), (dialog, which) -> {
                        Intent newIntent = new Intent(this, QRCodeScanActivity.class);
                        qrcodeActivityResultLauncher.launch(newIntent);
                    })
                    .show();
        }
    }

    private void checkLicenseCode(String licenseCode) {
        mBinding.licenseNumber.setEnabled(false);
        mBinding.btnCheck.setEnabled(false);
        mBinding.licenseNumberLayout.setError(null);
        mBinding.progressPar.setVisibility(View.VISIBLE);

        new Thread(() -> {
            if (licenseCode == null && licenseCode.length() == 0) {
                showError(getString(R.string.license_number_not_enter), mBinding.licenseNumberLayout);
                return;
            }

            byte[] checkSignKeyBuf = Signature.getkeycontrol(0);
            byte[] ecp = Utils.hexStringToByteArray(licenseCode);

            if (ecp.length != 28) {
                showError(getString(R.string.license_number_enter_error), mBinding.licenseNumberLayout);
                return;
            }

            if (Signature.ecpcontrol(checkSignKeyBuf, mDeviceId.getBytes(StandardCharsets.UTF_8)/*Utils.hexStringToByteArray(mDeviceId)*/, ecp) == 0) {
                PrefsUtils.ins().setLicenseReg(true);
                Intent newIntent = new Intent(RegLicenseActivity.this, LoginActivity.class);
                startActivity(newIntent);
                finish();
            } else {
                showError(getString(R.string.license_number_error), mBinding.licenseNumberLayout);
            }
        }).start();
    }

    private void showError(final String error, View view) {
        mHandler.post(() ->  {
            if (view instanceof TextInputLayout) {
                ((TextInputLayout)view).setError(error);
            }
            mBinding.licenseNumber.setEnabled(true);
            mBinding.btnCheck.setEnabled(true);
            mBinding.progressPar.setVisibility(View.GONE);
        });
    }

    public void registerForSelectFileResult() {
        selectFileResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        if (resultData != null) {
                            Uri fileUri = resultData.getData();
                            DocumentFile selectedFile = DocumentFile.fromSingleUri(RegLicenseActivity.this, fileUri);
                            if (selectedFile != null) {
                                try (InputStream is = getContentResolver().openInputStream(selectedFile.getUri())) {
                                    byte [] data = new byte[is.available()];
                                    is.read(data);

                                    if (checkCodeLicense(data)) {
                                        String codeLicense = new String(data);
                                        mBinding.licenseNumber.setText(codeLicense);
                                        mBinding.licenseNumberLayout.setError(null);
                                        return;
                                    }
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }

                                Toast.makeText(this, "Ошибка ввода", Toast.LENGTH_SHORT).show();
                            }
                        }
                    }
                });
    }

    @SuppressLint("CheckResult")
    public void registerQRCodeScanResult() {
        qrcodeActivityResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        if (resultData != null) {
                            int res = resultData.getIntExtra(QRCodeScanActivity.RESULT, QRCodeScanActivity.ERROR);

                            if (res == QRCodeScanActivity.OK) {
                                String qrData = resultData.getStringExtra(QRCodeScanActivity.DATA);
                                if (qrData != null && checkCodeLicense(qrData.getBytes(StandardCharsets.UTF_8))) {
                                    mBinding.licenseNumber.setText(qrData);
                                    mBinding.licenseNumberLayout.setError(null);
                                    return;
                                } else {
                                    Toast.makeText(this, "Ошибка ввода", Toast.LENGTH_SHORT).show();
                                }
                            }
                        }
                    }
                });
    }

    private boolean checkCodeLicense(byte data[]) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        boolean isFind = false;

        if (data.length != 56)
            return false;

        for (byte b : data) {
            for (char c : hexArray) {
                if (b == c) {
                    isFind = true;
                    break;
                }
            }
            if (!isFind)
                return false;
            isFind = false;
        }

        return true;
    }

}
