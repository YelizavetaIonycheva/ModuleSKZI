package org.pniei.moduleskzi.qrcode;

import android.content.Intent;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.pniei.portal.R;

public class QRCodeScanActivity extends AppCompatActivity {
    public static final String TAG = "QRCodeScaneActivity";
    public static final String DATA = "QRCodeData";
    public static final String RESULT = "Result";
    public static final int OK = 0;
    public static final int ERROR = 1;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_qrcodescane);

        getSupportFragmentManager().beginTransaction()
                .replace(R.id.conteiner_camera, QRCodeScanFragment.newInstance())
                .commit();
    }

    public void returnData(String data) {
        Intent intent = new Intent();
        intent.putExtra(DATA, data);
        intent.putExtra(RESULT, OK);
        setResult(RESULT_OK, intent);
        finish();
    }
}
