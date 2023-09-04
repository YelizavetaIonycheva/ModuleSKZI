package org.pniei.moduleskzi.activities;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import org.pniei.moduleskzi.fragments.AuthenticationFragment;
import org.pniei.moduleskzi.fragments.RegistrationFragment;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.portal.R;

public class LoginActivity extends AppCompatActivity {
    private static final String TAG  = "LoginActivity";
    private Handler mHandler;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        //Utils.initTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        mHandler = new Handler(Looper.getMainLooper());

        if (checkAndRequestNotifyPermission()) {
            fragmentShow();
        }

        /*if (PrefsUtils.ins().getHashPass() == null) {
            displayFragment(RegistrationFragment.newInstance(this), false);
        } else {
            displayFragment(AuthenticationFragment.newInstance(this), false);
        }*/
    }

    void fragmentShow() {
        boolean isRegistered = PrefsUtils.ins().getHashPass() != null /*& VpnClient.keyFileExists(this)*/;
        FragmentManager fm = getSupportFragmentManager();
        Fragment fragment = isRegistered ? AuthenticationFragment.newInstance(this) : RegistrationFragment.newInstance(this);
        fm.beginTransaction()
                .add(R.id.fragmentContainer, fragment)
                .commit();
    }

    public void displayFragment(Fragment fragment, boolean toBackStack) {
        FragmentManager fm = getSupportFragmentManager();
        FragmentTransaction transaction = fm.beginTransaction();

        if (toBackStack)
            transaction.addToBackStack(null);

        transaction.replace(R.id.fragmentContainer, fragment);
        transaction.commit();
    }

    public void loginOk() {
        PrefsUtils.ins().setAuth(true);
        mHandler.post(() -> {
            Intent newIntent = new Intent(LoginActivity.this, MainActivity.class);
            startActivity(newIntent);
            finish();
        });
    }
    private boolean checkAndRequestNotifyPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                permissionsResultCallback.launch(Manifest.permission.POST_NOTIFICATIONS);
                return false;
            } else
                return true;
        } else {
            return true;
        }
    }

    private final ActivityResultLauncher<String> permissionsResultCallback =
            registerForActivityResult(new ActivityResultContracts.RequestPermission(), isGranted -> {
                if (isGranted) {
                    fragmentShow();
                } else {
                    new MaterialAlertDialogBuilder(this)
                            .setTitle("Запрос разрешения")
                            .setMessage("Для работы приложения необходимо предоставить разрешение создавать уведомления")
                            .setNegativeButton("Отмена", (dialog, which) -> {})
                            .setPositiveButton("Предоставить", (dialog, which) -> {
                                checkAndRequestNotifyPermission();
                            })
                            .show();
                }
            });
}
