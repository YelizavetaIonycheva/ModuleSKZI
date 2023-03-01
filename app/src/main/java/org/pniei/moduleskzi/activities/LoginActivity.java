package org.pniei.moduleskzi.activities;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.fragments.AuthenticationFragment;
import org.pniei.moduleskzi.fragments.RegistrationFragment;
import org.pniei.moduleskzi.utils.PrefsUtils;

public class LoginActivity extends AppCompatActivity {
    private static final String TAG  = "LoginActivity";
    private Handler mHandler;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        //Utils.initTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        mHandler = new Handler(Looper.getMainLooper());

        if (PrefsUtils.ins().getHashPass() == null) {
            displayFragment(RegistrationFragment.newInstance(this), false);
        } else {
            displayFragment(AuthenticationFragment.newInstance(this), false);
        }
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

}
