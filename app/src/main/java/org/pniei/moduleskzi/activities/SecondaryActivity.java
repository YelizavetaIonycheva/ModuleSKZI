package org.pniei.moduleskzi.activities;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import org.pniei.portal.R;
import org.pniei.moduleskzi.fragments.AboutFragment;
import org.pniei.moduleskzi.fragments.SettingsFragment;
import org.pniei.moduleskzi.listener.OnBackClickListener;
import org.pniei.moduleskzi.utils.PrefsUtils;

public class SecondaryActivity extends AppCompatActivity {
    // Ключи принимаемых параметров
    public static final String TYPE_FRAGMENT_KEY = "t_f_key";
    public static final String CHAT_ROOM_ID_KEY = "c_r_id_key";
    public static final String CONTACT_ID_KEY = "c_id_key";
    public static final String CONTACT_IS_NEW_KEY = "c_is_n_key";
    public static final String CONTACT_IS_PNONE_KEY = "c_is_p_key";
    public static final String HISTORY_NUMBER = "number";
    public static final String HISTORY_STATUS = "status";
    public static final String HISTORY_TIME = "time";

    public static final int SETTINGS_FRAGMENT = 0;
    public static final int ABOUT_FRAGMENT = 1;

    private Fragment currentFragment;
    private Intent mIntent;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        //Utils.initTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secondary);

        mIntent = getIntent();
        if (mIntent != null && mIntent.hasExtra(TYPE_FRAGMENT_KEY)) {
            switch (mIntent.getIntExtra(TYPE_FRAGMENT_KEY, 0)) {

                case SETTINGS_FRAGMENT : {
                    currentFragment = SettingsFragment.newInstance(this);
                    break;
                }

                case ABOUT_FRAGMENT : {
                    currentFragment = AboutFragment.newInstance(this);
                    break;
                }
            }
            displayFragment(currentFragment, false);
        } else {
            throw new RuntimeException("Activity intent not have Extra");
        }
    }

    public void displayFragment(Fragment fragment, boolean toBackStack) {
        FragmentManager fm = getSupportFragmentManager();
        FragmentTransaction transaction = fm.beginTransaction();


        if (toBackStack)
            transaction.addToBackStack(null);


        transaction.replace(R.id.fragmentContainer, fragment);
        transaction.commitAllowingStateLoss();
    }

    @Override
    public void onBackPressed() {
        if (currentFragment instanceof OnBackClickListener) {
            if (((OnBackClickListener)currentFragment).allowBackPressed()) {
                super.onBackPressed();
            }
        } else {
            super.onBackPressed();
        }
    }


    @Override
    protected void onPause() {
        PrefsUtils.ins().setAppBackground(true);
        super.onPause();
    }

    @Override
    protected void onResume() {
        PrefsUtils.ins().setAppBackground(false);
        super.onResume();
    }

}
