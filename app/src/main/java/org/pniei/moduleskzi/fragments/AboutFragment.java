package org.pniei.moduleskzi.fragments;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import org.pniei.moduleskzi.R;

public class AboutFragment extends Fragment {
    private static Context mContext;

    public static AboutFragment newInstance(Context context) {
        mContext = context;
        return new AboutFragment();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_about, container, false);
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        try {
            String appVersion = "Версия: " + getContext().getPackageManager().getPackageInfo(getContext().getPackageName(), 0).versionName;
            ((TextView)view.findViewById(R.id.app_version)).setText(appVersion);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
    }
}
