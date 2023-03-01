package org.pniei.moduleskzi.fragments;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import org.pniei.moduleskzi.R;
import org.pniei.moduleskzi.utils.Logger;

public class LoggerFragment extends Fragment {
    private TextView logTextView;
    private Button button_back, button_clear;
    private ProgressBar progressBar;
    private ScrollView scrollView;
    private Handler mHandler;

    public static LoggerFragment newInstance() {
        return new LoggerFragment();
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mHandler = new Handler(Looper.getMainLooper());
        new Thread(() -> {
            String message = Logger.inc().getLogString();
            mHandler.post(() -> {
                showLog(message);
            });
        }).start();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_logger, container, false);
    }

    public void onViewCreated(@NonNull View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        logTextView = view.findViewById(R.id.logTextView);
        button_back = view.findViewById(R.id.button_back);
        button_clear = view.findViewById(R.id.button_clear);
        progressBar = view.findViewById(R.id.progressBar);
        scrollView = view.findViewById(R.id.scrollView);

        button_back.setOnClickListener(v -> backOrClose());

        button_clear.setOnClickListener(v -> {
            logTextView.setText("");
            Logger.inc().clear();
        });
    }

    private void backOrClose() {
        if(getActivity().getSupportFragmentManager().getBackStackEntryCount() > 0)
            getActivity().getSupportFragmentManager().popBackStack();
        else
            getActivity().finish();
    }

    private void showLog(String logString) {
        logTextView.setText(logString);
        scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        progressBar.setVisibility(View.GONE);
    }
}

