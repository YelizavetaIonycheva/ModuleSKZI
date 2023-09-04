package org.pniei.moduleskzi.fragments;

import android.os.Bundle;

import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceScreen;
import org.pniei.portal.R;
import org.pniei.moduleskzi.utils.Utils;
import org.pniei.portal.vpn.VpnClient;
import java.util.ArrayList;

public class AdvancedSettingsSubScreenFragment extends PreferenceFragmentCompat {
    public static final String PAGE_ID = "page_id";
    private PreferenceScreen mPreferenceScreen;
    private Preference pref_key_w_num_komplect, pref_key_w_name_komplect, pref_key_w_num_serial, /*pref_key_w_num_of_keys,*/ pref_key_w_date_begin, pref_key_w_date_end;
    private Preference pref_key_n_num_komplect, pref_key_n_name_komplect, pref_key_n_num_serial, /*pref_key_n_num_of_keys,*/ pref_key_n_date_begin, pref_key_n_date_end;
    private String root_key;
    int index_next_key;

    public static AdvancedSettingsSubScreenFragment newInstance(String pageId) {
        AdvancedSettingsSubScreenFragment f = new AdvancedSettingsSubScreenFragment();
        Bundle args = new Bundle();
        args.putString(PAGE_ID, pageId);
        f.setArguments(args);
        return (f);
    }

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        addPreferencesFromResource(R.xml.preferences);
        PreferenceCategory pCat = findPreference(getString(R.string.pref_key_compl_key));
        root_key = rootKey;
        if(root_key.equals(getString(R.string.pref_key_working_compl_key))) {
            mPreferenceScreen = (PreferenceScreen)pCat.getPreference(0);
            pref_key_w_num_komplect = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_w_num_komplect_key));
            pref_key_w_name_komplect = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_w_name_komplect_key));
            pref_key_w_num_serial = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_w_num_serial_key));
            //pref_key_w_num_of_keys = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_w_num_of_keys_key));
            pref_key_w_date_begin = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_w_date_begin_key));
            pref_key_w_date_end = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_w_date_end_key));
        } else /*if(root_key.equals(getString(R.string.pref_key_next_compl_key)))*/ {
            index_next_key = Integer.valueOf(rootKey.substring(rootKey.lastIndexOf("_")+1));
            mPreferenceScreen = createPrefScreenNextKey();
            mPreferenceScreen.getPreference(0).setTitle(getString(R.string.key_next_settings_title) + " " + (index_next_key + 1));
            pref_key_n_num_komplect = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_n_num_komplect_key));
            pref_key_n_name_komplect = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_n_name_komplect_key));
            pref_key_n_num_serial = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_n_num_serial_key));
            //pref_key_n_num_of_keys = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_n_num_of_keys_key));
            pref_key_n_date_begin = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_n_date_begin_key));
            pref_key_n_date_end = (Preference)mPreferenceScreen.findPreference(getString(R.string.pref_key_n_date_end_key));
        }

        initSettings();
        if(mPreferenceScreen != null)
            getPreferenceManager().setPreferences(mPreferenceScreen);
    }

    private PreferenceScreen createPrefScreenNextKey() {
        PreferenceScreen preferenceScreen = getPreferenceManager().createPreferenceScreen(getContext());

        Preference pref_key_n_name_komplect = new Preference(getContext());
        pref_key_n_name_komplect.setKey(getString(R.string.pref_key_n_name_komplect_key));
        pref_key_n_name_komplect.setTitle(R.string.key_name_komplect_title);

        Preference pref_key_n_num_serial = new Preference(getContext());
        pref_key_n_num_serial.setKey(getString(R.string.pref_key_n_num_serial_key));
        pref_key_n_num_serial.setTitle(R.string.key_num_serial_title);

        Preference pref_key_n_num_komplect = new Preference(getContext());
        pref_key_n_num_komplect.setKey(getString(R.string.pref_key_n_num_komplect_key));
        pref_key_n_num_komplect.setTitle(R.string.key_num_komplect_title);

        /*Preference pref_key_n_num_of_keys = new Preference(getContext());
        pref_key_n_num_of_keys.setKey(getString(R.string.pref_key_n_num_of_keys_key));
        pref_key_n_num_of_keys.setTitle(R.string.key_num_of_keys_title);*/

        Preference pref_key_n_date_begin = new Preference(getContext());
        pref_key_n_date_begin.setKey(getString(R.string.pref_key_n_date_begin_key));
        pref_key_n_date_begin.setTitle(R.string.key_date_begin_title);

        Preference pref_key_n_date_end = new Preference(getContext());
        pref_key_n_date_end.setKey(getString(R.string.pref_key_n_date_end_key));
        pref_key_n_date_end.setTitle(R.string.key_date_end_title);

        PreferenceCategory preferenceCategory = new PreferenceCategory(getContext());
        preferenceScreen.addPreference(preferenceCategory);
        preferenceCategory.addPreference(pref_key_n_name_komplect);
        preferenceCategory.addPreference(pref_key_n_num_serial);
        preferenceCategory.addPreference(pref_key_n_num_komplect);
        //preferenceCategory.addPreference(pref_key_n_num_of_keys);
        preferenceCategory.addPreference(pref_key_n_date_begin);
        preferenceCategory.addPreference(pref_key_n_date_end);

        return preferenceScreen;
    }

    private void initSettings() {
        String nameBlock = "";
        if(root_key.equals(getString(R.string.pref_key_working_compl_key))) {
            VpnClient.KeyInf keyInf = VpnClient.ins().getWorkKey();
            if(keyInf != null) {
                try {
                    nameBlock = new String(keyInf.kd, "windows-1251");
                } catch (Exception e) { }
                pref_key_w_name_komplect.setSummary(nameBlock);
                pref_key_w_num_serial.setSummary(Utils.convertSerToStr(Utils.serArrayToInt(keyInf.ser)));
                pref_key_w_num_komplect.setSummary(Utils.convertComplToStr(keyInf.compl));
                // pref_key_w_num_of_keys.setSummary(keyInf.numCompl + "");
                pref_key_w_date_begin.setSummary(Utils.parsingDate(keyInf.dateBegin));
                pref_key_w_date_end.setSummary(Utils.parsingDate(keyInf.dateEnd));
            }
        }
        else /*if (root_key.equals(getString(R.string.pref_key_next_compl_key)))*/{
            ArrayList<VpnClient.KeyInf> keys = VpnClient.ins().getNextKeys();
            if(keys != null && keys.size() > 0) {
                VpnClient.KeyInf keyInf = VpnClient.ins().getNextKeys().get(index_next_key);
                if(keyInf != null) {
                    try {
                        nameBlock = new String(keyInf.kd, "windows-1251");
                    } catch (Exception e) { }
                    pref_key_n_name_komplect.setSummary(nameBlock);
                    pref_key_n_num_serial.setSummary(Utils.convertSerToStr(Utils.serArrayToInt(keyInf.ser)));
                    pref_key_n_num_komplect.setSummary(Utils.convertComplToStr(keyInf.compl));
                    //pref_key_n_num_of_keys.setSummary(keyInf.numCompl + "");
                    pref_key_n_date_begin.setSummary(Utils.parsingDate(keyInf.dateBegin));
                    pref_key_n_date_end.setSummary(Utils.parsingDate(keyInf.dateEnd));
                }
            }
        }
    }
}

