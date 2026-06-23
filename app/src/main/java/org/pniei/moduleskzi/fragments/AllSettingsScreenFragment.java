package org.pniei.moduleskzi.fragments;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.documentfile.provider.DocumentFile;
import androidx.preference.EditTextPreference;
import androidx.preference.MultiSelectListPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceScreen;
import androidx.preference.SwitchPreferenceCompat;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import org.pniei.dwface.biometry.BiometryActivity;
import org.pniei.dwface.biometry.BiometryPrefs;
import org.pniei.dwface.biometry.BiometryUtils;
import org.pniei.portal.R;
import org.pniei.moduleskzi.activities.SecondaryActivity;
import org.pniei.moduleskzi.liveData.ManagerLiveData;
import org.pniei.moduleskzi.utils.CryptUtils;
import org.pniei.moduleskzi.utils.FileUtils;
import org.pniei.moduleskzi.utils.PrefsUtils;
import org.pniei.moduleskzi.utils.Utils;
import org.pniei.portal.vpn.VpnClient;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.pniei.moduleskzi.fragments.ChangePassFragment;

public class AllSettingsScreenFragment extends PreferenceFragmentCompat {
    private PreferenceScreen mPreferenceScreen;
    private ActivityResultLauncher<Intent> biometryResultLauncher;
    private ActivityResultLauncher<Intent> selectDirResultLauncher;
    private ActivityResultLauncher<Intent> selectFileResultLauncher;

    private ActivityResultLauncher<String> requestPermissionWrite;
    private static Context mContext;
    private DocumentFile pickedDir = null;
    private DocumentFile pickedFile = null;
    private TextView selectedDir = null;
    private Handler mHandler;
    /*private AlertDialog waitDialog;*/
    private String mRootKey;

    public static AllSettingsScreenFragment newInstance(Context context) {
        mContext = context;
        return new AllSettingsScreenFragment();
    }

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        addPreferencesFromResource(R.xml.preferences);
        mPreferenceScreen = findPreference(rootKey);
        mHandler = new Handler(Looper.getMainLooper());
        mRootKey = rootKey;
        if(rootKey.equals(getString(R.string.pref_ip_address_key))) {
            initIpAddressSettings();
            setIpAddressPreferencesListener();
        } else if(rootKey.equals(getString(R.string.pref_vpn_info_key))) {
            initKeyInfo();
        } else if(rootKey.equals(getString(R.string.pref_biometry_settings_key))) {
            registerForBiometryResult();
            registerForSelectDirResult();
            registerForSelectFileResult();
            initBiometrySettings();
            registerForRequestPermission();
        } else if(rootKey.equals(getString(R.string.pref_advanced_key))) {
            registerForSelectDirResult();
            registerForSelectFileResult();
            initAdvancedSettings();
            setAdvancedPreferencesListener();
        }

        if(mPreferenceScreen != null)
            getPreferenceManager().setPreferences(mPreferenceScreen);
    }

    @Override
    public void onNavigateToScreen(PreferenceScreen preferenceScreen){
        AdvancedSettingsSubScreenFragment fragment = new AdvancedSettingsSubScreenFragment();
        Bundle args = new Bundle();
        args.putString(PreferenceFragmentCompat.ARG_PREFERENCE_ROOT, preferenceScreen.getKey());
        fragment.setArguments(args);
        getParentFragmentManager()
                .beginTransaction()
                .replace(getId(), fragment)
                .addToBackStack(null)
                .commit();
    }

    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        if (mRootKey.equals(getString(R.string.pref_vpn_info_key))) {
            ManagerLiveData.ins().getSkziTimeError().observe(getViewLifecycleOwner(), s -> {
                if (!s.equals("")) {
                    findPreference(getString(R.string.pref_connect_skzi_time_error_key)).setVisible(true);
                    findPreference(getString(R.string.pref_connect_skzi_time_error_key)).setOnPreferenceClickListener(preference -> {
                        new MaterialAlertDialogBuilder(mContext)
                                .setTitle(getString(R.string.pref_connect_skzi_time_error))
                                .setMessage(s)
                                .setPositiveButton("OK", null)
                                .show();
                        return true;
                    });
                } else {
                    findPreference(getString(R.string.pref_connect_skzi_time_error_key)).setVisible(false);
                }
            });
        }

        return super.onCreateView(inflater, container, savedInstanceState);
    }

    private void initIpAddressSettings() {
            EditTextPreference ipSkzi = findPreference(getString(R.string.pref_ip_skzi_key));
            ipSkzi.setSummary(PrefsUtils.ins().getIpSkzi());
            ipSkzi.setText(PrefsUtils.ins().getIpSkzi());

            EditTextPreference ipMon = findPreference(getString(R.string.pref_ip_mon_key));
            ipMon.setSummary(PrefsUtils.ins().getIpMon());
            ipMon.setText(PrefsUtils.ins().getIpMon());

            EditTextPreference ipDns = findPreference(getString(R.string.pref_ip_dns_key));
            ipDns.setSummary(PrefsUtils.ins().getIpDns());
            ipDns.setText(PrefsUtils.ins().getIpDns());

            EditTextPreference ipDnsSecond = findPreference(getString(R.string.pref_ip_dns_second_key));
            ipDnsSecond.setSummary(PrefsUtils.ins().getIpDnsSecond());
            ipDnsSecond.setText(PrefsUtils.ins().getIpDnsSecond());
    }

    private void setIpAddressPreferencesListener() {
        findPreference(getString(R.string.pref_ip_skzi_key)).setOnPreferenceChangeListener((preference, newValue) -> {
            if(!PrefsUtils.ins().getIpSkzi().equals(newValue.toString())) {
                PrefsUtils.ins().setIpSkzi(newValue.toString());
                preference.setSummary(newValue.toString());
            }
            return true;
        });

        findPreference(getString(R.string.pref_ip_mon_key)).setOnPreferenceChangeListener((preference, newValue) -> {
            if(!PrefsUtils.ins().getIpMon().equals(newValue.toString())) {
                PrefsUtils.ins().setIpMon(newValue.toString());
                preference.setSummary(newValue.toString());
            }
            return true;
        });

        findPreference(getString(R.string.pref_ip_dns_key)).setOnPreferenceChangeListener((preference, newValue) -> {
            if(!PrefsUtils.ins().getIpDns().equals(newValue.toString())) {
                PrefsUtils.ins().setIpDns(newValue.toString());
                preference.setSummary(newValue.toString());
            }
            return true;
        });

        findPreference(getString(R.string.pref_ip_dns_second_key)).setOnPreferenceChangeListener((preference, newValue) -> {
            if(!PrefsUtils.ins().getIpDnsSecond().equals(newValue.toString())) {
                PrefsUtils.ins().setIpDnsSecond(newValue.toString());
                preference.setSummary(newValue.toString());
            }
            return true;
        });
    }

    private void initAdvancedSettings() {

    }

    private void setAdvancedPreferencesListener() {
        findPreference(getString(R.string.pref_export_logs_key)).setOnPreferenceClickListener(preference -> {
            ((SecondaryActivity)getActivity()).displayFragment(LoggerFragment.newInstance(), true);
            return false;
        });
        findPreference(getString(R.string.pref_change_pass_key)).setOnPreferenceClickListener(preference -> {
            ((SecondaryActivity) getActivity()).displayFragment(ChangePassFragment.newInstance(mContext), true);
            return false;
        });

        findPreference(getString(R.string.pref_background_work_key)).setOnPreferenceClickListener(preference -> {
            Intent intent = new Intent();
            String packageName = mContext.getPackageName();
            PowerManager pm = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
            if (pm.isIgnoringBatteryOptimizations(packageName))
                intent.setAction(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
            else {
                intent.setAction(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                intent.setData(Uri.parse("package:" + packageName));
            }
            startActivity(intent);
            return false;
        });

    }

    private void initKeyInfo() {
        ArrayList<VpnClient.KeyInf> nextKeys = VpnClient.ins().getNextKeys();
        if (nextKeys != null) {
            for(int i = 0; i < nextKeys.size(); i++) {
                PreferenceCategory keys_category = (PreferenceCategory) findPreference(getString(R.string.pref_key_compl_key));
                PreferenceScreen preferenceScreen = createPrefScreenNextKey();
                preferenceScreen.setKey("key_next_settings_" + i);
                preferenceScreen.setTitle("Комплект ключей (очередной) " + (i + 1));
                keys_category.addPreference(preferenceScreen);
            }
        }

        MultiSelectListPreference work_with_vpn = (MultiSelectListPreference)findPreference(getString(R.string.pref_work_with_vpn_key));

        boolean isCaptureAll = PrefsUtils.ins().isCaptureAll();

        SwitchPreferenceCompat is_capture_all_apps = (SwitchPreferenceCompat) findPreference(getString(R.string.pref_skzi_capture_all_apps_key));
        is_capture_all_apps.setChecked(isCaptureAll);
        is_capture_all_apps.setOnPreferenceChangeListener( (preference, newValue) -> {
            PrefsUtils.ins().setCaptureAll((boolean)newValue);

            initKeyInfo();

            return true;
        });


        if (isCaptureAll) {
            work_with_vpn.setVisible(false);
        } else {
            work_with_vpn.setVisible(true);
            PackageManager pm = mContext.getPackageManager();
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://"));
            //intent.setData(Uri.parse("http://"));
            List<ResolveInfo> listBrowser = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL);
            String [] list_package_app = new String [listBrowser.size()];
            String [] list_name_app = new String [listBrowser.size()];

            int i = 0;
            for(ResolveInfo resolveInfo : listBrowser) {
                list_package_app[i] = resolveInfo.activityInfo.packageName;
                list_name_app[i] = resolveInfo.activityInfo.loadLabel(getContext().getPackageManager()).toString();
                i++;
            }

            work_with_vpn.setEntries(list_name_app);
            work_with_vpn.setEntryValues(list_package_app);
            work_with_vpn.setValues(PrefsUtils.ins().getVpnApps());

            work_with_vpn.setOnPreferenceChangeListener((preference, newValue) -> {
                PrefsUtils.ins().setVpnApps((Set<String>)newValue);
                VpnClient.stopVpnService(mContext);
                return true;
            });

        }


    }

    private PreferenceScreen createPrefScreenNextKey() {
        PreferenceScreen preferenceScreen = getPreferenceManager().createPreferenceScreen(getContext());
        PreferenceCategory preferenceCategory = new PreferenceCategory(getContext());
        preferenceCategory.setTitle(R.string.key_next_settings_title);
        preferenceScreen.addPreference(preferenceCategory);
        return preferenceScreen;
    }

    private void initBiometrySettings() {
        PreferenceCategory category = findPreference(getString(R.string.pref_biometry_settings_cat_key));
        if (category == null)
            return;

        if (!BiometryPrefs.ins().isInitBiometryLib()) {
            category.setVisible(false);
            return;
        }

        Preference deleteBiometry = category.getPreference(0);
        Preference createBiometry = category.getPreference(1);
        Preference updateBiometry = category.getPreference(2);
        Preference exportBiometry = category.getPreference(3);
        Preference importBiometry = category.getPreference(4);

        if (BiometryPrefs.ins().isBiometryBind()) {
            deleteBiometry.setVisible(true);
            deleteBiometry.setOnPreferenceClickListener(preference -> {
                new MaterialAlertDialogBuilder(getContext())
                        .setTitle("Удалить биометрический контейнер ?")
                        .setNegativeButton("Нет", null)
                        .setPositiveButton("Да", (dialog, which) -> {
                            Utils.showWaitDialog(mContext, "Удаление контейнера");
                            /*waitDialog = new MaterialAlertDialogBuilder(mContext)
                                    .setTitle("Удаление контейнера")
                                    .setView(R.layout.dialog_wait)
                                    .setCancelable(false)
                                    .show();*/

                            new Thread(() -> {
                                BiometryPrefs.ins().setBiometryBind(false);
                                BiometryPrefs.ins().setP1(0);
                                BiometryPrefs.ins().setP2(0);
                                BiometryPrefs.ins().setP3(0);
                                Utils.deleteRecursive(BiometryUtils.getImagesDir(mContext));
                                Utils.deleteRecursive(BiometryUtils.getNbccDir(mContext));
                                Utils.deleteRecursive(BiometryUtils.getRectDir(mContext));

                                mHandler.post(() -> {
                                    Utils.closeWaitDialog();
                                    /* waitDialog.dismiss();*/
                                    initBiometrySettings();
                                    Toast.makeText(mContext, "Биометрический контейнер удален", Toast.LENGTH_SHORT).show();
                                });
                            }).start();
                        })
                        .show();
                return true;
            });
            createBiometry.setVisible(false);
            updateBiometry.setVisible(true);
            updateBiometry.setOnPreferenceClickListener(preference -> {
                new MaterialAlertDialogBuilder(mContext)
                        .setTitle("Переобучение биометрического контейнера")
                        .setMessage(R.string.info_update_biometry)
                        .setNegativeButton("Отмена", null)
                        .setPositiveButton("Переобучить", (dialog, which) -> {
                            ArrayList<byte[]> dataArray = new ArrayList<>();
                            dataArray.add(PrefsUtils.ins().getHashPass());
                            byte [] data = BiometryUtils.dataGeneration(dataArray);
                            BiometryPrefs.ins().setKeyDecryptImage(PrefsUtils.ins().getHashPass());
                            BiometryPrefs.ins().setKeyEncryptImage(PrefsUtils.ins().getHashPass());
                            Intent newIntent = new Intent(mContext, BiometryActivity.class);
                            newIntent.putExtra(BiometryActivity.REGIME, BiometryActivity.REGIME_UPDATE);
                            newIntent.putExtra(BiometryActivity.DATA, data);
                            biometryResultLauncher.launch(newIntent);
                        })
                        .show();
                return true;
            });

            exportBiometry.setVisible(true);
            exportBiometry.setOnPreferenceClickListener(preference -> {
                AlertDialog alertDialog = new MaterialAlertDialogBuilder(mContext)
                        .setTitle("Экспорт биометрического контейнера")
                        .setMessage(R.string.info_export_biometry)
                        .setView(R.layout.dialog_export_biometry)
                        .setNegativeButton("Отмена", null)
                        .setPositiveButton("Экспорт", (dialog, which) -> {
                            if (pickedDir == null)
                                return;

                            CheckBox isAddImagesCheckBox = ((AlertDialog)dialog).findViewById(R.id.isAddImages);
                            boolean isAddImages = isAddImagesCheckBox.isChecked();

                            Utils.showWaitDialog(mContext, "Экспорт контейнера");
                            /*waitDialog = new MaterialAlertDialogBuilder(mContext)
                                    .setTitle("Экспорт контейнера")
                                    .setView(R.layout.dialog_wait)
                                    .setCancelable(false)
                                    .show();*/

                            new Thread(() -> {
                                DocumentFile fileCont = pickedDir.createFile("text", "ImpulsBiom.bc");
                                // Создание архива
                                File archive = BiometryUtils.exportContainer(mContext, isAddImages);
                                if (archive == null) {
                                    mHandler.post(() -> {
                                        Utils.closeWaitDialog();
                                        /* waitDialog.dismiss();*/
                                        Toast.makeText(mContext, "Ошибка экспорта контейнера", Toast.LENGTH_SHORT).show();
                                    });
                                    return;
                                }

                                try (OutputStream os = mContext.getContentResolver().openOutputStream(fileCont.getUri())) {
                                    byte [] data;
                                    FileInputStream fis = new FileInputStream(archive);
                                    data = new byte [fis.available()];
                                    fis.read(data);
                                    // Шифрование архива
                                    data = CryptUtils.cryptData(data, PrefsUtils.ins().getHashPass());
                                    os.write(data);
                                    os.flush();
                                    archive.delete();
                                } catch (Exception ex) {
                                    archive.delete();
                                    mHandler.post(() -> {
                                        Utils.closeWaitDialog();
                                        /*waitDialog.dismiss();*/
                                        Toast.makeText(mContext, "Ошибка экспорта контейнера", Toast.LENGTH_SHORT).show();
                                    });
                                    return;
                                }
                                mHandler.post(() -> {
                                    Utils.closeWaitDialog();
                                    /*waitDialog.dismiss();*/
                                    Toast.makeText(mContext, "Контейнер экспортирован", Toast.LENGTH_SHORT).show();
                                });
                            }).start();
                        })
                        .show();
                ImageButton button = alertDialog.findViewById(R.id.btnSelectKeyDir);
                button.setOnClickListener(view -> {
                    if (ContextCompat.checkSelfPermission(mContext, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                        if (ActivityCompat.shouldShowRequestPermissionRationale(getActivity(), Manifest.permission.WRITE_EXTERNAL_STORAGE) ) {
                            // Можно отобразить для чего нужно разрешение
                        }
                        requestPermissionWrite.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE);
                    } else {
                        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
                        selectDirResultLauncher.launch(intent);
                    }
                });
                selectedDir = alertDialog.findViewById(R.id.nameDir);
                return true;
            });
            importBiometry.setVisible(false);
        } else {
            deleteBiometry.setVisible(false);
            createBiometry.setVisible(true);
            createBiometry.setOnPreferenceClickListener(preference -> {
                new MaterialAlertDialogBuilder(mContext)
                        .setTitle("Создание биометрического контейнера")
                        .setMessage(R.string.info_create_biometry)
                        .setNegativeButton("Отмена", null)
                        .setPositiveButton("Создать", (dialog, which) -> {
                            ArrayList<byte[]> dataArray = new ArrayList<>();
                            dataArray.add(PrefsUtils.ins().getHashPass());
                            byte [] data = BiometryUtils.dataGeneration(dataArray);
                            BiometryUtils.createDirs(mContext);
                            BiometryPrefs.ins().setKeyDecryptImage(PrefsUtils.ins().getHashPass());
                            BiometryPrefs.ins().setKeyEncryptImage(PrefsUtils.ins().getHashPass());
                            Intent newIntent = new Intent(mContext, BiometryActivity.class);
                            newIntent.putExtra(BiometryActivity.REGIME, BiometryActivity.REGIME_COLLECT_ALL);
                            newIntent.putExtra(BiometryActivity.DATA, data);
                            biometryResultLauncher.launch(newIntent);
                        })
                        .show();
                return true;
            });
            updateBiometry.setVisible(false);
            exportBiometry.setVisible(false);
            importBiometry.setVisible(true);
            importBiometry.setOnPreferenceClickListener(preference -> {
                AlertDialog alertDialog = new MaterialAlertDialogBuilder(mContext)
                        .setTitle(getString(R.string.import_biometry_title))
                        .setMessage(R.string.info_import_biometry)
                        .setView(R.layout.dialog_import_biometry)
                        .setNegativeButton("Отмена", null)
                        .setPositiveButton("Импорт", (dialog, which) -> {
                            EditText editText = ((AlertDialog)dialog).findViewById(R.id.pass);
                            if (editText == null)
                                return;

                            String passEnter = editText.getText().toString();
                            if (passEnter.length() == 0) {
                                Toast.makeText(mContext, "Пароль не введен", Toast.LENGTH_SHORT).show();
                                return;
                            }

                            if (pickedFile == null)
                                return;
                            Utils.showWaitDialog(mContext, "Импорт контейнера");

                            new Thread(() -> {
                                File temp = new File(BiometryUtils.getBiometryDir(mContext), "BiomContArchive");
                                try (InputStream is = mContext.getContentResolver().openInputStream(pickedFile.getUri())) {
                                    byte [] data = new byte[is.available()];
                                    is.read(data);

                                    data = CryptUtils.decryptData(data, CryptUtils.getHash(passEnter.getBytes()));
                                    if (data == null) {
                                        mHandler.post(() -> {
                                            Utils.closeWaitDialog();
                                            Toast.makeText(mContext, "Неверный пароль", Toast.LENGTH_SHORT).show();
                                        });
                                        return;
                                    }

                                    FileOutputStream fos = new FileOutputStream(temp);
                                    fos.write(data);
                                    fos.flush();
                                    fos.close();
                                } catch (Exception ex) {
                                    temp.delete();
                                    mHandler.post(() -> {
                                        Utils.closeWaitDialog();
                                        Toast.makeText(mContext, "Ошибка импорта контейнера", Toast.LENGTH_SHORT).show();
                                    });
                                    return;
                                }

                                if (!BiometryUtils.importContainer(mContext, temp)) {
                                    temp.delete();
                                    mHandler.post(() -> {
                                        Utils.closeWaitDialog();
                                        /*waitDialog.dismiss();*/
                                        Toast.makeText(mContext, "Ошибка импорта контейнера", Toast.LENGTH_SHORT).show();
                                    });
                                    return;
                                }

                                temp.delete();
                                BiometryPrefs.ins().setBiometryBind(true);
                                mHandler.post(() -> {
                                    Utils.closeWaitDialog();
                                    /*waitDialog.dismiss();*/
                                    initBiometrySettings();
                                    Toast.makeText(mContext, "Контейнер импортирован", Toast.LENGTH_SHORT).show();
                                });
                            }).start();
                        })
                        .show();
                ImageButton button = alertDialog.findViewById(R.id.btnSelectFile);
                button.setOnClickListener(view -> {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("*/*");
                    selectFileResultLauncher.launch(intent);
                });
                selectedDir = alertDialog.findViewById(R.id.nameDir);

                return true;
            });
        }
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
                                    BiometryUtils.saveNBCC(mContext, nbcc);
                                    Toast.makeText(mContext, org.pniei.dwface.R.string.biometry_result_ok, Toast.LENGTH_SHORT).show();
                                    BiometryPrefs.ins().setBiometryBind(true);
                                    initBiometrySettings();
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

    public void registerForSelectDirResult() {
        selectDirResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        Uri treeUri = resultData.getData();
                        pickedDir = DocumentFile.fromTreeUri(mContext, treeUri);
                        mContext.getContentResolver().takePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

                        String dir = FileUtils.getUriPath(mContext, treeUri);
                        if (selectedDir != null)
                            selectedDir.setText(dir == null ? "" : ("/" + dir));
                    }
                });
    }

    public void registerForSelectFileResult() {
        selectFileResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        Intent resultData = result.getData();
                        Uri fileUri = resultData.getData();
                        pickedFile = DocumentFile.fromSingleUri(getContext(), fileUri);
                        selectedDir.setText(pickedFile.getName());
                    }
                });
    }

    public void registerForRequestPermission() {
        requestPermissionWrite = registerForActivityResult(
                new ActivityResultContracts.RequestPermission(),
                isGranted -> {
                    Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
                    selectDirResultLauncher.launch(intent);
                }
        );

    }


    @Override
    public void onDestroyView() {
        ManagerLiveData.ins().getSkziTimeError().removeObservers(getViewLifecycleOwner());
        super.onDestroyView();
    }


}
