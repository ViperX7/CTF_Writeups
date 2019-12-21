package com.r4hu1.secret;

import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private Button mButton;
    /* access modifiers changed from: private */
    public EditText mEditText;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView((int) C0273R.layout.activity_main);
        this.mButton = (Button) findViewById(C0273R.C0275id.submit);
        this.mButton.setOnClickListener(new OnClickListener() {
            public void onClick(View view) {
                int i;
                MainActivity mainActivity = MainActivity.this;
                mainActivity.mEditText = (EditText) mainActivity.findViewById(C0273R.C0275id.editText);
                String obj = MainActivity.this.mEditText.getText().toString();
                StringBuilder sb = new StringBuilder();
                if (obj.isEmpty()) {
                    MainActivity.this.error();
                    return;
                }
                for (int i2 = 0; i2 < obj.length(); i2++) {
                    char charAt = obj.charAt(i2);
                    if (charAt < 'a' || charAt > 'm') {
                        if (charAt < 'n' || charAt > 'z') {
                            if (charAt < 'A' || charAt > 'M') {
                                if (charAt >= 'N') {
                                    if (charAt > 'Z') {
                                    }
                                }
                                sb.append(charAt);
                            }
                        }
                        i = charAt - 13;
                        charAt = (char) i;
                        sb.append(charAt);
                    }
                    i = charAt + 13;
                    charAt = (char) i;
                    sb.append(charAt);
                }
                MainActivity.this.flagChecker(sb.toString());
            }
        });
    }

    public void flagChecker(String str) {
        byte[] bytes = str.getBytes();
        if (str.length() != 21 || !str.startsWith("vapgs{") || !str.endsWith("}")) {
            error();
        } else if (bytes[12] == bytes[15] && bytes[12] == 95) {
            for (int i = 6; i < 20; i++) {
                int i2 = i - 5;
                switch (i2) {
                    case 1:
                        if (bytes[(i2 * 2) + 4] == 97) {
                            break;
                        } else {
                            error();
                            break;
                        }
                    case 2:
                        if (bytes[(i2 * 2) + 3] == 110) {
                            break;
                        } else {
                            error();
                            break;
                        }
                    case 3:
                        if (bytes[(i2 * 2) + 2] == 116) {
                            break;
                        } else {
                            error();
                            break;
                        }
                    case 4:
                        if (bytes[(i2 * 2) + 1] == 110) {
                            break;
                        } else {
                            error();
                            break;
                        }
                    case 5:
                        if (bytes[(i2 * 2) + 0] == 103) {
                            break;
                        } else {
                            error();
                            break;
                        }
                    case 6:
                        if (bytes[(i2 * 2) - 1] == 98) {
                            break;
                        } else {
                            error();
                            break;
                        }
                    case 7:
                        if (bytes[(i2 * 2) - 2] == 95) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 8:
                        if (bytes[(i2 * 2) - 3] == 118) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 9:
                        if (bytes[(i2 * 2) - 4] == 102) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 10:
                        if (bytes[(i2 * 2) - 5] == 95) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 11:
                        if (bytes[(i2 * 2) - 6] == 99) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 12:
                        if (bytes[(i2 * 2) - 7] == 110) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 13:
                        if (bytes[(i2 * 2) - 8] == 118) {
                            break;
                        } else {
                            error1();
                            break;
                        }
                    case 14:
                        if (bytes[(i2 * 2) - 9] != 97) {
                            break;
                        } else {
                            hurray();
                            break;
                        }
                }
            }
        } else {
            error();
        }
    }

    /* access modifiers changed from: 0000 */
    public void error() {
        Toast.makeText(this, "This is not a secret", 1).show();
    }

    /* access modifiers changed from: 0000 */
    public void error1() {
        Toast.makeText(this, "OOPS!, You were close!", 1).show();
    }

    /* access modifiers changed from: 0000 */
    public void hurray() {
        Toast.makeText(this, "Kudos!! That's the secret", 1).show();
    }
}
