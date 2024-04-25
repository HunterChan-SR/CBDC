package com.example.cdbcapp.activity;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.example.cdbcapp.R;
import com.example.cdbcapp.databinding.ActivityMainBinding;
import com.example.cdbcapp.libnative.libnative;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'cdbcapp' library on application startup.
    static {
        System.loadLibrary("cdbcapp");
    }


    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = findViewById(R.id.text_view);
        tv.setText(libnative.goCBDC());

//        Button buttonEnroll = findViewById(R.id.button_enroll);
//        buttonEnroll.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                Intent intent = new Intent(MainActivity.this, EnrollActivity.class);
//                startActivity(intent);
//            }
//        });
//
//        Button buttonOfflineTx = findViewById(R.id.button_offline_tx);
//        buttonOfflineTx.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                Intent intent = new Intent(MainActivity.this, OfflineTxActivity.class);
//                startActivity(intent);
//            }
//        });
    }


}