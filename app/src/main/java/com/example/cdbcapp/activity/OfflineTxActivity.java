package com.example.cdbcapp.activity;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.example.cdbcapp.R;
import com.example.cdbcapp.libnative.libnative;

public class OfflineTxActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_offline_tx);

        Button buttonExit = findViewById(R.id.button_exit_offline_tx);
        buttonExit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });
        TextView textViewOfflineTx = findViewById(R.id.text_offline_tx);
        textViewOfflineTx.setText(libnative.TestOfflineTx());

    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        finish();
    }
}
