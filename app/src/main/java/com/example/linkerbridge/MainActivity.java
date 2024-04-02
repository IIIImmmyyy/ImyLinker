package com.example.linkerbridge;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.example.linkerbridge.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'linkerbridge' library on application startup.
    static {
        System.loadLibrary("imytest");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.btn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                loadSo2();
            }
        });
//        loadSo();
    }

    /**
     * A native method that is implemented by the 'linkerbridge' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native void  loadSo();

    public native void loadSo2();
}