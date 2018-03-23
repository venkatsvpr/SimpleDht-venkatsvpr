package edu.buffalo.cse.cse486586.simpledht;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.app.Activity;
import android.telephony.TelephonyManager;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

import static android.content.ContentValues.TAG;

public class SimpleDhtActivity extends Activity {
    static final String default_remote_port = "11108";
    static final String[] remote_port_arr = new String[] {"11108", "11112", "11116" , "11120" ,"11124"};
    static String myPort = null;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_simple_dht_main);
        
        TextView tv = (TextView) findViewById(R.id.textView1);
        tv.setMovementMethod(new ScrollingMovementMethod());
        findViewById(R.id.button3).setOnClickListener(
                new OnTestClickListener(tv, getContentResolver()));


        /* Venkat - Do the server socket setup */
        TelephonyManager tel = (TelephonyManager) this.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        ServerSocket serverSocket = null;
        try {
                serverSocket = new ServerSocket(10000);
                new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.activity_simple_dht_main, menu);
        return true;
    }

    private class  ServerTask extends AsyncTask<ServerSocket, String, Void>
    {
        private Uri mUri;
        private ContentResolver mContentResolver;
        private ContentValues cv = new ContentValues();


        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            try {
                if (myPort.equals(default_remote_port)) {
                    ServerSocket serverSocket = sockets[0];
                    Socket accept = null;
                    while (true) {
                        Log.d("venkat","waiting to accept sockets myport is "+myPort);
                        accept = serverSocket.accept();
                        DataInputStream in = new DataInputStream(accept.getInputStream());
                        String message = null;
                        message = in.readUTF();
                        Log.d("venkat", "Reading Message from accept " + accept);
                        if (message == null) {
                            Log.d("venkat", "null message read skip");
                            continue;
                        }
                        Log.d("venkat", "Read the  message: " + message);
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();

                    }
                }
                else {
                    Log.d("venkat", "Going to connect to the peer... myPort is" + myPort);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(default_remote_port));
                    socket.setSoTimeout(500);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    out.writeUTF("hello from " + myPort);
                    out.flush();

                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    String message = null;
                    message = in.readUTF();
                    Log.d("venkat", "Read ack reply:" + message);
                    out.close();
                    in.close();
                    socket.close();
                }
            }
            catch (SocketTimeoutException e) {
                Log.e("venkat", "ClientTask timeout");

            }
            catch (EOFException e) {
                Log.e("venkat", "ClientTask eof");
            }
            catch (StreamCorruptedException e ){
                Log.e("venkat", "stream corrupt");
            }
            catch (IOException e) {
                Log.e("venkat", "ClientTask socket IOException");
            }
            String output_message ="summa";
            publishProgress(new String[]{output_message});
            return null;
        }
        protected void onProgressUpdate(String...strings) {
            Log.d("venkat","in publish progress");
            return;
        }
    }


}
