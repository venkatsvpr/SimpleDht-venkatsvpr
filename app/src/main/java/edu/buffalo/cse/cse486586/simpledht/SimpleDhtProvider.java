package edu.buffalo.cse.cse486586.simpledht;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Formatter;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

/* Referenses:
   1) https://beginnersbook.com/2013/12/hashmap-in-java-with-example/  -  had simple code and used this
   to understand about Hashmap. No code is copied.

 */
public class SimpleDhtProvider extends ContentProvider {
    static Lock get_lock = new ReentrantLock();
    static final String default_remote_port = "11108";
    static final String[] remote_port_arr = new String[] {"11108", "11112", "11116" , "11120" ,"11124"};
    static String[] hash_remote_port_arr = new String[] {null,null,null,null,null};
    static String myhash = null;
    static String myPort = null;
    static int myPortIndex = -1;
    static int prevIndex = -1;
    static int nextIndex = -1;
    static int peerCount = 0;
    static int nextPort = -1;
    static String prev_info = "NA";
    static String peer_info = "NA";
    static int count = 0;
    static HashMap<String, String> hmap = null;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        Log.d("venkat","delete "+selection+" "+selectionArgs);
        if (selection.equals("@")) {
            deleteMyValues();
        }
        else if (selection.equals("*")) {
            if (peerCount >0)
            {
                send_message(peer_info,"*:"+myPort, "delete");
            }
            deleteMyValues();
        }
        else {
            if (hmap.containsKey(selection)) {
                hmap.remove(selection);
            }
            else {
                if (hash_in_range(genHash(selection),myPort,peer_info)) {
                    send_message(peer_info, selection, "delete");
                }
                /*
                String hashkey = null;
                String nextPort = null;

                try {
                    hashkey = genHash(selection);
                    nextPort = getPort(0);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                for (int i = 0; i <= 4; i++) {
                    if (hash_remote_port_arr[i] == null) {
                        continue;
                    }

                    if (hashkey.compareTo(hash_remote_port_arr[i]) < 0) {
                        try {
                            nextPort = getPort(i);
                            break;
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }
                }
                if (nextPort != null) {
                    send_message(nextPort, selection, "delete");
                } */
            }
        }

        if (peerCount == 0) {
            if (selection == "@")
            Log.d("venkat","no peers deleteting locally  for"+selection);
            hmap.remove(selection);
        }

        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        String key_val = values.getAsString("key");
        String data = values.getAsString("value");

        if (peerCount == 0) {
            Log.d("venkat", " insert  " + key_val + " " + data);
            hmap.put(key_val, data);
        }
        else {

            String hashkey = null;
            try {
                hashkey = genHash(key_val);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
              /*

            for (int i =0; i<=4; i++) {
                if (hash_remote_port_arr[i] == null) {
                    continue;
                }

                if (hashkey.compareTo(hash_remote_port_arr[i])<0) {
                    try {
                        nextPort = getPort(i);
                        break;
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
            }

            if (nextPort.equals(myPort)) {
                hmap.put(key_val, data);
            }
            else {
                String ret = null;
                ret = send_message(nextPort,key_val+":"+data,"put");
            }
            */
            if (hash_in_range(hashkey, myPort, peer_info)) {
                send_message(peer_info, key_val + ":" + data, "force-put");
            } else {
                String ret = send_message(nextPort, key_val + ":" + data, "put");
            }
        }

            // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean onCreate() {
        /* Venkat - Do the server socket setup */
        Context context = getContext();
        TelephonyManager tel = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        try {
            myhash = genHash(myPort);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(10000);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            e.printStackTrace();
        }

        hmap = new HashMap<String, String>();
        Log.d("venkat"," Hasharray is "+Arrays.toString(hash_remote_port_arr));
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder) {

        Log.d("venkat","query "+selection+" "+selectionArgs +" val"+hmap.get(selection));
        MatrixCursor mCursor = null;
        mCursor = new MatrixCursor(new String[]{"key", "value"});

        if (peerCount == 0) {
            if (selection.equals("*") || selection.equals("@")) {
                mCursor = getMyValues(mCursor);
            } else {
                mCursor.addRow(new String[]{selection, hmap.get(selection)});
            }
        }
        else {


            String hashkey = null;
            String hashmyport = null;

            try {
                hashkey = genHash(selection);
                hashmyport = genHash(myPort);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            String nextInfo = peer_info;
            if (selection.equals("*")) {
                getMyValues (mCursor);

                int i = 0;
                while (i < 5) {
                    /* First send message to our peer.  */
                    String ret = send_message(nextInfo, "*", "all");
                    String[] split_tokens = ret.split("#");
                    for (int j = 0; j < split_tokens.length; j++) {
                        if (split_tokens[j] == null) {
                            continue;
                        }
                        String[] kv_tokens = split_tokens[j].split(":");
                        mCursor.addRow(new String[]{kv_tokens[0], kv_tokens[1]});
                    }

                    /* From current peer get its peer */

                    String returnval = null;
                    returnval = send_message(nextInfo, "*", "next_info");
                    if (returnval.equals(myPort)) {
                        break;
                    }
                    if (returnval) {
                        nextInfo = returnval;
                    } else {
                        break;
                    }
                    i++;
                }

               /*
                for (int i =0; i<=4; i++) {
                    if (hash_remote_port_arr[i] != null) {
                        String nextport = null;
                        String ret =null;
                        try {
                            nextport = getPort(i);
                            ret = send_message(nextport,"*","all");


                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                        if (ret != null) {
                            String[] split_tokens = ret.split("#");
                            for (int j =0; j <split_tokens.length; j++) {
                                if (split_tokens[j] == null) {
                                    continue;
                                }
                                String[] kv_tokens = split_tokens[j].split(":");
                                mCursor.addRow(new String[] {kv_tokens[0],kv_tokens[1]});
                            }
                        }
                        else {
                            Log.d ("venkat","null returned from send_messsage");
                        }
                    }
                }
                */

            }
            else if (selection.equals("#")) {
                getMyValues(mCursor);
            }
            else {
                Log.d("venkat"," my port is "+myPort+" next port is "+peer_info);
                /*
                String nextPort = null;

                try {
                    nextPort = getPort(0);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                for (int i =0; i<=4; i++) {
                    if (hashkey.compareTo(hash_remote_port_arr[i])<0) {
                        try {
                            nextPort = getPort(i);
                            break;
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }
                }

                if (nextPort.equals(myPort)) {
                    mCursor.addRow(new String[]{selection, hmap.get(selection)});
                }
                else {
                    String ret = null;
                    ret = send_message(nextPort,selection,"get");
                    String[] split_tokens = ret.split(":");
                    if (ret != null) {
                        Log.d("venkat","Ret value is "+ret);
                        String retkey = split_tokens[0];
                        String retval = split_tokens[1];
                        mCursor.addRow(new String[]{selection, retval});
                    }
                }
                */
                if (hmap.containsKey(selection)){
                    mCursor.addRow(new String[]{selection, hmap[selection]});
                }
                else if (!peer_info.equals("NA")) {
                    /* venkat have to fix this part */
                    /* some locking mechanisim have to be devised */
                    if (hash_in_range(hashkey,myPort,peer_info)) {
                        String ret = send_message(peer_info,selection+":"+myPort,"get");
                        String[] split_tokens = ret.split(":");
                        if (ret != null) {
                            Log.d("venkat","Ret value is "+ret);
                            String retkey = split_tokens[0];
                            String retval = split_tokens[1];
                            mCursor.addRow(new String[]{selection, retval});
                        }
                    }
                }
            }
        }
        return mCursor;
    }

    private boolean hash_in_range(String hash, String start, String end) {
        String start_hash = genHash(start);
        String end_hash = genHash(end);
        if ((start_hash.compareTo(hash) >0) && (end_hash.compareTo(hash)<0)) {
            return true;
        }
        if (start_hash.compareTo(end_hash) > 0) {
            if ((start_hash.compareTo(hash) >0) || (end_hash.compareTo(hash)<0)) {
                return true;
            }
        }
        return false;
    }
    private String send_message (String port, String selection, String method) {
        try {
            Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                    Integer.parseInt(port));
            socket.setSoTimeout(500);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF(method + "#" + selection + "#" + myPort);
            out.flush();

            DataInputStream in = new DataInputStream(socket.getInputStream());
            String message = null;
            message = in.readUTF();
            Log.d("venkat", "Read ack reply:" + message);
            out.close();
            in.close();
            socket.close();
            Log.d ("venkat" , " myport: "+myPort+" peer: "+peer_info);
            return message;
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

        return null;
    }
    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        Log.d("venkat"," update "+selection+" "+selectionArgs+" "+values);
        // TODO Auto-generated method stub
        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private void EmptyLocalHmap ()  {
        for (String key : hmap.keySet()) {
            hmap.remove(key);
        }
    }

    private MatrixCursor getMyValues (MatrixCursor mCursor) {
        for (String key : hmap.keySet()) {
            mCursor.addRow(new String[]{key , hmap.get(key)});
        }
        return mCursor;
    }

    private void deleteMyValues () {
        for (String key : hmap.keySet()) {
            hmap.remove(key);
        }
    }

    private String getPort (int Index) throws NoSuchAlgorithmException {
        if (Index >=0 && Index <= 4 ) {
            Log.d("venkat", "getPort :"+Index);
            for (int i = 0; i <= 4; i++) {
                if (hash_remote_port_arr[Index].equals(genHash(remote_port_arr[i]))) {
                    return remote_port_arr[i];
                }
            }
        }
        return null;
    }

    private void send_peer_information (String[] remote_hash) throws NoSuchAlgorithmException {
        int i =0;
        String portInfo = null;
        String nextPortInfo = null;

        for (i = 0; i <=4; i++) {
            if (remote_hash[i] == null) {
                i--;
                break;
            }
            portInfo = getPort(i);
            nextPortInfo = getPort(i+1);

            if (portInfo.equals(myPort)) {
                peer_info = nextPortInfo;
                continue;
            }

            if (nextPortInfo == null) {
                nextPortInfo = getPort(0);
            }
            Log.d("venkat","sending peer update to"+portInfo+" with peer as "+nextPortInfo);
            send_message(portInfo,nextPortInfo,"peer");
        }
        return;
    }

    private class  ServerTask extends AsyncTask<ServerSocket, String, Void>
    {
        private Uri mUri;
        private ContentResolver mContentResolver;
        private ContentValues cv = new ContentValues();


        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            try {
                if (!myPort.equals(default_remote_port)) {
                    Log.d("venkat", "Going to connect to the peer... myPort is" + myPort);
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(default_remote_port));
                    socket.setSoTimeout(500);
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    out.writeUTF("connect#" + myPort);
                    out.flush();

                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    String message = null;
                    message = in.readUTF();
                    Log.d("venkat", "Read ack reply:" + message);
                    out.close();
                    in.close();
                    socket.close();
                }

                hash_remote_port_arr[0] = myhash;
                ServerSocket serverSocket = sockets[0];
                Socket accept = null;
                while (true) {
                    Log.d("venkat", "waiting to accept sockets myport is " + myPort +" peer is "+peer_info);
                    accept = serverSocket.accept();
                    peerCount += 1;
                    DataInputStream in = new DataInputStream(accept.getInputStream());
                    String message = null;
                    message = in.readUTF();
                    String[] split_tokens = message.split("#");
                    Log.d("venkat", "Reading Message from accept " + accept);
                    if (message == null) {
                        Log.d("venkat", "null message read skip");
                        continue;
                    }
                    else if (split_tokens[0].equals("connect")) {
                        String peerport = split_tokens[1];
                        for (int i = 0; i <= 4; i++) {
                            if (hash_remote_port_arr[i] == null) {
                                hash_remote_port_arr[i] = genHash(peerport);
                            }
                        }
                        Arrays.sort(hash_remote_port_arr);
                        Log.d("venkat", "Read the  message: " + message);
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                        send_peer_information(hash_remote_port_arr);
                    }
                    else if (split_tokens[0].equals("get")) {
                        /* use the same logic for others..
                        venkat.....
                         */
                        String fromPort  = split_tokens[2];
                        String key_string = split_tokens[1];
                        String[] key_splits = key_string.split(":");
                        String key = key_splits[0];
                        String value = null;

                        if (hmap.containsKey(key)) {
                            value = hmap.get(key);
                            DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                            out_print.writeUTF(key+":"+value);
                            out_print.flush();
                        }
                        else if (key_splits[1].equals(peer_info))  {
                            DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                            out_print.writeUTF(key+":"+" ");
                            out_print.flush();
                        }
                        else {
                            String message = peer_info+"#"+key_string+"#get#"+Integer.toString(count);
                            Log.d("venkat","Message input :"+message);
                            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, message, myPort, accept);

                        }
                    }
                    else if (split_tokens[0].equals("next_info")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(peer_info);
                        out_print.flush();
                    }
                    else if (split_tokens[0].equals("all")) {
                        String outString = null;
                        for (String key : hmap.keySet()) {
                            outString += key;
                            outString += ":";
                            outString += hmap.get(key);
                            outString += "#";
                        }
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(outString);
                        out_print.flush();
                    }
                    else if (split_tokens[0].equals("force-put")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();

                        String keyvalue = split_tokens[1];
                        String[] new_split_tokens  = keyvalue.split(":");
                        hmap.put(new_split_tokens[0], new_split_tokens[1]);
                    }
                    else if (split_tokens[0].equals("put")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();


                        String keyvalue = split_tokens[1];
                        String[] new_split_tokens  = keyvalue.split(":");
                        if (hash_in_range(genHash(new_split_tokens[0]),myPort,peer_info)) {
                            send_message(peer_info, split_tokens[1],"force-put");
                        } else {
                            send_message(peer_info, split_tokens[1],"put");
                        }
                        hmap.put(new_split_tokens[0], new_split_tokens[1]);

                    }
                    else if (split_tokens[0].equals("delete")) {
                        String token1 = split_tokens[1];
                        String[] subsplit = token1.split(":");
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();

                        if (subsplit.length == 2) {
                            if (subsplit[0].equals("*")) {
                                deleteMyValues();
                                if (!peer_info.equals(subsplit[1])) {
                                    send_message(peer_info,token1,"delete");
                                }
                            }
                        }
                        else {
                            String key = token1;
                            if (hmap.containsKey(key)) {
                                hmap.remove(key);
                            }
                            else {
                                send_message(peer_info, key, "delete");
                            }
                        }

                    }
                    else if (split_tokens[0].equals("peer")) {
                        peer_info = split_tokens[1];
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                    }
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
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
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

    private class ClientTask extends AsyncTask<String, Void, Void> {
        @Override
        protected Void doInBackground(String... msgs)
        {
            if (msgs[0]== null) {
                return null;
            }

            String message  = msgs[0];
            Socket accept = (Socket)msgs[2];
            String[] split_tokens =  message.split("#");
            String port = split_tokens[0];
            String selection = split_tokens[1];
            String method = split_tokens[2];
            String r_count = split_tokens[3];

            String ret = client_send_message(port,selection,method);

            Log.d("venkat",myPort+"created");
            try {
                DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                out_print.writeUTF(ret);
                out_print.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }

        private String client_send_message (String port, String selection, String method) {
            try {
                Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(port));
                socket.setSoTimeout(500);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeUTF(method + "#" + selection + "#" + myPort);
                out.flush();

                DataInputStream in = new DataInputStream(socket.getInputStream());
                String message = null;
                message = in.readUTF();
                Log.d("venkat", "Read ack reply:" + message);
                out.close();
                in.close();
                socket.close();
                Log.d ("venkat" , " myport: "+myPort+" peer: "+peer_info);
                return message;
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

            return null;
        }


    }
}
