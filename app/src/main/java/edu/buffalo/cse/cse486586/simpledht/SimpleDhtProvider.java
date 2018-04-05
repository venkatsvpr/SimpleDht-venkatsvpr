package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.util.concurrent.atomic.AtomicInteger;
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
    static String[] hash_remote_port_arr = new String[] {"NA", "NA", "NA", "NA","NA"};
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
    static HashMap<String, String> querybuffer = new HashMap<String, String>();
    static HashMap<String, String> avdname =  new HashMap<String, String>();


    static Object querylock = new Object();


    public void put_data (String key, String value) {
        Log.d("venkat","doing put data ");
        FileOutputStream outputStream;
        try
        {
            if ((value != null ) && (key != null))
            {
                Log.d("venkat", "openFileOutput - Success - File: " + key + "data" + value);
                outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                outputStream.write(value.getBytes());
                outputStream.close();
            }
            else
            {
                Log.d("venkat","write failed due to some reason");
            }
        }
        catch (Exception e)
        {
            Log.e("venkat", "File write failed");
        }
    }


    public String get_data(String selection) {
        Log.d("venkat","doi get_data "+selection);
        String message = null;
        Log.v("query", selection);
        InputStream is = null;
        try
        {
            is = getContext().openFileInput(selection);
            InputStreamReader is_Reader = new InputStreamReader(is);
            BufferedReader b_Reader = new BufferedReader(is_Reader);
            message = b_Reader.readLine();
            b_Reader.close();
            is_Reader.close();
            is.close();
        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }

        catch (IOException e) {
            e.printStackTrace();
        }

        return message;
    }

    public boolean containskey (String selection) {
        Log.d("venkat","going to do contains key"+selection);
        InputStream is = null;
        try {
            is = getContext().openFileInput(selection);
            is.close();
            return true;
        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void remove_data (String selection) {
        Log.d("venkat","going to do remove_Data on "+selection);
        File directory = getContext().getFilesDir();
        File file = new File(directory, selection);
        if (file.exists()) {
            Log.d("venkat","file exists  deleting the same");
            file.delete();
        }
        return;
    }
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
                send_message(peer_info, selection+":"+myPort, "delete");
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
        Log.d("venkat"," insert "+key_val+" "+data+" peercount "+peerCount);
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
            if (hash_in_range(hashkey, myPort, peer_info))
            {
                Log.d("venkat"," forceputting in the next "+peer_info);
                send_message(peer_info, key_val + ":" + data, "force-put");
            } else {
                Log.d("venkat","put in next "+peer_info);
                String ret = send_message(peer_info, key_val + ":" + data, "put");
            }
        }
            // TODO Auto-generated method stub
        return uri;
    }

    @Override
    public boolean onCreate() {
        /* Venkat - Do the server socket setup */
        Context context = getContext();
        TelephonyManager tel = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        Log.d("venkat"," my port is "+myPort);
        avdname.put("11108","5554");
        avdname.put("11112","5556");
        avdname.put("11116","5558");
        avdname.put("11120","5560");
        avdname.put("11124","5562");

        try {
            myhash = genHash(avdname.get(myPort));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        Log.d("venkat"," myhash "+myhash+" local "+avdname.get(myPort));




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
            try {
                hashkey = genHash(selection);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            String nextInfo = peer_info;
            if (selection.equals("*"))
            {
                getMyValues (mCursor);
                int i = 0;
                while (i < 5) {
                    // First send message to our peer.
                    String ret = send_message(nextInfo, "*", "all");
                    if (!ret.equals("ack")) {
                            Log.d("venkat", "peer responded to all with :" + ret);
                        String[] split_tokens = ret.split("#");
                        for (int j = 0; j < split_tokens.length; j++) {
                            String[] kv_tokens = split_tokens[j].split(":");
                            if (kv_tokens.length == 2) {
                                mCursor.addRow(new String[]{kv_tokens[0], kv_tokens[1]});
                            }
                        }
                    }
                    // From current peer get its peer

                    String returnval = null;
                    returnval = send_message(nextInfo, "*", "next_info");
                    Log.d("venkat","peer replied with next_info as :"+returnval);
                    if (returnval.equals(myPort)) {
                        break;
                    }
                    if (returnval != null) {
                        nextInfo = returnval;
                    } else {
                        break;
                    }
                    i++;
                }
            }
            else if (selection.equals("@")) {
                getMyValues(mCursor);
            }
            else {
                Log.d("venkat"," my port is "+myPort+" next port is "+peer_info);

                if (hmap.containsKey(selection)){
                    Log.d("venkat","selection contained in hmap "+selection);
                    mCursor.addRow(new String[]{selection, hmap.get(selection)});
                }
                else if (!peer_info.equals("NA")) {
                    /* venkat have to fix this part */
                    /* some locking mechanisim have to be devised */
                            send_message(peer_info, selection + ":" + myPort, "get");
                            Log.d("venkat","entering sync block");
                            synchronized (querylock) {
                            try {
                                Log.d("venkat","waiting on lock at query for "+selection);
                                querylock.wait();
                                Log.d("venkat","lock obtained ....");
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                            if (querybuffer.containsKey(selection)) {
                                String ret = querybuffer.get(selection);
                                mCursor.addRow(new String[]{selection, ret});
                                /* have to clear querybuffer of the entry */
                            }

                    }
                }
            }
        }
        return mCursor;
    }

    private boolean hash_in_range(String hash, String start, String end) {
        String start_hash = null;
        String end_hash = null;
        try {
            start_hash = genHash(avdname.get(start));
            end_hash = genHash(avdname.get(end));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        if ((start_hash.compareTo(hash) <0) && (end_hash.compareTo(hash)>0)) {
            return true;
        }

        if (start_hash.compareTo(end_hash) > 0) {
            if ((start_hash.compareTo(hash) <0) || (end_hash.compareTo(hash)>0)) {
                return true;
            }
        }
        return false;
    }
    private String send_message (String port, String selection, String method) {
        try {
            Log.d("venkat","send message: port: "+port+" selection: "+selection+" method:"+method);
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
        Log.d("venkat", "getMyValues : myhash is " +myhash);
        for (String key : hmap.keySet()) {
            Log.d("venkat",key+" : "+hmap.get(key));
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
                if (hash_remote_port_arr[Index].equals(genHash(avdname.get(remote_port_arr[i])))) {
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

        String[] sorted_ports = new String[] {"NA", "NA", "NA" , "NA" ,"NA"};
        for (i = 0; i <=4; i++) {
            if (getPort(i) != null) {
                sorted_ports[i] = getPort(i);
            }
        }

        String firstport = null;
        String prevport = null;
        for (i = 0; i <=4; i++) {
            if (!sorted_ports[i].equals("NA")) {
                if (firstport == null) {
                    firstport = sorted_ports[i];
                }

                if (prevport != null) {
                    send_message(prevport,sorted_ports[i]+":"+peerCount,"peer");
                }
                prevport = sorted_ports[i];
            }
        }

        if (!firstport.equals(prevport)) {
            send_message(prevport,firstport+":"+peerCount,"peer");
        }



      /* have to sort this  out */
        /*

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
        */
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
                    DataInputStream in = new DataInputStream(accept.getInputStream());
                    String message = null;
                    message = in.readUTF();
                    String[] split_tokens = message.split("#");
                    Log.d("venkat", "Reading Message from accept " + accept);
                    if (message == null) {
                        Log.d("venkat", "null message read skip");
                        continue;
                    }

                    Log.d("venkat" ," Message is : "+message);
                    if (split_tokens[0].equals("connect")) {
                        peerCount += 1;
                        String peerport = split_tokens[1];
                        for (int i = 0; i <= 4; i++) {
                            if (hash_remote_port_arr[i] == "NA") {
                                hash_remote_port_arr[i] = genHash(avdname.get(peerport));
                                break;
                            }
                            else if (hash_remote_port_arr[i].equals(genHash(avdname.get(peerport)))) {
                                break;
                            }
                        }
                        Log.d ("venkat"," without sort"+Arrays.toString(hash_remote_port_arr));
                        Arrays.sort(hash_remote_port_arr);
                        Log.d ("venkat"," Hash array "+Arrays.toString(hash_remote_port_arr));
                        Log.d("venkat", "Read the  message: " + message+" from "+peerport + "hash is "+genHash(avdname.get(peerport)));
                        Log.d("venkat"," ports in ring : "+getPort(0)+" "+getPort(1)+" "+getPort(2)+" "+getPort(3)+" "+ getPort(4));
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();
                        send_peer_information(hash_remote_port_arr);
                    }
                    else if (split_tokens[0].equals("get-reply")) {
                        synchronized (querylock) {
                            String key_string = split_tokens[1];
                            String[] key_splits = key_string.split(":");
                            String key = key_splits[0];
                            String value = key_splits[1];
                            Log.d("venkat"," key:"+key+" value:"+value);
                            querybuffer.put(key, value);
                            querylock.notify();
                        }
                    }
                    else if (split_tokens[0].equals("get")) {
                        /* use the same logic for others..
                        venkat.....
                         */

                        String fromPort  = split_tokens[2];
                        String key_string = split_tokens[1];
                        String[] key_splits = key_string.split(":");
                        String key = key_splits[0];
                        String sender = key_splits[1];

                        if (hmap.containsKey(key)) {
                            /* have to send to this guy */
                            /* who initiated teher query */
                            DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                            out_print.writeUTF("ack");
                            out_print.flush();

                            String mess2 = sender+"#"+key+":"+hmap.get(key)+"#get-reply";
                            Log.d("venkat","going to reply back to "+sender+" for get of  key "+key+"with value "+hmap.get(key));
                            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, mess2, myPort);
                        }
                        else if (key_splits[1].equals(peer_info))  {
                            Log.d("venkat","This shouldnt ever happen");
                            DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                            out_print.writeUTF(key+":"+" ");
                            out_print.flush();
                        }
                        else {
                            DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                            out_print.writeUTF("ack");
                            out_print.flush();

                            String mess2 = peer_info+"#"+key_string+"#get#"+Integer.toString(count);
                            Log.d("venkat","Message input :"+message);
                            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, mess2, myPort);
                        }
                    }
                    else if (split_tokens[0].equals("next_info")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(peer_info);
                        out_print.flush();
                    }
                    else if (split_tokens[0].equals("all")) {
                        String outString = "";
                        for (String key : hmap.keySet()) {
                            outString += key;
                            outString += ":";
                            outString += hmap.get(key);
                            outString += "#";
                        }

                        if (outString == null)
                        {
                            outString = "ack";
                        }
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF(outString);
                        out_print.flush();
                    }
                    else if (split_tokens[0].equals("force-put")) {
                        String keyvalue = split_tokens[1];
                        String[] new_split_tokens  = keyvalue.split(":");
                        hmap.put(new_split_tokens[0], new_split_tokens[1]);
                        Log.d("venkat","inserted into hmap "+new_split_tokens[0]+":"+new_split_tokens[1]);
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();

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
                        //hmap.put(new_split_tokens[0], new_split_tokens[1]);

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
                            else {
                                if (hmap.containsKey(subsplit[0])) {
                                    hmap.remove(subsplit[0]);
                                }
                                else {
                                    if (!peer_info.equals(subsplit[1])) {
                                        send_message(peer_info,token1,"delete");
                                    }
                                }
                            }
                        }
                        else {
                            Log.d("venkat","Shouldnt be here ever!!!!!");
                        }
                    }
                    else if (split_tokens[0].equals("peer")) {
                        DataOutputStream out_print = new DataOutputStream(accept.getOutputStream());
                        out_print.writeUTF("ack");
                        out_print.flush();

                        String data = split_tokens[1];
                        String[] subsplit = data.split(":");
                        peer_info = subsplit[0];
                        peerCount = Integer.parseInt(subsplit[1]);

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
            String[] split_tokens =  message.split("#");
            String port = split_tokens[0];
            String selection = split_tokens[1];
            String method = split_tokens[2];

            String ret = client_send_message(port,selection,method);

            Log.d("venkat",myPort+"created");
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
