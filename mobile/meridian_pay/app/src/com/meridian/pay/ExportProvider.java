package com.meridian.pay;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import java.io.File;

public class ExportProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        File base = new File(getContext().getFilesDir(), "receipts");
        String path = uri.getPath();
        String name = path.startsWith("/files/") ? path.substring("/files/".length()) : path;
        File target = new File(base, name);
        try {
            return ParcelFileDescriptor.open(target, ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public String getType(Uri uri) {
        return "text/plain";
    }

    @Override
    public Cursor query(Uri uri, String[] p, String s, String[] a, String o) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues v) {
        return null;
    }

    @Override
    public int delete(Uri uri, String s, String[] a) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues v, String s, String[] a) {
        return 0;
    }
}
