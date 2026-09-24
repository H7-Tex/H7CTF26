package com.deskline;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

public class TicketProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    // exposes the agent's ticket list to companion apps. the caller-supplied selection is
    // concatenated straight into the query.
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        SQLiteDatabase db = new DeskDb(getContext()).getReadableDatabase();
        String sql = "SELECT id, subject, body FROM tickets";
        if (selection != null && selection.trim().length() > 0) {
            sql += " WHERE " + selection;
        }
        if (sortOrder != null && sortOrder.trim().length() > 0) {
            sql += " ORDER BY " + sortOrder;
        }
        return db.rawQuery(sql, null);
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.com.deskline.tickets";
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
