package com.deskline;

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import org.json.JSONArray;
import org.json.JSONObject;

public class DeskDb extends SQLiteOpenHelper {
    public DeskDb(Context ctx) {
        super(ctx, "deskline.db", null, 1);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT, body TEXT)");
        db.execSQL("CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT, value TEXT)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int a, int b) {
    }

    public void seedFromSync(String json) throws Exception {
        JSONObject o = new JSONObject(json);
        SQLiteDatabase db = getWritableDatabase();
        db.delete("tickets", null, null);
        db.delete("credentials", null, null);
        JSONArray t = o.getJSONArray("tickets");
        for (int i = 0; i < t.length(); i++) {
            JSONObject it = t.getJSONObject(i);
            ContentValues cv = new ContentValues();
            cv.put("subject", it.getString("subject"));
            cv.put("body", it.getString("body"));
            db.insert("tickets", null, cv);
        }
        JSONObject note = o.getJSONObject("internal");
        ContentValues cv = new ContentValues();
        cv.put("label", note.getString("label"));
        cv.put("value", note.getString("value"));
        db.insert("credentials", null, cv);
        db.close();
    }
}
