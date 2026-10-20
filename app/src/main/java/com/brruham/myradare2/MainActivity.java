package com.brruham.myradare2;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.*;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.view.*;
import android.view.inputmethod.EditorInfo;
import android.widget.*;
import java.io.*;
import java.util.concurrent.*;
import java.util.zip.*;

public class MainActivity extends Activity {
  interface Op { void run() throws Exception; }

  static final int RQ_PICK = 1, RQ_SAVEBIN = 2, RQ_SAVELOG = 3;
  static final String SAMPLE =
      "-- jalankan 'Analisis aa' dulu\n" +
      "local pat = 'samp'\n" +
      "local strs = r2j('izj')\n" +
      "for i, s in ipairs(strs) do\n" +
      "  progress(i, #strs)\n" +
      "  if s.string and s.string:find(pat, 1, true) then\n" +
      "    for _, x in ipairs(r2j('axtj @ ' .. hex(s.vaddr))) do\n" +
      "      log(s.string .. ' <- ' .. tostring(x.fcn_name) .. ' @ ' .. hex(x.from))\n" +
      "    end\n" +
      "  end\n" +
      "end\n";

  final Handler ui = new Handler(Looper.getMainLooper());
  final ExecutorService ex = Executors.newSingleThreadExecutor();
  final StringBuilder logBuf = new StringBuilder();
  boolean logPending = false;
  TextView logTv, status, fileTv;
  ScrollView logSv;
  ProgressBar bar;
  EditText arg, con, lua;
  View pBtn, pCon, pLua;
  R2 r2;
  LuaRunner luaRunner;
  File work, current;
  volatile String proj = "p", stage = "";
  volatile boolean busy = false, cancelled = false;
  volatile long t0;

  final Runnable tick = new Runnable() {
    public void run() {
      status.setText(busy ? "⏳ " + stage + " — " + (SystemClock.elapsedRealtime() - t0) / 1000 + " dtk" : "siap");
      ui.postDelayed(this, 500);
    }
  };

  @Override protected void onCreate(Bundle b) {
    super.onCreate(b);
    work = new File(getFilesDir(), "work");
    work.mkdirs();
    r2 = new R2(getFilesDir(), getCacheDir(), s -> log(s));
    luaRunner = new LuaRunner(new LuaRunner.Host() {
      public void log(String s) { MainActivity.this.log(s); }
      public void progress(int p) { setProg(p); }
      public String r2(String c) throws IOException { return MainActivity.this.r2.cmd(c, false, true); }
      public File outDir() {
        File base = getExternalFilesDir(null);
        File d = new File(base != null ? base : getFilesDir(), "out");
        d.mkdirs();
        return d;
      }
    });
    buildUi();
    ui.post(tick);
    task("Menyiapkan r2", () -> {
      extract();
      String last = getSharedPreferences("s", 0).getString("last", null);
      if (last != null && new File(last).exists()) openFile(new File(last));
    });
  }

  // ---------- UI ----------
  int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density); }

  Button btn(String t, View.OnClickListener l) {
    Button b = new Button(this);
    b.setText(t); b.setAllCaps(false); b.setTextSize(12);
    b.setMinimumHeight(dp(40)); b.setMinHeight(dp(40));
    b.setPadding(dp(2), 0, dp(2), 0);
    b.setOnClickListener(l);
    return b;
  }

  LinearLayout row() {
    LinearLayout r = new LinearLayout(this);
    r.setOrientation(LinearLayout.HORIZONTAL);
    return r;
  }

  LinearLayout.LayoutParams w1() { return new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f); }

  void buildUi() {
    LinearLayout root = new LinearLayout(this);
    root.setOrientation(LinearLayout.VERTICAL);
    root.setPadding(dp(6), dp(6), dp(6), dp(6));

    LinearLayout r1 = row();
    r1.setGravity(Gravity.CENTER_VERTICAL);
    r1.addView(btn("Pilih .so", v -> {
      Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
      i.addCategory(Intent.CATEGORY_OPENABLE);
      i.setType("*/*");
      startActivityForResult(i, RQ_PICK);
    }));
    fileTv = new TextView(this);
    fileTv.setText("(belum ada file)");
    fileTv.setPadding(dp(8), 0, 0, 0);
    r1.addView(fileTv, w1());
    root.addView(r1);

    status = new TextView(this);
    status.setTextSize(12);
    root.addView(status);
    bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
    bar.setMax(100);
    root.addView(bar, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(8)));

    LinearLayout tabs = row();
    tabs.addView(btn("Tombol", v -> show(0)), w1());
    tabs.addView(btn("Konsol", v -> show(1)), w1());
    tabs.addView(btn("Lua", v -> show(2)), w1());
    tabs.addView(btn("Batal", v -> cancel()), w1());
    root.addView(tabs);

    FrameLayout fl = new FrameLayout(this);

    // panel tombol
    ScrollView sv = new ScrollView(this);
    LinearLayout col = new LinearLayout(this);
    col.setOrientation(LinearLayout.VERTICAL);
    arg = new EditText(this);
    arg.setHint("alamat / pola (0x1234, teks, hex)");
    arg.setSingleLine();
    col.addView(arg);
    String[][] B = {
        {"Info", "iI"}, {"Sections", "iS"}, {"Symbols", "is"}, {"Imports", "ii"},
        {"Exports", "iE"}, {"Strings", "iz"}, {"Entry", "ie"}, {"Fungsi", "afl"},
        {"Analisis aa", "aa;aflc"}, {"Deep aaa", "aaa;aflc"}, {"Disasm", "pd 40 @ %"}, {"Hex", "px 256 @ %"},
        {"Cari teks", "/ %"}, {"Cari hex", "/x %"}, {"Xref ke", "axt @ %"}, {"Fungsi di", "af @ %;pdf @ %"},
        {"Simpan proj", null}, {"Simpan As", null}, {"Ekspor log", null}, {"Bersih log", null}};
    LinearLayout cur = null;
    for (int i = 0; i < B.length; i++) {
      if (i % 4 == 0) { cur = row(); col.addView(cur); }
      final String label = B[i][0], tpl = B[i][1];
      cur.addView(btn(label, v -> onTool(label, tpl)), w1());
    }
    sv.addView(col);
    pBtn = sv;
    fl.addView(sv, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(200)));

    // panel konsol
    LinearLayout pc = new LinearLayout(this);
    pc.setOrientation(LinearLayout.VERTICAL);
    con = new EditText(this);
    con.setHint("perintah r2, mis: afl~samp");
    con.setSingleLine();
    con.setTypeface(Typeface.MONOSPACE);
    con.setImeOptions(EditorInfo.IME_ACTION_SEND);
    con.setOnEditorActionListener((tv, id, ev) -> { runCon(); return true; });
    pc.addView(con);
    pc.addView(btn("Jalankan", v -> runCon()));
    pCon = pc;
    pc.setVisibility(View.GONE);
    fl.addView(pc, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(200)));

    // panel lua
    LinearLayout pl = new LinearLayout(this);
    pl.setOrientation(LinearLayout.VERTICAL);
    lua = new EditText(this);
    lua.setTypeface(Typeface.MONOSPACE);
    lua.setTextSize(12);
    lua.setGravity(Gravity.TOP | Gravity.START);
    lua.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
    lua.setText(getSharedPreferences("s", 0).getString("lua", SAMPLE));
    pl.addView(lua, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(150)));
    LinearLayout lr = row();
    lr.addView(btn("Run", v -> runLua()), w1());
    lr.addView(btn("Stop", v -> cancel()), w1());
    lr.addView(btn("Contoh", v -> lua.setText(SAMPLE)), w1());
    pl.addView(lr);
    pLua = pl;
    pl.setVisibility(View.GONE);
    fl.addView(pl, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(200)));

    root.addView(fl);

    logSv = new ScrollView(this);
    logTv = new TextView(this);
    logTv.setTypeface(Typeface.MONOSPACE);
    logTv.setTextSize(11);
    logTv.setTextIsSelectable(true);
    logSv.addView(logTv);
    root.addView(logSv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

    setContentView(root);
  }

  void show(int i) {
    pBtn.setVisibility(i == 0 ? View.VISIBLE : View.GONE);
    pCon.setVisibility(i == 1 ? View.VISIBLE : View.GONE);
    pLua.setVisibility(i == 2 ? View.VISIBLE : View.GONE);
  }

  void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }

  void onTool(String label, String tpl) {
    if (tpl != null) {
      String a = arg.getText().toString().trim();
      if (tpl.contains("%") && a.isEmpty()) { toast("Isi kolom alamat/pola"); return; }
      runCmd(tpl.replace("%", a));
      return;
    }
    switch (label) {
      case "Simpan proj": runCmd("Ps " + proj); break;
      case "Simpan As": {
        if (current == null) { toast("Belum ada file"); return; }
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("*/*");
        i.putExtra(Intent.EXTRA_TITLE, current.getName());
        startActivityForResult(i, RQ_SAVEBIN);
        break;
      }
      case "Ekspor log": {
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TITLE, "r2log.txt");
        startActivityForResult(i, RQ_SAVELOG);
        break;
      }
      case "Bersih log":
        synchronized (logBuf) { logBuf.setLength(0); }
        logTv.setText("");
        break;
    }
  }

  void runCon() {
    String c = con.getText().toString().trim();
    if (c.isEmpty()) return;
    runCmd(c);
    con.setText("");
  }

  void runLua() {
    final String code = lua.getText().toString();
    getSharedPreferences("s", 0).edit().putString("lua", code).apply();
    task("Lua", () -> { ensure(); luaRunner.run(code); });
  }

  // ---------- log & progress ----------
  void log(String s) {
    synchronized (logBuf) {
      logBuf.append(s);
      int over = logBuf.length() - 200000;
      if (over > 0) logBuf.delete(0, over);
      if (logPending) return;
      logPending = true;
    }
    ui.postDelayed(() -> {
      String t;
      synchronized (logBuf) { t = logBuf.toString(); logPending = false; }
      logTv.setText(t);
      logSv.post(() -> logSv.scrollTo(0, logTv.getHeight()));
    }, 200);
  }

  void setProg(int p) {
    ui.post(() -> {
      if (p < 0) bar.setIndeterminate(true);
      else { bar.setIndeterminate(false); bar.setProgress(p); }
    });
  }

  // ---------- tugas ----------
  void task(String name, Op op) {
    ex.submit(() -> {
      busy = true; stage = name; t0 = SystemClock.elapsedRealtime(); setProg(-1);
      log("\n▶ " + name + "\n");
      try {
        op.run();
        log("\n✔ selesai " + (SystemClock.elapsedRealtime() - t0) / 1000 + " dtk\n");
      } catch (Throwable e) {
        log("\n✖ " + (cancelled ? "dibatalkan" : String.valueOf(e.getMessage())) + "\n");
      }
      if (cancelled) {
        cancelled = false;
        try { if (current != null) openFile(current); }
        catch (Throwable t) { log("gagal buka ulang: " + t.getMessage() + "\n"); }
      }
      busy = false;
      setProg(0);
    });
  }

  void cancel() {
    if (!busy) { toast("Tidak ada proses"); return; }
    cancelled = true;
    luaRunner.stop();
    r2.kill();
    log("\n⏹ membatalkan...\n");
  }

  void ensure() throws Exception {
    if (current == null) throw new Exception("pilih file dulu");
    if (!r2.alive()) openFile(current);
  }

  void runCmd(String c) {
    task(c.length() > 40 ? c.substring(0, 40) + "…" : c, () -> { ensure(); r2.cmd(c, true, false); log("\n"); });
  }

  void openFile(File f) throws Exception {
    current = f;
    proj = f.getName().replaceAll("[^A-Za-z0-9_]", "_");
    log("Membuka " + f.getName() + "\n");
    r2.open(f);
    String pl = r2.cmd("Pl", false, true);
    if (pl.contains(proj)) { log("Memuat project " + proj + "\n"); r2.cmd("Po " + proj, true, false); }
    getSharedPreferences("s", 0).edit().putString("last", f.getPath()).apply();
    ui.post(() -> fileTv.setText(f.getName() + " (" + f.length() / 1024 + " KB)"));
  }

  // ---------- ekstrak r2 ----------
  static String readStr(File f) {
    try (BufferedReader r = new BufferedReader(new FileReader(f))) { return r.readLine(); }
    catch (Exception e) { return ""; }
  }
  static void writeStr(File f, String s) throws IOException { try (FileWriter w = new FileWriter(f)) { w.write(s); } }
  static void delTree(File f) {
    File[] k = f.listFiles();
    if (k != null) for (File c : k) delTree(c);
    f.delete();
  }

  void extract() throws Exception {
    File fd = getFilesDir();
    File mark = new File(fd, "r2.ok");
    long len;
    try (AssetFileDescriptor a = getAssets().openFd("r2.zip")) { len = a.getLength(); }
    String sig = String.valueOf(len);
    if (new File(fd, "r2/bin/radare2").exists() && sig.equals(readStr(mark))) return;
    log("Mengekstrak radare2 (sekali saja)...\n");
    delTree(new File(fd, "r2"));
    final long[] cnt = {0};
    InputStream in = new FilterInputStream(getAssets().open("r2.zip")) {
      public int read(byte[] b, int o, int l) throws IOException {
        int n = super.read(b, o, l);
        if (n > 0) cnt[0] += n;
        return n;
      }
    };
    String base = fd.getCanonicalPath() + "/";
    try (ZipInputStream z = new ZipInputStream(in)) {
      ZipEntry e;
      byte[] buf = new byte[65536];
      while ((e = z.getNextEntry()) != null) {
        File f = new File(fd, e.getName());
        if (!f.getCanonicalPath().startsWith(base)) continue;
        if (e.isDirectory()) { f.mkdirs(); continue; }
        f.getParentFile().mkdirs();
        try (FileOutputStream o = new FileOutputStream(f)) {
          int n;
          while ((n = z.read(buf)) > 0) o.write(buf, 0, n);
        }
        f.setExecutable(true, false);
        f.setReadable(true, false);
        setProg((int) (cnt[0] * 100 / Math.max(1, len)));
      }
    }
    writeStr(mark, sig);
  }

  // ---------- file ----------
  String nameOf(Uri u) {
    try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
      if (c != null && c.moveToFirst()) {
        int i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
        if (i >= 0) return c.getString(i);
      }
    }
    return "file.so";
  }

  long sizeOf(Uri u) {
    try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
      if (c != null && c.moveToFirst()) {
        int i = c.getColumnIndex(OpenableColumns.SIZE);
        if (i >= 0) return c.getLong(i);
      }
    }
    return -1;
  }

  @Override protected void onActivityResult(int rq, int rc, Intent d) {
    super.onActivityResult(rq, rc, d);
    if (rc != RESULT_OK || d == null || d.getData() == null) return;
    final Uri u = d.getData();
    if (rq == RQ_PICK) {
      task("Salin file", () -> {
        r2.kill();
        String nm = nameOf(u).replaceAll("[^A-Za-z0-9._-]", "_");
        long sz = sizeOf(u);
        File out = new File(work, nm);
        try (InputStream i = getContentResolver().openInputStream(u); FileOutputStream o = new FileOutputStream(out)) {
          byte[] b = new byte[65536];
          long c = 0;
          int n;
          while ((n = i.read(b)) > 0) {
            o.write(b, 0, n);
            c += n;
            if (sz > 0) setProg((int) (c * 100 / sz));
          }
        }
        openFile(out);
      });
    } else if (rq == RQ_SAVEBIN) {
      task("Simpan As", () -> {
        try (InputStream i = new FileInputStream(current); OutputStream o = getContentResolver().openOutputStream(u)) {
          byte[] b = new byte[65536];
          int n;
          while ((n = i.read(b)) > 0) o.write(b, 0, n);
        }
      });
    } else if (rq == RQ_SAVELOG) {
      task("Ekspor log", () -> {
        String t;
        synchronized (logBuf) { t = logBuf.toString(); }
        try (OutputStream o = getContentResolver().openOutputStream(u)) { o.write(t.getBytes("UTF-8")); }
      });
    }
  }
}
