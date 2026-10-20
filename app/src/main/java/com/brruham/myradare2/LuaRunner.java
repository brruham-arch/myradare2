package com.brruham.myradare2;

import java.io.*;
import java.util.Iterator;
import org.json.*;
import org.luaj.vm2.*;
import org.luaj.vm2.compiler.LuaC;
import org.luaj.vm2.lib.*;

public class LuaRunner {
  public interface Host {
    void log(String s);
    void progress(int pct);
    String r2(String cmd) throws IOException;
    File outDir();
  }

  final Host h;
  volatile boolean stop;

  LuaRunner(Host h) { this.h = h; }
  void stop() { stop = true; }
  void chk() { if (stop) throw new LuaError("dihentikan"); }

  static String join(Varargs a) {
    StringBuilder sb = new StringBuilder();
    for (int i = 1; i <= a.narg(); i++) { if (i > 1) sb.append('\t'); sb.append(a.arg(i).tojstring()); }
    return sb.toString();
  }

  static LuaValue conv(Object o) {
    if (o == null || o == JSONObject.NULL) return LuaValue.NIL;
    if (o instanceof JSONObject) {
      JSONObject j = (JSONObject) o;
      LuaTable t = new LuaTable();
      Iterator<String> k = j.keys();
      while (k.hasNext()) { String key = k.next(); t.set(key, conv(j.opt(key))); }
      return t;
    }
    if (o instanceof JSONArray) {
      JSONArray a = (JSONArray) o;
      LuaTable t = new LuaTable();
      for (int i = 0; i < a.length(); i++) t.set(i + 1, conv(a.opt(i)));
      return t;
    }
    if (o instanceof Boolean) return LuaValue.valueOf((Boolean) o);
    if (o instanceof Integer) return LuaValue.valueOf((Integer) o);
    if (o instanceof Long) return LuaValue.valueOf((double) (Long) o);
    if (o instanceof Double) return LuaValue.valueOf((Double) o);
    return LuaValue.valueOf(o.toString());
  }

  void run(String code) {
    stop = false;
    Globals g = new Globals();
    g.load(new BaseLib());
    g.load(new Bit32Lib());
    g.load(new TableLib());
    g.load(new StringLib());
    g.load(new CoroutineLib());
    g.load(new MathLib());
    LoadState.install(g);
    LuaC.install(g);
    g.set("dofile", LuaValue.NIL);
    g.set("loadfile", LuaValue.NIL);

    VarArgFunction lg = new VarArgFunction() {
      public Varargs invoke(Varargs a) { h.log(join(a) + "\n"); return NONE; }
    };
    g.set("log", lg);
    g.set("print", lg);
    g.set("r2", new OneArgFunction() {
      public LuaValue call(LuaValue c) {
        chk();
        try { return LuaValue.valueOf(h.r2(c.checkjstring())); }
        catch (IOException e) { throw new LuaError(String.valueOf(e.getMessage())); }
      }
    });
    g.set("r2j", new OneArgFunction() {
      public LuaValue call(LuaValue c) {
        chk();
        try {
          String s = h.r2(c.checkjstring()).trim();
          int a = s.indexOf('['), b = s.indexOf('{');
          int i = (a < 0) ? b : (b < 0 ? a : Math.min(a, b));
          if (i < 0) return LuaValue.NIL;
          return conv(new JSONTokener(s.substring(i)).nextValue());
        } catch (IOException e) { throw new LuaError(String.valueOf(e.getMessage())); }
        catch (JSONException e) { throw new LuaError("json: " + e.getMessage()); }
      }
    });
    g.set("progress", new TwoArgFunction() {
      public LuaValue call(LuaValue a, LuaValue b) {
        chk();
        double t = b.todouble();
        h.progress(t > 0 ? (int) (a.todouble() * 100 / t) : 0);
        return LuaValue.NIL;
      }
    });
    g.set("hex", new OneArgFunction() {
      public LuaValue call(LuaValue a) { return LuaValue.valueOf("0x" + Long.toHexString((long) a.todouble())); }
    });
    g.set("save", new TwoArgFunction() {
      public LuaValue call(LuaValue n, LuaValue t) {
        try {
          File f = new File(h.outDir(), new File(n.checkjstring()).getName());
          try (FileOutputStream o = new FileOutputStream(f)) { o.write(t.checkjstring().getBytes("UTF-8")); }
          h.log("[save] " + f.getPath() + "\n");
        } catch (IOException e) { throw new LuaError(String.valueOf(e.getMessage())); }
        return LuaValue.NIL;
      }
    });

    try {
      g.load(code, "script").call();
      h.log("[lua selesai]\n");
    } catch (LuaError e) {
      h.log("[lua] " + e.getMessage() + "\n");
    } catch (Throwable t) {
      h.log("[lua error] " + t + "\n");
    }
  }
}
