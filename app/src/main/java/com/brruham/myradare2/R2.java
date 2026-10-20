package com.brruham.myradare2;

import java.io.*;
import java.util.*;

public class R2 {
  public interface Sink { void out(String s); }
  final File prefix, home, cache;
  final Sink sink;
  volatile Process p;
  OutputStream os;
  InputStream is;

  R2(File files, File cache, Sink s) {
    prefix = new File(files, "r2");
    home = new File(files, "home");
    this.cache = cache;
    sink = s;
  }

  boolean alive() { Process q = p; return q != null && q.isAlive(); }
  void kill() { Process q = p; if (q != null) q.destroyForcibly(); }

  synchronized void open(File f) throws IOException {
    kill();
    home.mkdirs();
    File bin = new File(prefix, "bin/radare2");
    if (!bin.exists()) throw new IOException("radare2 tidak ada: " + bin);
    ProcessBuilder pb = new ProcessBuilder(bin.getPath(), "-q0", "-w", f.getPath());
    pb.redirectErrorStream(true);
    Map<String, String> e = pb.environment();
    e.put("HOME", home.getPath());
    e.put("TMPDIR", cache.getPath());
    e.put("LD_LIBRARY_PATH", new File(prefix, "lib").getPath());
    e.put("TERM", "dumb");
    p = pb.start();
    os = p.getOutputStream();
    is = p.getInputStream();
    read(null, true);
    cmd("e scr.color=0;e scr.utf8=false;e scr.interactive=false;e asm.demangle=false", false, false);
  }

  private void read(StringBuilder sb, boolean echo) throws IOException {
    byte[] b = new byte[16384];
    while (true) {
      int n = is.read(b);
      if (n < 0) throw new IOException("r2 berhenti");
      int z = -1;
      for (int i = 0; i < n; i++) if (b[i] == 0) { z = i; break; }
      int len = z < 0 ? n : z;
      if (len > 0) {
        String s = new String(b, 0, len, "UTF-8");
        if (sb != null) sb.append(s);
        if (echo && sink != null) sink.out(s);
      }
      if (z >= 0) return;
    }
  }

  synchronized String cmd(String c, boolean echo, boolean collect) throws IOException {
    if (p == null) throw new IOException("sesi belum dibuka");
    os.write((c + "\n").getBytes("UTF-8"));
    os.flush();
    StringBuilder sb = collect ? new StringBuilder() : null;
    read(sb, echo);
    return collect ? sb.toString() : "";
  }
}
