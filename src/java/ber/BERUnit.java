package ber;

import java.math.BigInteger; 
import java.nio.ByteBuffer;

public class BERUnit {
 public final byte header;
 public final byte[] length;
 public final byte[] value;
 public final byte[] bytes;
 
 public BERUnit (byte h, byte[] v) {
   header = h;
   value = v;
   int lsize = v.length;
   byte[] lt = (new BigInteger (Integer.toString(lsize))).toByteArray();
if (lsize > 127) {
     ByteBuffer lb = ByteBuffer.allocate(1 + lt.length);
     lb.put((byte) (lt.length | 0x80));
     lb.put(lt);
     length=lb.array();} else {
       length = lt;
     };
   ByteBuffer bf = ByteBuffer.allocate((1 + length.length) + v.length);
   bf.put(h);
   bf.put(length);
   bf.put(value);
   bytes = bf.array();
 }
 
 public BERUnit (byte[] b) {
  ByteBuffer berbuffer = ByteBuffer.allocate(b.length);
  berbuffer.put(b).rewind();
  header = berbuffer.get();
  berbuffer.mark();
  byte tl = berbuffer.get();
  int lv;
  if (0x80 == (0x80 & tl)) {
    int l = 1 + (int) (0x7f & tl);
    length = new byte[l];
    berbuffer.reset();
    berbuffer.get(length);
    byte[] ta = new byte[length.length - 1];
    berbuffer.reset();
    berbuffer.get();
    berbuffer.get(ta, 0, ta.length);
    lv = (new BigInteger(1, ta)).intValue();
  } else {
    length = new byte[]{tl};
    lv = (int) tl;
  }
  value = new byte[lv];
  berbuffer.get(value);
  bytes = (ByteBuffer.allocate((length.length + 1) + (value.length))).put(header).put(length).put(value).array();
 }
}
