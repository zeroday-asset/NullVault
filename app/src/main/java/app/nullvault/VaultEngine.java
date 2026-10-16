package app.nullvault;

import org.json.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Portable vault and import engine. Never logs secrets. */
public final class VaultEngine {
 public static final int ITERATIONS=600000;
 public static byte[] random(int n){byte[] b=new byte[n];new SecureRandom().nextBytes(b);return b;}
 public static byte[] derive(char[] password,byte[] salt)throws Exception{PBEKeySpec s=new PBEKeySpec(password,salt,ITERATIONS,256);try{return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(s).getEncoded();}finally{s.clearPassword();}}
 public static JSONObject seal(JSONArray entries,byte[] key,byte[] salt)throws Exception{
  byte[] iv=random(12),plain=entries.toString().getBytes(StandardCharsets.UTF_8);
  try{Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));c.updateAAD("NullVault:1".getBytes(StandardCharsets.UTF_8));JSONObject e=new JSONObject();e.put("version",1);e.put("iterations",ITERATIONS);e.put("salt",b64(salt));e.put("iv",b64(iv));e.put("data",b64(c.doFinal(plain)));return e;}finally{Arrays.fill(plain,(byte)0);}
 }
 public static byte[] salt(JSONObject e)throws Exception{
  if(e.getInt("version")!=1||e.getInt("iterations")!=ITERATIONS)throw new Exception("Unsupported encrypted vault version");
  byte[] s=Base64.getDecoder().decode(e.getString("salt"));if(s.length!=16)throw new Exception("Invalid salt");return s;
 }
 public static JSONArray open(JSONObject e,byte[] key)throws Exception{salt(e);byte[] iv=Base64.getDecoder().decode(e.getString("iv"));if(iv.length!=12)throw new Exception("Invalid IV");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));c.updateAAD("NullVault:1".getBytes(StandardCharsets.UTF_8));byte[] plain=c.doFinal(Base64.getDecoder().decode(e.getString("data")));try{return new JSONArray(new String(plain,StandardCharsets.UTF_8));}finally{Arrays.fill(plain,(byte)0);}}
 private static String b64(byte[] b){return Base64.getEncoder().encodeToString(b);}
 public static String clean(String s){return s.replaceAll("[\\s=-]","").toUpperCase(Locale.ROOT);}
 public static byte[] base32(String secret)throws Exception{
  String s=clean(secret);java.io.ByteArrayOutputStream out=new java.io.ByteArrayOutputStream();int buffer=0,bits=0;
  if(s.isEmpty())throw new Exception("Empty secret");for(char ch:s.toCharArray()){int v="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch);if(v<0)throw new Exception("Invalid Base32 secret");buffer=(buffer<<5)|v;bits+=5;if(bits>=8){bits-=8;out.write((buffer>>bits)&255);}}
  if(out.size()<1 || (bits>0 && (buffer&((1<<bits)-1))!=0) || s.length()%8==1 || s.length()%8==3 || s.length()%8==6)throw new Exception("Invalid Base32 encoding");return out.toByteArray();
 }
 public static String algorithm(String a)throws Exception{String n=a.toUpperCase(Locale.ROOT).replace("-","");if(!Arrays.asList("SHA1","SHA256","SHA512").contains(n))throw new Exception("Unsupported OTP algorithm: "+a);return n;}
 public static void validate(JSONObject e)throws Exception{
  if(e.optString("title").trim().isEmpty())throw new Exception("Entry needs a name");
  if(!e.optString("totp").isEmpty()){byte[] b=base32(e.getString("totp"));Arrays.fill(b,(byte)0);algorithm(e.optString("algorithm","SHA1"));int d=e.optInt("digits",6),p=e.optInt("period",30);if(d<6||d>8||p<1||p>300)throw new Exception("Unsupported OTP digits or period");}
 }
 public static String code(JSONObject e,long seconds)throws Exception{
  validate(e);int digits=e.optInt("digits",6),period=e.optInt("period",30);byte[] bytes=base32(e.getString("totp"));
  try{Mac mac=Mac.getInstance("Hmac"+algorithm(e.optString("algorithm","SHA1")));mac.init(new SecretKeySpec(bytes,mac.getAlgorithm()));byte[] h=mac.doFinal(ByteBuffer.allocate(8).putLong(seconds/period).array());int o=h[h.length-1]&15;int n=((h[o]&127)<<24)|((h[o+1]&255)<<16)|((h[o+2]&255)<<8)|(h[o+3]&255);int divisor=1;for(int i=0;i<digits;i++)divisor*=10;return String.format(Locale.ROOT,"%0"+digits+"d",n%divisor);}finally{Arrays.fill(bytes,(byte)0);}
 }
 public static JSONObject fromUri(String value)throws Exception{
  URI uri=new URI(value.trim());if(!"otpauth".equalsIgnoreCase(uri.getScheme())||!"totp".equalsIgnoreCase(uri.getHost()))throw new Exception("Only otpauth://totp links are supported in this build");
  Map<String,String> query=new HashMap<>();for(String pair:Objects.toString(uri.getRawQuery(),"").split("&")){String[] parts=pair.split("=",2);if(parts.length==2)query.put(URLDecoder.decode(parts[0],"UTF-8"),URLDecoder.decode(parts[1],"UTF-8"));}
  String label=URLDecoder.decode(Objects.toString(uri.getRawPath(),"").replaceFirst("^/",""),"UTF-8"),issuer=query.getOrDefault("issuer",label.contains(":")?label.substring(0,label.indexOf(':')):""),account=label.contains(":")?label.substring(label.indexOf(':')+1):label;
  if(query.getOrDefault("secret", "").isEmpty())throw new Exception("The otpauth link needs a secret");
  JSONObject e=new JSONObject();e.put("title",issuer.isEmpty()?account:issuer);e.put("username",account);e.put("totp",clean(query.getOrDefault("secret","")));e.put("algorithm",algorithm(query.getOrDefault("algorithm","SHA1")));e.put("digits",Integer.parseInt(query.getOrDefault("digits","6")));e.put("period",Integer.parseInt(query.getOrDefault("period","30")));validate(e);return e;
 }
 public static JSONArray parseImport(String source)throws Exception{
  String text=source.trim();if(text.startsWith("\ufeff"))text=text.substring(1).trim();JSONArray out=new JSONArray();
  if(text.startsWith("otpauth://")){for(String line:text.split("\\r?\\n")){if(!line.trim().isEmpty())out.put(fromUri(line));}return out;}
  if(text.startsWith("[")){JSONArray a=new JSONArray(text);for(int i=0;i<a.length();i++){JSONObject e=a.getJSONObject(i);validate(e);out.put(e);}return out;}
  JSONObject root=new JSONObject(text);
  if(root.optBoolean("encrypted",false)||root.opt("db") instanceof String)throw new Exception("Encrypted Aegis/Bitwarden exports are not supported yet. Use their unencrypted JSON export locally, or a NullVault encrypted backup.");
  JSONObject db=root.optJSONObject("db");if(db==null)db=root;
  if(db.has("entries")){
   JSONArray a=db.getJSONArray("entries");for(int i=0;i<a.length();i++){JSONObject item=a.getJSONObject(i);if(item.has("info")){if(!"totp".equalsIgnoreCase(item.optString("type")))throw new Exception("This file contains an unsupported OTP type; nothing was imported.");JSONObject info=item.getJSONObject("info"),e=new JSONObject();e.put("title",item.optString("issuer").isEmpty()?item.optString("name"):item.optString("issuer"));e.put("username",item.optString("name"));e.put("totp",clean(info.getString("secret")));e.put("algorithm",algorithm(info.optString("algo","SHA1")));e.put("digits",info.optInt("digits",6));e.put("period",info.optInt("period",30));validate(e);out.put(e);}else{validate(item);out.put(item);}}return out;
  }
  if(root.has("items")){
   JSONArray items=root.getJSONArray("items");
   for(int i=0;i<items.length();i++){
    JSONObject item=items.getJSONObject(i),e=new JSONObject();
    e.put("title",item.optString("name", "Imported item").trim().isEmpty()?"Imported item":item.optString("name"));
    e.put("notes",item.optString("notes", ""));e.put("sourceBitwarden",item);
    JSONObject login=item.optJSONObject("login");
    if(login!=null){
     e.put("username",login.optString("username", ""));e.put("password",login.optString("password", ""));
     String otp=login.optString("totp", "").trim();
     if(!otp.isEmpty()){
      try{
       JSONObject auth=otp.regionMatches(true,0,"otpauth://",0,10)?fromUri(otp):new JSONObject().put("title",e.getString("title")).put("totp",clean(otp));
       validate(auth);for(String k:Arrays.asList("totp","algorithm","digits","period"))if(auth.has(k))e.put(k,auth.get(k));
      }catch(Exception unsupported){
       e.put("unsupportedOtp",login.optString("totp"));
       e.put("importWarning","Authenticator value preserved, but this format cannot generate codes yet. Password and notes imported normally.");
      }
     }
     JSONArray uris=login.optJSONArray("uris");if(uris!=null&&uris.length()>0)e.put("url",uris.getJSONObject(0).optString("uri", ""));
    }else if(item.optInt("type")!=2){
     e.put("importWarning","This Bitwarden item type is preserved in the encrypted backup. Structured card/identity editing is not available yet.");
    }
    if(item.has("deletedDate")&&!item.isNull("deletedDate"))e.put("importWarning","Archived/deleted Bitwarden item preserved. Review before use.");
    validate(e);out.put(e);
   }return out;
  }
  throw new Exception("Unrecognized format. Choose Aegis JSON, Bitwarden vault JSON, otpauth text, or a NullVault backup.");
 }
 public static JSONArray merge(JSONArray current,JSONArray incoming)throws Exception{
  JSONArray out=new JSONArray(current.toString());for(int i=0;i<incoming.length();i++){JSONObject e=incoming.getJSONObject(i);validate(e);boolean duplicate=false;for(int j=0;j<out.length();j++){JSONObject old=out.getJSONObject(j);if(old.optString("title").equals(e.optString("title"))&&old.optString("username").equals(e.optString("username"))&&old.optString("password").equals(e.optString("password"))&&clean(old.optString("totp")).equals(clean(e.optString("totp")))&&old.optInt("period",30)==e.optInt("period",30)&&old.optInt("digits",6)==e.optInt("digits",6)&&old.optString("algorithm","SHA1").equals(e.optString("algorithm","SHA1"))&&old.optString("notes").equals(e.optString("notes"))&&old.optString("url").equals(e.optString("url"))&&old.optString("unsupportedOtp").equals(e.optString("unsupportedOtp"))&&Objects.equals(Objects.toString(old.opt("sourceBitwarden"),""),Objects.toString(e.opt("sourceBitwarden"),""))){duplicate=true;break;}}if(!duplicate){JSONObject copy=new JSONObject(e.toString());copy.put("id",UUID.randomUUID().toString());out.put(copy);}}return out;
 }
}
