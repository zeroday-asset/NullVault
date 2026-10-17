package app.nullvault;
import java.net.URI;
/** Accept only explicit app package links and normal web URLs; never arbitrary intents. */
public final class LinkTarget {
 public static String packageName(String value){try{URI u=new URI(value.trim());if(!"androidapp".equalsIgnoreCase(u.getScheme())||u.getRawUserInfo()!=null||u.getPort()!=-1||u.getRawQuery()!=null||u.getRawFragment()!=null||(u.getPath()!=null&&!u.getPath().isEmpty()&&!u.getPath().equals("/")))return null;String p=u.getHost();return p!=null&&p.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")?p:null;}catch(Exception e){return null;}}
 public static URI web(String value)throws Exception{URI u=new URI(value.trim());if(!("https".equalsIgnoreCase(u.getScheme())||"http".equalsIgnoreCase(u.getScheme()))||u.getHost()==null||u.getRawUserInfo()!=null)throw new Exception("Use an https:// website or androidapp://package.name link");return u;}
 public static String iconOrigin(String value)throws Exception{URI u=web(value);String host=u.getHost();if(host.equalsIgnoreCase("localhost")||host.indexOf(':')>=0||host.matches("[0-9.]+")||!host.contains(".")||host.endsWith(".local"))throw new Exception("No remote icon for local addresses");return new URI("https",null,host,-1,"/favicon.ico",null,null).toString();}
 public static void validate(String value)throws Exception{if(value.trim().isEmpty())return;if(packageName(value)!=null)return;web(value);}
}
