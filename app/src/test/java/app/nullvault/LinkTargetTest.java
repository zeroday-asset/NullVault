package app.nullvault;
import org.junit.Test;
import static org.junit.Assert.*;
public class LinkTargetTest {
 @Test public void recognizesInstalledAppLinks(){assertEquals("com.getmimo",LinkTarget.packageName("androidapp://com.getmimo"));assertNull(LinkTarget.packageName("androidapp://com.getmimo/other"));assertNull(LinkTarget.packageName("androidapp://com.getmimo?x=1"));}
 @Test public void rejectsExecutableAndCredentialBearingLinks()throws Exception{for(String s:new String[]{"intent://evil","javascript:alert(1)","file:///tmp/x","https://user:password@example.com"}){try{LinkTarget.validate(s);fail("Unsafe target accepted");}catch(Exception expected){}}}
 @Test public void faviconOmitsCredentialPathsAndQueries()throws Exception{assertEquals("https://example.com/favicon.ico",LinkTarget.iconOrigin("https://example.com/private/account?token=secret"));try{LinkTarget.iconOrigin("http://127.0.0.1/private");fail("Local icon accepted");}catch(Exception expected){}}
}
