import java.io.OutputStream;
import java.io.*;
import java.util.List;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.StringTokenizer;
import org.apache.commons.codec.binary.Base64;

public class App {
    private static final Logger log = LogManager.getLogger("app");

    public static void main(String[] args) throws Exception {
        try {
                HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
                server.createContext("/test", new MyHandler());
                server.setExecutor(null); // creates a default executor
                log.debug("starting web server on port {}", 8000);
                server.start();
        } catch (Exception e) {
                e.printStackTrace();
        }
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String method = t.getRequestMethod();
            log.info("Request Method: {}", method);

            String query = t.getRequestURI().getQuery();
            log.info("Request Query: {}", query);

            String userAgent = null;
            final List<String> strings = t.getRequestHeaders().get("User-Agent");
            if (strings.size() > 0) {
              userAgent = strings.get(0);
            }
            log.info("User-Agent: {}", userAgent);

            if(t.getRequestHeaders().get("Authorization") != null) {

                final List<String> auth_strings = t.getRequestHeaders().get("Authorization");

                if (auth_strings.size() > 0) {
                    String authheader = auth_strings.get(0);                  
                    StringTokenizer st = new StringTokenizer(authheader);
                    if (st.hasMoreTokens()) {
                        String basic = st.nextToken();
                        log.info(basic);
                        if (basic.equalsIgnoreCase("Basic")) {
                            try {
                                String credentials = new String(Base64.decodeBase64(st.nextToken()), "UTF-8");                                                                                                                                                                                                                                                                 
                                log.info("Credentials: " + credentials);                                                                                                                                                                                                                                                                                                      
                                int p = credentials.indexOf(":");                                                                                                                                                                                                                                                                                                              
                                if (p != -1) {                                                                                                                                                                                                                                                                                                                                 
                                    String login = credentials.substring(0, p).trim();                                                                                                                                                                                                                                                                                         
                                    String password = credentials.substring(p + 1).trim();                                                                                                                                                                                                                                                                                     
                                    log.info("password: " + password);                                                                                                                                                                                                                                                                                                      
                                    log.info("user: " + login);                                                                                                                                                                                                                                                                                                             
                                } else {                                                                                                                                                                                                                                                                                                                                       
                                    log.info("invalid basic auth");                                                                                                                                                                                                                                                                                                       
                                }                                                                                                                                                                                                                                                                                                                                              
                            } catch (UnsupportedEncodingException e) {                                                                                                                                                                                                                                                                                                         
                                log.info("Couldn't retrieve authentication", e);                                                                                                                                                                                                                                                                                        
                            }
                        }                                                                                                                                                                                                                                                                                                              
                    }
                }
            }

            StringBuilder sb = new StringBuilder();
            InputStream ios = t.getRequestBody();
            int i;
            while ((i = ios.read()) != -1) {
                sb.append((char) i);
            }
            log.info("Request Body: {}", sb);

            String response = "This is the response";
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
