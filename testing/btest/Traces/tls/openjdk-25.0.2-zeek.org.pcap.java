// OpenJDK 25 sends a client hello message that contains a
// signature_algorithms_cert extension
//
// Java file created by Claude code

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TlsTest {
    public static void main(String[] args) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://zeek.org:443"))
                .build();
        client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
