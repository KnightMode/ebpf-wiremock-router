package io.ebpfwiremock;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Utility to fetch the captured test-to-service dependency report
 * from the eBPF controller after all tests complete.
 *
 * Usage in a test suite teardown or CI script:
 *   EbpfTestReport.printReport();
 *   EbpfTestReport.saveReport("build/test-dependencies.json");
 */
public class EbpfTestReport {

    private static final String CONTROLLER_URL =
            System.getProperty("ebpf.controller.url", "http://localhost:9667");

    /**
     * Fetch and print the full dependency report showing which tests called which services.
     */
    public static String getReport() throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(CONTROLLER_URL + "/api/report"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public static void printReport() {
        try {
            String report = getReport();
            System.out.println("\n=== eBPF WireMock Test Dependency Report ===\n");
            System.out.println(report);
        } catch (Exception e) {
            System.err.println("[ebpf-wiremock] could not fetch report: " + e.getMessage());
        }
    }
}
