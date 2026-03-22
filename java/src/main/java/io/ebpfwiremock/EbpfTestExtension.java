package io.ebpfwiremock;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * JUnit 5 extension that notifies the eBPF router controller about test lifecycle events.
 *
 * Usage:
 *   @ExtendWith(EbpfTestExtension.class)
 *   class OrderServiceTest { ... }
 *
 * Or register globally in META-INF/services/org.junit.jupiter.api.extension.Extension
 *
 * The extension sends the current test's fully qualified name + method to the Go controller
 * via a lightweight HTTP API. The controller correlates all network connections captured
 * by eBPF during that test window with the test metadata.
 */
public class EbpfTestExtension implements BeforeEachCallback, AfterEachCallback {

    private static final String CONTROLLER_URL =
            System.getProperty("ebpf.controller.url", "http://localhost:9667");

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(500))
            .build();

    @Override
    public void beforeEach(ExtensionContext context) {
        String testClass = context.getRequiredTestClass().getName();
        String testMethod = context.getRequiredTestMethod().getName();
        String displayName = context.getDisplayName();

        // Get the OS thread ID — eBPF will see this TID on connect() calls
        long tid = ProcessHandle.current().pid(); // JVM main PID
        long threadId = Thread.currentThread().threadId();

        String json = String.format(
                """
                {
                    "event": "test_start",
                    "test_class": "%s",
                    "test_method": "%s",
                    "display_name": "%s",
                    "pid": %d,
                    "java_thread_id": %d,
                    "timestamp": %d
                }
                """,
                testClass, testMethod, displayName, tid, threadId, System.currentTimeMillis()
        );

        sendEvent(json);
    }

    @Override
    public void afterEach(ExtensionContext context) {
        String testClass = context.getRequiredTestClass().getName();
        String testMethod = context.getRequiredTestMethod().getName();
        boolean passed = context.getExecutionException().isEmpty();

        String json = String.format(
                """
                {
                    "event": "test_end",
                    "test_class": "%s",
                    "test_method": "%s",
                    "passed": %b,
                    "pid": %d,
                    "timestamp": %d
                }
                """,
                testClass, testMethod, passed,
                ProcessHandle.current().pid(), System.currentTimeMillis()
        );

        sendEvent(json);
    }

    private void sendEvent(String json) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(CONTROLLER_URL + "/api/test-event"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            CLIENT.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (IOException | InterruptedException e) {
            // Non-fatal: if the controller isn't running, tests still work normally
            System.err.println("[ebpf-wiremock] controller not reachable: " + e.getMessage());
        }
    }
}
