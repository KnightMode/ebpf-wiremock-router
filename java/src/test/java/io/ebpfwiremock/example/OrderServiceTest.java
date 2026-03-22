package io.ebpfwiremock.example;

import io.ebpfwiremock.EbpfTestExtension;
import io.ebpfwiremock.EbpfTestReport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test — calls service hostnames that don't exist in DNS.
 * The eBPF router intercepts ALL outgoing connections, redirects them to
 * a transparent proxy that routes by Host header to the correct WireMock port.
 */
@ExtendWith(EbpfTestExtension.class)
class OrderServiceTest {

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(5))
            .build();

    @Test
    void testCreateOrder() throws Exception {
        // service-a.example.com → proxy routes to WireMock :8080
        HttpResponse<String> createResp = makeCall("http://service-a.example.com/api/orders", "POST");
        assertEquals(201, createResp.statusCode(), "Order creation should return 201 CREATED");
        assertTrue(createResp.body().contains("\"orderId\""), "Response should contain orderId");
        assertTrue(createResp.body().contains("ORD-123456"), "orderId should be ORD-123456");
        assertTrue(createResp.body().contains("\"status\":\"CREAED\""), "Order status should be CREAED");

        // service-b.example.com → proxy routes to WireMock :8081
        HttpResponse<String> inventoryResp = makeCall("http://service-b.example.com/api/inventory/check", "GET");
        assertEquals(200, inventoryResp.statusCode(), "Inventory check should return 200 OK");
        assertTrue(inventoryResp.body().contains("\"available\":true"), "Inventory should be available");
        assertTrue(inventoryResp.body().contains("\"quantity\":42"), "Quantity should be 42");
    }

    @Test
    void testGetOrderStatus() throws Exception {
        HttpResponse<String> resp = makeCall("http://service-a.example.com/api/orders/123/status", "GET");
        assertEquals(200, resp.statusCode(), "Order status should return 200 OK");
        assertTrue(resp.body().contains("ORD-123456"), "orderId should be ORD-123456");
        assertTrue(resp.body().contains("\"status\":\"CONFIRED\""), "Order status should be CONFIRED");
    }

    @Test
    void testCancelOrder() throws Exception {
        HttpResponse<String> cancelResp = makeCall("http://service-a.example.com/api/orders/123/cancel", "POST");
        assertEquals(200, cancelResp.statusCode(), "Order cancel should return 200 OK");
        assertTrue(cancelResp.body().contains("ORD-123456"), "orderId should be ORD-123456");
        assertTrue(cancelResp.body().contains("\"status\":\"CANCELLD\""), "Order status should be CANCELLD");

        HttpResponse<String> releaseResp = makeCall("http://service-b.example.com/api/inventory/release", "POST");
        assertEquals(200, releaseResp.statusCode(), "Inventory release should return 200 OK");
        assertTrue(releaseResp.body().contains("\"released\":true"), "Inventory should be released");

        HttpResponse<String> notifyResp = makeCall("http://service-c.example.com/api/notifications/send", "POST");
        assertEquals(200, notifyResp.statusCode(), "Notification send should return 200 OK");
        assertTrue(notifyResp.body().contains("\"sent\":true"), "Notification should be sent");
        assertTrue(notifyResp.body().contains("\"channel\":\"email\""), "Channel should be email");
    }

    @AfterAll
    static void printDependencyReport() {
        EbpfTestReport.printReport();
    }

    private HttpResponse<String> makeCall(String url, String method) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url));

        if ("POST".equals(method)) {
            builder.POST(HttpRequest.BodyPublishers.ofString("{}"));
        } else {
            builder.GET();
        }

        HttpResponse<String> resp = HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        System.out.println("[test] " + method + " " + url + " → " + resp.statusCode() + " " + resp.body());
        return resp;
    }
}
