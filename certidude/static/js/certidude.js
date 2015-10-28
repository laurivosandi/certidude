$(document).ready(function() {
    console.info("Opening EventSource from:", window.location.href);

    var source = new EventSource(window.location.href);

    source.onmessage = function(event) {
        console.log("Received server-sent event:", event);
    }

    source.addEventListener("request_deleted", function(e) {
        console.log("Removing deleted request #" + e.data);
        $("#request_" + e.data).remove();
    });

    source.addEventListener("request_submitted", function(e) {
        console.log("Request submitted:", e.data);
    });

    source.addEventListener("request_signed", function(e) {
        console.log("Request signed:", e.data);
        $("#request_" + e.data).remove();
        // TODO: Insert <li> to signed certs list
    });

    source.addEventListener("certificate_revoked", function(e) {
        console.log("Removing revoked certificate #" + e.data);
        $("#certificate_" + e.data).remove();
    });

});
