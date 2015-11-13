$(document).ready(function() {
    console.info("Loading CA, to debug: curl " + window.location.href + " --negotiate -u : -H 'Accept: application/json'");

    $.ajax({
        method: "GET",
        url: "/api/ca/",
        dataType: "json",
        success: function(session, status, xhr) {
            console.info("Loaded CA list:", session);

            if (!session.authorities) {
                alert("No certificate authorities to manage! Have you created one yet?");
                return;
            }

            $.ajax({
                method: "GET",
                url: "/api/ca/" + session.authorities[0],
                dataType: "json",
                success: function(authority, status, xhr) {
                    console.info("Got CA:", authority);

                    console.info("Opening EventSource from:", "/api/ca/" + authority.slug);

                    var source = new EventSource("/api/" + authority.slug);

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

                    $("#container").html(nunjucks.render('authority.html', { authority: authority, session: session }));

                    $.ajax({
                        method: "GET",
                        url: "/api/ca/" + authority.slug + "/lease/",
                        dataType: "json",
                        success: function(leases, status, xhr) {
                            console.info("Got leases:", leases);
                            for (var j = 0; j < leases.length; j++) {
                                var $status = $("#signed_certificates [data-dn='" + leases[j].dn + "'] .status");
                                if (!$status.length) {
                                    console.info("Detected rogue client:", leases[j]);
                                    continue;
                                }
                                $status.html(nunjucks.render('status.html', {
                                    lease: {
                                        address: leases[j].address,
                                        dn: leases[j].dn,
                                        acquired: new Date(leases[j].acquired).toLocaleString(),
                                        released: leases[j].released ? new Date(leases[j].released).toLocaleString() : null
                                    }}));
                            }
                        }
                    });
                }
            });
        }
    });
});
