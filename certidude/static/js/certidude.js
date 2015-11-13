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

                    console.info("Opening EventSource from:", authority.event_channel);

                    var source = new EventSource(authority.event_channel);

                    source.onmessage = function(event) {
                        console.log("Received server-sent event:", event);
                    }

                    source.addEventListener("up-client", function(e) {
                        console.log("Adding security association:" + e.data);
                        var lease = JSON.parse(e.data);
                        var $status = $("#signed_certificates [data-dn='" + lease.identity + "'] .status");
                        $status.html(nunjucks.render('status.html', {
                            lease: {
                                address: lease.address,
                                identity: lease.identity,
                                acquired: new Date(),
                                released: null
                            }}));
                    });

                    source.addEventListener("down-client", function(e) {
                        console.log("Removing security association:" + e.data);
                        var lease = JSON.parse(e.data);
                        var $status = $("#signed_certificates [data-dn='" + lease.identity + "'] .status");
                        $status.html(nunjucks.render('status.html', {
                            lease: {
                                address: lease.address,
                                identity: lease.identity,
                                acquired: null,
                                released: new Date()
                            }}));
                    });

                    source.addEventListener("request_deleted", function(e) {
                        console.log("Removing deleted request #" + e.data);
                        $("#request_" + e.data).remove();
                    });

                    source.addEventListener("request_submitted", function(e) {
                        console.log("Request submitted:", e.data);
                    });

                    source.addEventListener("request_signed", function(e) {
                        console.log("Request signed:", e.data);
                        $("#request_" + e.data).slideUp("normal", function() { $(this).remove(); });
                        // TODO: Insert <li> to signed certs list
                    });

                    source.addEventListener("certificate_revoked", function(e) {
                        console.log("Removing revoked certificate #" + e.data);
                        $("#certificate_" + e.data).slideUp("normal", function() { $(this).remove(); });
                    });

                    $("#container").html(nunjucks.render('authority.html', { authority: authority, session: session }));

                    $.ajax({
                        method: "GET",
                        url: "/api/ca/" + authority.slug + "/lease/",
                        dataType: "json",
                        success: function(leases, status, xhr) {
                            console.info("Got leases:", leases);
                            for (var j = 0; j < leases.length; j++) {
                                var $status = $("#signed_certificates [data-dn='" + leases[j].identity + "'] .status");
                                if (!$status.length) {
                                    console.info("Detected rogue client:", leases[j]);
                                    continue;
                                }
                                $status.html(nunjucks.render('status.html', {
                                    lease: {
                                        address: leases[j].address,
                                        identity: leases[j].identity,
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
