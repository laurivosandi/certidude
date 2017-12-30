
'use strict';

const KEYWORDS = [
    ["Android", "android"],
    ["iPhone", "iphone"],
    ["iPad", "ipad"],
    ["Ubuntu", "ubuntu"],
    ["Fedora", "fedora"],
    ["Linux", "linux"],
    ["Macintosh", "mac"],
];

jQuery.timeago.settings.allowFuture = true;

function normalizeCommonName(j) {
    return j.replace("@", "--").split(".").join("-"); // dafuq ?!
}

function onHashChanged() {
    var query = {};
    var a = location.hash.substring(1).split('&');
    for (var i = 0; i < a.length; i++) {
        var b = a[i].split('=');
        query[decodeURIComponent(b[0])] = decodeURIComponent(b[1] || '');
    }

    console.info("Hash is now:", query);

    loadAuthority();
}

function onTagClicked(tag) {
    var cn = $(tag).attr("data-cn");
    var id = $(tag).attr("title");
    var value = $(tag).html();
    var updated = prompt("Enter new tag or clear to remove the tag", value);
    if (updated == "") {
        $(event.target).addClass("disabled");
        $.ajax({
            method: "DELETE",
            url: "/api/signed/" + cn + "/tag/" + id + "/"
        });
    } else if (updated && updated != value) {
        $(tag).addClass("disabled");
        $.ajax({
            method: "PUT",
            url: "/api/signed/" + cn + "/tag/" + id + "/",
            data: { value: updated },
            dataType: "text",
            complete: function(xhr, status) {
                console.info("Tag added successfully", xhr.status,  status);
            },
            success: function() {
            },
            error: function(xhr, status, e) {
                console.info("Submitting request failed with:", status, e);
                alert(e);
            }
        });
    }
}

function onNewTagClicked(menu) {
    var cn = $(menu).attr("data-cn");
    var key = $(menu).attr("data-key");
    var value = prompt("Enter new " + key + " tag for " + cn);
    if (!value) return;
    if (value.length == 0) return;
    var $container = $(".tags[data-cn='" + cn + "']");
    $container.addClass("disabled");
    $.ajax({
        method: "POST",
        url: "/api/signed/" + cn + "/tag/",
        data: { value: value, key: key },
        dataType: "text",
        complete: function(xhr, status) {
            console.info("Tag added successfully", xhr.status,  status);
        },
        success: function() {
            $container.removeClass("disabled");
        },
        error: function(xhr, status, e) {
            console.info("Submitting request failed with:", status, e);
            alert(e);
        }
    });
}

function onTagFilterChanged() {
    var key = $(event.target).val();
    console.info("New key is:", key);
}

function onLogEntry (e) {
    if (e.data) {
        e = JSON.parse(e.data);
    }

    if ($("#log-level-" + e.severity).prop("checked")) {
        $("#log-entries").prepend(env.render("views/logentry.html", {
            entry: {
                created: new Date(e.created).toLocaleString(),
                message: e.message,
                severity: e.severity
            }
        }));
    }
};

function onRequestSubmitted(e) {
    console.log("Request submitted:", e.data);
    $.ajax({
        method: "GET",
        url: "/api/request/" + e.data + "/",
        dataType: "json",
        success: function(request, status, xhr) {
            console.info("Going to prepend:", request);
            onRequestDeleted(e); // Delete any existing ones just in case
            $("#pending_requests").prepend(
                env.render('views/request.html', { request: request }));
            $("#pending_requests time").timeago();
        },
        error: function(response) {
            console.info("Failed to retrieve certificate:", response);
        }
    });
}

function onRequestDeleted(e) {
    console.log("Removing deleted request", e.data);
    $("#request-" + normalizeCommonName(e.data)).remove();
}

function onLeaseUpdate(e) {
    var slug = normalizeCommonName(e.data);
    console.log("Lease updated:", e.data);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + e.data + "/lease/",
        dataType: "json",
        success: function(lease, status, xhr) {
            console.info("Retrieved lease update details:", lease);
            lease.age = (new Date() - new Date(lease.last_seen)) / 1000.0
            var $lease = $("#certificate-" + slug + " .lease");
            $lease.html(env.render('views/lease.html', {
                certificate: {
                    lease: lease }}));
            $("time", $lease).timeago();

        },
        error: function(response) {
            console.info("Failed to retrieve certificate:", response);
        }
    });
}

function onRequestSigned(e) {
    console.log("Request signed:", e.data);
    var slug = normalizeCommonName(e.data);
    console.log("Removing:", slug);

    $("#request-" + slug).slideUp("normal", function() { $(this).remove(); });
    $("#certificate-" + slug).slideUp("normal", function() { $(this).remove(); });

    $.ajax({
        method: "GET",
        url: "/api/signed/" + e.data + "/",
        dataType: "json",
        success: function(certificate, status, xhr) {
            console.info("Retrieved certificate:", certificate);
            $("#signed_certificates").prepend(
                env.render('views/signed.html', { certificate: certificate, session: session }));
            $("#signed_certificates time").timeago(); // TODO: optimize?
        },
        error: function(response) {
            console.info("Failed to retrieve certificate:", response);
        }
    });
}

function onCertificateRevoked(e) {
    console.log("Removing revoked certificate", e.data);
    $("#certificate-" + normalizeCommonName(e.data)).slideUp("normal", function() { $(this).remove(); });
}

function onTagUpdated(e) {
    var cn = e.data;
    console.log("Tag updated event recevied", cn);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + cn + "/tag/",
        dataType: "json",
        success:function(tags, status, xhr) {
            console.info("Updated", cn, "tags", tags);
            $(".tags[data-cn='" + cn+"']").html(
                env.render('views/tags.html', {
                    certificate: {
                        common_name: cn,
                        tags:tags }}));
        }
    })
}

function onAttributeUpdated(e) {
    var cn = e.data;
    console.log("Attributes updated", cn);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + cn + "/attr/",
        dataType: "json",
        success:function(attributes, status, xhr) {
            console.info("Updated", cn, "attributes", attributes);
            $(".attributes[data-cn='" + cn + "']").html(
                env.render('views/attributes.html', {
                    certificate: {
                        common_name: cn,
                        attributes:attributes }}));
        }
    })
}

function onServerStarted() {
    console.info("Server started");
    location.reload();
}

function onServerStopped() {
    $("view").html('<div class="loader"></div><p>Server under maintenance</p>');
    console.info("Server stopped");

}

function onSendToken() {
    $.ajax({
        method: "POST",
        url: "/api/token/",
        data: { username: $("#token_username").val(), mail: $("#token_mail").val() },
        dataType: "text",
        complete: function(xhr, status) {
            console.info("Token sent successfully", xhr.status, status);
        },
        success: function(data) {
            var url = JSON.parse(data).url;
            console.info("DATA:", url);
            var code = new QRCode({
                content: url,
                width: 512,
                height: 512,
            });
            document.getElementById("token_qrcode").innerHTML = code.svg();

        },
        error: function(xhr, status, e) {
            console.info("Submitting request failed with:", status, e);
            alert(e);
        }
    });



}

function loadAuthority() {
    console.info("Loading CA, to debug: curl " + window.location.href + " --negotiate -u : -H 'Accept: application/json'");
    $.ajax({
        method: "GET",
        url: "/api/",
        dataType: "json",
        error: function(response) {
            if (response.responseJSON) {
                var msg = response.responseJSON
            } else {
                var msg = { title: "Error " + response.status, description: response.statusText }
            }
            $("#view").html(env.render('views/error.html', { message: msg }));
        },
        success: function(session, status, xhr) {
            window.session = session;

            console.info("Loaded:", session);
            $("#login").hide();

            /**
             * Render authority views
             **/
            $("#view").html(env.render('views/authority.html', { session: session, window: window }));
            $("time").timeago();
            if (session.authority) {
                $("#log input").each(function(i, e) {
                    console.info("e.checked:", e.checked , "and", e.id, "@localstorage is", localStorage[e.id], "setting to:", localStorage[e.id] || e.checked, "bool:", localStorage[e.id] || e.checked == "true");
                    e.checked = localStorage[e.id] ? localStorage[e.id] == "true" : e.checked;
                });

                $("#log input").change(function() {
                    localStorage[this.id] = this.checked;
                });

                console.info("Opening EventSource from:", session.authority.events);

                var source = new EventSource(session.authority.events);

                source.onmessage = function(event) {
                    console.log("Received server-sent event:", event);
                }


                source.addEventListener("lease-update", onLeaseUpdate);
                source.addEventListener("request-deleted", onRequestDeleted);
                source.addEventListener("request-submitted", onRequestSubmitted);
                source.addEventListener("request-signed", onRequestSigned);
                source.addEventListener("certificate-revoked", onCertificateRevoked);
                source.addEventListener("tag-update", onTagUpdated);
                source.addEventListener("attribute-update", onAttributeUpdated);
                source.addEventListener("server-started", onServerStarted);
                source.addEventListener("server-stopped", onServerStopped);

                console.info("Swtiching to requests section");
                $("section").hide();
                $("section#requests").show();
                $("#section-revoked").show();
                $("#section-signed").show();
                $("#section-requests").show();
                $("#section-token").show();


            }

            $("nav#menu li").click(function(e) {
                $("section").hide();
                $("section#" + $(e.target).attr("data-section")).show();
            });



            $("#enroll").click(function() {
                var keys = forge.pki.rsa.generateKeyPair(1024);

                $.ajax({
                    method: "POST",
                    url: "/api/token/",
                    data: "username=" + session.user.name,
                    complete: function(xhr, status) {
                        console.info("Token generated successfully:", xhr, status);

                    },
                    error: function(xhr, status, e) {
                        console.info("Token generation failed:", status, e);
                        alert(e);
                    }
                });



                var privateKeyBuffer = forge.pki.privateKeyToPem(keys.privateKey);
            });

            /**
             * Set up search bar
              */
            $(window).on("search", function() {
                var q = $("#search").val();
                $(".filterable").each(function(i, e) {
                    if ($(e).attr("data-cn").toLowerCase().indexOf(q) >= 0) {
                        $(e).show();
                    } else {
                        $(e).hide();
                    }
                });
            });




            /**
             * Bind key up event of search bar
             */
            $("#search").on("keyup", function() {
                if (window.searchTimeout) { clearTimeout(window.searchTimeout); }
                window.searchTimeout = setTimeout(function() { $(window).trigger("search"); }, 500);
                console.info("Setting timeout", window.searchTimeout);

            });

            console.log("Features enabled:", session.features);

            if (session.request_submission_allowed) {
                $("#request_submit").click(function() {
                    $(this).addClass("busy");
                    $.ajax({
                        method: "POST",
                        contentType: "application/pkcs10",
                        url: "/api/request/",
                        data: $("#request_body").val(),
                        dataType: "text",
                        complete: function(xhr, status) {
                            console.info("Request submitted successfully, server returned", xhr.status,  status);
                            $("#request_submit").removeClass("busy");
                        },
                        success: function() {
                            // Clear textarea on success
                            $("#request_body").val("");
                        },
                        error: function(xhr, status, e) {
                            console.info("Submitting request failed with:", status, e);
                            alert(e);
                        }
                    });

                });
            }

            /**
             * Fetch log entries
             */
            if (session.features.logging) {
                $("nav .nav-link.log").removeClass("disabled").click(function() {
                    $("#view-dashboard").hide();
                    $("#view-log").show();
                    $.ajax({
                        method: "GET",
                        url: "/api/log/",
                        dataType: "json",
                        success: function(entries, status, xhr) {
                            console.info("Got", entries.length, "log entries");
                            console.info("j=", entries.length-1);
                            for (var j = entries.length-1; j--; ) {
                                onLogEntry(entries[j]);
                            };
                            source.addEventListener("log-entry", onLogEntry);
                        }
                    });
                });
            }
        }
    });
}

function datetimeFilter(s) {
    return new Date(s);
}

function serialFilter(s) {
    return s.substring(0,8) + " " +
        s.substring(8,12) + " " +
        s.substring(12,16) + " " +
        s.substring(16,28) + " " +
        s.substring(28,32) + " " +
        s.substring(32);
}

$(document).ready(function() {
    window.env = new nunjucks.Environment();
    env.addFilter("datetime", datetimeFilter);
    env.addFilter("serial", serialFilter);
    onHashChanged();
});
