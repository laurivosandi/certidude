jQuery.timeago.settings.allowFuture = true;

function normalizeCommonName(j) {
    return j.replace("@", "--").split(".").join("-"); // dafuq ?!
}

function setTag(cn, key, value, indicator) {
    $(indicator).addClass("busy");
    $.ajax({
        method: "POST",
        url: "/api/signed/" + cn + "/tag/",
        data: { value: value, key: key },
        dataType: "text",
        complete: function(xhr, status) {
            console.info("Tag added successfully", xhr.status,  status);
        },
        success: function() {
            $(indicator).removeClass("busy");
        },
        error: function(xhr, status, e) {
            console.info("Submitting request failed with:", status, e);
            alert(e);
        }
    });
}

function onTagClicked(event) {
    var tag = event.target;
    var cn = $(event.target).attr("data-cn");
    var id = $(event.target).attr("title");
    var value = $(event.target).html();
    var updated = prompt("Enter new tag or clear to remove the tag", value);
    if (updated == "") {
        $(event.target).addClass("busy");
        $.ajax({
            method: "DELETE",
            url: "/api/signed/" + cn + "/tag/" + id + "/"
        });
    } else if (updated && updated != value) {
        $(tag).addClass("busy");
        $.ajax({
            method: "PUT",
            url: "/api/signed/" + cn + "/tag/" + id + "/",
            data: { value: updated },
            dataType: "text",
            complete: function(xhr, status) {
                console.info("Tag added successfully", xhr.status,  status);
            },
            success: function() {
                $(tag).removeClass("busy");
            },
            error: function(xhr, status, e) {
                console.info("Submitting request failed with:", status, e);
                alert(e);
            }
        });

    }
}

function onNewTagClicked(event) {
    var menu = event.target;
    var cn = $(menu).attr("data-cn");
    var key = $(menu).val();
    $(menu).val("");
    var value = prompt("Enter new " + key + " tag for " + cn);
    if (!value) return;
    if (value.length == 0) return;
    setTag(cn, key, value, event.target);
}

function onTagFilterChanged() {
    var key = $(event.target).val();
    console.info("New key is:", key);
}

function onLogEntry (e) {
    var entry = JSON.parse(e.data);
    if ($("#log_level_" + entry.severity).prop("checked")) {
        console.info("Received log entry:", entry);
        $("#log_entries").prepend(nunjucks.render("views/logentry.html", {
            entry: {
                created: new Date(entry.created).toLocaleString(),
                message: entry.message,
                severity: entry.severity
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
                nunjucks.render('views/request.html', { request: request }));
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
    console.log("Lease updated:", e.data);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + e.data + "/lease/",
        dataType: "json",
        success: function(lease, status, xhr) {
            console.info("Retrieved lease update details:", lease);
            lease.age = (new Date() - new Date(lease.last_seen)) / 1000.0
            var $status = $("#signed_certificates [data-cn='" + e.data + "'] .status");
            $status.html(nunjucks.render('views/status.html', {
                certificate: {
                    lease: lease }}));
            $("time", $status).timeago();

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
                nunjucks.render('views/signed.html', { certificate: certificate }));
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
    console.log("Tag updated", cn);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + cn + "/tag/",
        dataType: "json",
        success:function(tags, status, xhr) {
            console.info("Updated", cn, "tags", tags);
            $(".tags span[data-cn='" + cn + "']").html(
                nunjucks.render('views/tags.html', {
                    certificate: {
                        common_name: cn,
                        tags:tags }}));
        }
    })
}

$(document).ready(function() {
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
            $("#container").html(nunjucks.render('views/error.html', { message: msg }));
        },
        success: function(session, status, xhr) {
            $("#login").hide();

            /**
             * Render authority views
             **/
            $("#container").html(nunjucks.render('views/authority.html', { session: session, window: window }));
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

                source.addEventListener("log-entry", onLogEntry);
                source.addEventListener("lease-update", onLeaseUpdate);
                source.addEventListener("request-deleted", onRequestDeleted);
                source.addEventListener("request-submitted", onRequestSubmitted);
                source.addEventListener("request-signed", onRequestSigned);
                source.addEventListener("certificate-revoked", onCertificateRevoked);
                source.addEventListener("tag-update", onTagUpdated);

                console.info("Swtiching to requests section");
                $("section").hide();
                $("section#requests").show();
                $("#section-revoked").show();
                $("#section-signed").show();
                $("#section-requests").show();
            }

            $("nav#menu li").click(function(e) {
                $("section").hide();
                $("section#" + $(e.target).attr("data-section")).show();
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
                $("#section-log").show();
                $.ajax({
                    method: "GET",
                    url: "/api/log/",
                    dataType: "json",
                    success:function(entries, status, xhr) {
                        console.info("Got", entries.length, "log entries");
                        for (var j = 0; j < entries.length; j++) {
                            if ($("#log_level_" + entries[j].severity).prop("checked")) {
                                $("#log_entries").append(nunjucks.render("views/logentry.html", {
                                    entry: {
                                        created: new Date(entries[j].created).toLocaleString("et-EE"),
                                        message: entries[j].message,
                                        severity: entries[j].severity
                                    }
                                }));
                            }
                        }
                    }
                });
            }
        }
    });
});
