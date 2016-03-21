
function onTagClicked() {
    var value = $(this).html();
    var updated = prompt("Enter new tag or clear to remove the tag", value);
    if (updated == "") {
        $(this).addClass("busy");
        $.ajax({
            method: "DELETE",
            url: "/api/tag/" + $(this).attr("data-id")
        });

    } else if (updated && updated != value) {
        $.ajax({
            method: "PUT",
            url: "/api/tag/" + $(this).attr("data-id"),
            dataType: "json",
            data: {
                key: $(this).attr("data-key"),
                value: updated
            }
        });
    }
}

function onNewTagClicked() {
    var cn = $(event.target).attr("data-cn");
    var key = $(event.target).val();
    $(event.target).val("");
    var value = prompt("Enter new " + key + " tag for " + cn);
    if (!value) return;
    if (value.length == 0) return;
    $.ajax({
        method: "POST",
        url: "/api/tag/",
        dataType: "json",
        data: {
            cn: cn,
            value: value,
            key: key
        }
    });
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
            $("#pending_requests").prepend(
                nunjucks.render('views/request.html', { request: request }));
        }
    });
}

function onRequestDeleted(e) {
    console.log("Removing deleted request", e.data);
    $("#request-" + e.data.replace("@", "--").replace(".", "-")).remove();
}

function onClientUp(e) {
    console.log("Adding security association:", e.data);
    var lease = JSON.parse(e.data);
    var $status = $("#signed_certificates [data-dn='" + lease.identity + "'] .status");
    $status.html(nunjucks.render('views/status.html', {
        lease: {
            address: lease.address,
            identity: lease.identity,
            acquired: new Date(),
            released: null
        }}));
}

function onClientDown(e) {
    console.log("Removing security association:", e.data);
    var lease = JSON.parse(e.data);
    var $status = $("#signed_certificates [data-dn='" + lease.identity + "'] .status");
    $status.html(nunjucks.render('views/status.html', {
        lease: {
            address: lease.address,
            identity: lease.identity,
            acquired: null,
            released: new Date()
        }}));
}

function onRequestSigned(e) {
    console.log("Request signed:", e.data);

    $("#request-" + e.data.replace("@", "--").replace(".", "-")).slideUp("normal", function() { $(this).remove(); });
    $("#certificate-" + e.data.replace("@", "--").replace(".", "-")).slideUp("normal", function() { $(this).remove(); });

    $.ajax({
        method: "GET",
        url: "/api/signed/" + e.data + "/",
        dataType: "json",
        success: function(certificate, status, xhr) {
            console.info(certificate);
            $("#signed_certificates").prepend(
                nunjucks.render('views/signed.html', { certificate: certificate }));
        }
    });
}


function onCertificateRevoked(e) {
    console.log("Removing revoked certificate", e.data);
    $("#certificate-" + e.data.replace("@", "--").replace(".", "-")).slideUp("normal", function() { $(this).remove(); });
}

function onTagAdded(e) {
    console.log("Tag added", e.data);
    $.ajax({
        method: "GET",
        url: "/api/tag/" + e.data + "/",
        dataType: "json",
        success: function(tag, status, xhr) {
            // TODO: Deduplicate
            $tag = $("<span id=\"tag_" + tag.id + "\" title=\"" + tag.key + "=" + tag.value + "\" class=\"" + tag.key.replace(/\./g, " ") + " icon tag\" data-id=\""+tag.id+"\" data-key=\"" + tag.key + "\">" + tag.value + "</span>");
            $tags = $("#signed_certificates [data-cn='" + tag.cn + "'] .tags").prepend(" ");
            $tags = $("#signed_certificates [data-cn='" + tag.cn + "'] .tags").prepend($tag);
            $tag.click(onTagClicked);
        }
    })
}

function onTagRemoved(e) {
    console.log("Tag removed", e.data);
    $("#tag_" + e.data).remove();
}

function onTagUpdated(e) {
    console.log("Tag updated", e.data);
    $.ajax({
        method: "GET",
        url: "/api/tag/" + e.data + "/",
        dataType: "json",
        success:function(tag, status, xhr) {
            console.info("Updated tag", tag);
            $("#tag_" + tag.id).html(tag.value);
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
                source.addEventListener("up-client", onClientUp);
                source.addEventListener("down-client", onClientDown);
                source.addEventListener("request-deleted", onRequestDeleted);
                source.addEventListener("request-submitted", onRequestSubmitted);
                source.addEventListener("request-signed", onRequestSigned);
                source.addEventListener("certificate-revoked", onCertificateRevoked);
                source.addEventListener("tag-added", onTagAdded);
                source.addEventListener("tag-removed", onTagRemoved);
                source.addEventListener("tag-updated", onTagUpdated);

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
                    if ($(e).attr("data-dn").toLowerCase().indexOf(q) >= 0) {
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
            if (session.features.tagging) {
                console.info("Tagging enabled");
                $("#section-config").show();
                $.ajax({
                    method: "GET",
                    url: "/api/config/",
                    dataType: "json",
                    success: function(configuration, status, xhr) {
                        console.info("Appending", configuration.length, "configuration items");
                        $("#config").html(nunjucks.render('views/configuration.html', { configuration:configuration}));
                        /**
                         * Fetch tags for certificates
                         */
                        $.ajax({
                            method: "GET",
                            url: "/api/tag/",
                            dataType: "json",
                            success:function(tags, status, xhr) {
                                console.info("Got", tags.length, "tags");
                                $("#config").html(nunjucks.render('views/configuration.html', { configuration:configuration}));
                                for (var j = 0; j < tags.length; j++) {
                                    // TODO: Deduplicate
                                    $tag = $("<span id=\"tag_" + tags[j].id + "\"  title=\"" + tags[j].key + "=" + tags[j].value + "\" class=\"" + tags[j].key.replace(/\./g, " ") + " icon tag\" data-id=\""+tags[j].id+"\" data-key=\"" + tags[j].key + "\">" + tags[j].value + "</span>");
                                    console.info("Inserting tag", tags[j], $tag);
                                    $tags = $("#signed_certificates [data-cn='" + tags[j].cn + "'] .tags").prepend(" ");
                                    $tags = $("#signed_certificates [data-cn='" + tags[j].cn + "'] .tags").prepend($tag);
                                    $tag.click(onTagClicked);
                                    $("#tags_autocomplete").prepend("<option value=\"" + tags[j].id + "\">" + tags[j].key + "='" + tags[j].value + "'</option>");
                                }
                            }
                        });
                    }
                });
            }

            /**
             * Fetch leases associated with certificates
             */
            if (session.features.leases) {
                $.ajax({
                    method: "GET",
                    url: "/api/lease/",
                    dataType: "json",
                    success: function(leases, status, xhr) {
                        console.info("Got leases:", leases);
                        for (var j = 0; j < leases.length; j++) {
                            var $status = $("#signed_certificates [data-dn='" + leases[j].identity + "'] .status");
                            if (!$status.length) {
                                console.info("Detected rogue client:", leases[j]);
                                continue;
                            }
                            $status.html(nunjucks.render('views/status.html', {
                                lease: {
                                    address: leases[j].address,
                                    age: (new Date() - new Date(leases[j].released)) / 1000,
                                    identity: leases[j].identity,
                                    acquired: new Date(leases[j].acquired).toLocaleString(),
                                    released: leases[j].released ? new Date(leases[j].released).toLocaleString() : null
                                }}));
                        }

                    }
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
