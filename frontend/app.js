/* NullVector frontend.
 *
 * No framework and no build step. Every value that comes from the API is
 * rendered with textContent, never as HTML: model output and scan evidence are
 * untrusted, and the previous UI's unescaped markdown sink is exactly the bug
 * this avoids.
 */

(function () {
  "use strict";

  var healthTimer = null;

  function $(id) {
    return document.getElementById(id);
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    node.replaceChildren();
  }

  /* ---------- API ---------- */

  function api(path, options) {
    return fetch(path, options).then(function (response) {
      return response
        .json()
        .catch(function () {
          return null;
        })
        .then(function (data) {
          return { ok: response.ok, status: response.status, data: data };
        });
    });
  }

  /* ---------- health ---------- */

  function refreshHealth() {
    var pill = $("health");
    var text = $("health-text");

    api("/health")
      .then(function (result) {
        if (!result.ok || !result.data) throw new Error("bad health response");
        var online = result.data.ai === "online";
        pill.dataset.state = online ? "ok" : "warn";
        pill.title = online
          ? "Model endpoint is reachable."
          : "The model endpoint is not reachable. Start LM Studio to run AI scans.";
        text.textContent = online ? "ready · " + result.data.model : "model offline";
      })
      .catch(function () {
        pill.dataset.state = "down";
        pill.title = "The backend did not answer.";
        text.textContent = "backend unreachable";
      });
  }

  function startHealthPolling() {
    refreshHealth();
    if (healthTimer) clearInterval(healthTimer);
    healthTimer = setInterval(refreshHealth, 15000);
  }

  /* ---------- tabs ---------- */

  function selectTab(name) {
    var isAi = name === "ai";

    $("tab-ai").setAttribute("aria-selected", isAi ? "true" : "false");
    $("tab-url").setAttribute("aria-selected", isAi ? "false" : "true");
    $("form-ai").hidden = !isAi;
    $("form-url").hidden = isAi;
  }

  /* ---------- authorization gating ---------- */

  function syncButtons() {
    $("ai-run").disabled = !$("ai-authorized").checked;
    $("url-run").disabled = !$("url-authorized").checked;
  }

  /* ---------- status line ---------- */

  function setStatus(message) {
    var node = $("status");
    if (!message) {
      node.hidden = true;
      node.textContent = "";
      return;
    }
    node.textContent = message;
    node.hidden = false;
  }

  /* ---------- result rendering ---------- */

  function formatTime(value) {
    if (!value) return "";
    var date = new Date(value);
    if (isNaN(date.getTime())) return "";
    return date.toLocaleString();
  }

  function detailText(data) {
    if (!data) return "";
    var detail = data.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map(function (item) {
          var where = Array.isArray(item.loc) ? item.loc.join(".") : "";
          return (where ? where + ": " : "") + (item.msg || "invalid value");
        })
        .join("; ");
    }
    return "";
  }

  function errorHint(status) {
    if (status === 503) {
      return "The target model is not reachable. Start LM Studio, load the model, and check the health indicator.";
    }
    if (status === 403) {
      return "Confirm you are authorized to test this system before scanning.";
    }
    if (status === 400) {
      return "The target failed the safety checks, so no request was sent.";
    }
    if (status === 422) {
      return "One of the fields is invalid. Check the values and try again.";
    }
    return "";
  }

  function showError(status, data) {
    var results = $("results");
    clear(results);
    results.hidden = false;

    var box = el("div", "error");
    box.append(el("strong", null, status ? "Request failed (" + status + ")" : "Request failed"));

    var message = detailText(data) || "The scan could not be completed.";
    box.append(el("p", null, message));

    var hint = errorHint(status);
    if (hint) box.append(el("p", "hint-line", hint));

    results.append(box);
  }

  function countByStatus(findings) {
    var counts = { vulnerable: 0, warning: 0, pass: 0 };
    findings.forEach(function (finding) {
      if (Object.prototype.hasOwnProperty.call(counts, finding.status)) {
        counts[finding.status] += 1;
      }
    });
    return counts;
  }

  function badge(label, level) {
    var node = el("span", "badge");
    node.append(document.createTextNode(label + " "));
    var value = el("strong", null, String(level || "unknown"));
    value.dataset.level = String(level || "");
    node.append(value);
    return node;
  }

  function findingCard(finding) {
    var card = el("article", "card");
    card.dataset.status = String(finding.status || "");

    var top = el("div", "card-top");
    top.append(el("span", "test-id", finding.test_id || "unknown"));
    var pill = el("span", "status-pill", finding.status || "unknown");
    pill.dataset.status = String(finding.status || "");
    top.append(pill);

    card.append(top);
    card.append(el("h3", "card-summary", finding.summary || "No summary provided."));

    var badges = el("div", "badges");
    badges.append(badge("severity", finding.severity));
    badges.append(badge("confidence", finding.confidence));
    if (finding.category) badges.append(el("span", "badge", finding.category));
    card.append(badges);

    card.append(el("p", "label", "Evidence"));
    card.append(el("pre", "evidence", finding.evidence || "No evidence recorded."));

    if (finding.recommendation) {
      card.append(el("p", "label", "Recommendation"));
      card.append(el("p", "rec", finding.recommendation));
    }

    return card;
  }

  function resultHeader(data, counts) {
    var head = el("div", "results-head");

    var risk = el("div", "risk");
    var riskValue = String(data.risk || "info");
    var riskBadge = el("span", "risk-badge", riskValue);
    riskBadge.dataset.level = riskValue;

    var titles = el("div");
    titles.append(
      el(
        "div",
        "risk-title",
        data.scan_type === "ai_behavior" ? "AI behavior scan" : "URL security scan"
      )
    );

    var target = data.target || {};
    var meta = [];
    if (target.name) meta.push(target.name);
    if (target.host) meta.push(target.host);
    if (target.model) meta.push(target.model);
    if (target.resolved_ip) meta.push(target.resolved_ip);
    var when = formatTime(data.scanned_at);
    if (when) meta.push(when);

    titles.append(el("span", "risk-sub", meta.join(" · ")));
    risk.append(riskBadge, titles);

    var summary = el("div", "counts");
    [
      ["vulnerable", counts.vulnerable],
      ["warnings", counts.warning],
      ["passed", counts.pass]
    ].forEach(function (pair) {
      var block = el("div");
      block.append(el("b", null, pair[1]));
      block.append(document.createTextNode(pair[0]));
      summary.append(block);
    });

    head.append(risk, summary);
    return head;
  }

  function renderResult(data) {
    var results = $("results");
    var findings = Array.isArray(data && data.findings) ? data.findings : [];

    clear(results);
    results.hidden = false;

    var counts = countByStatus(findings);
    results.append(resultHeader(data || {}, counts));

    if (!findings.length) {
      results.append(el("div", "empty", "The scan returned no findings."));
      return;
    }

    findings.forEach(function (finding) {
      results.append(findingCard(finding));
    });
  }

  /* ---------- scan execution ---------- */

  function runScan(path, body, label) {
    var started = Date.now();
    setStatus("Running " + label + "…");
    syncButtons();

    var ticker = setInterval(function () {
      var seconds = Math.round((Date.now() - started) / 1000);
      setStatus("Running " + label + "… " + seconds + "s");
    }, 1000);

    return api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    })
      .then(function (result) {
        if (!result.ok) {
          showError(result.status, result.data);
          return;
        }
        renderResult(result.data);
      })
      .catch(function () {
        showError(0, null);
      })
      .finally(function () {
        clearInterval(ticker);
        setStatus("");
        syncButtons();
      });
  }

  function optionalValue(id) {
    var value = $(id).value.trim();
    return value ? value : undefined;
  }

  /* ---------- wiring ---------- */

  function init() {
    startHealthPolling();

    $("tab-ai").addEventListener("click", function () {
      selectTab("ai");
    });
    $("tab-url").addEventListener("click", function () {
      selectTab("url");
    });

    $("ai-authorized").addEventListener("change", syncButtons);
    $("url-authorized").addEventListener("change", syncButtons);

    $("form-ai").addEventListener("submit", function (event) {
      event.preventDefault();

      var body = { authorized: true };
      var name = optionalValue("ai-name");
      var model = optionalValue("ai-model");
      var system = optionalValue("ai-system");
      var canary = optionalValue("ai-canary");
      if (name) body.target_name = name;
      if (model) body.model = model;
      if (system) body.system_prompt = system;
      if (canary) body.canary = canary;

      runScan("/scan/ai", body, "AI scan");
    });

    $("form-url").addEventListener("submit", function (event) {
      event.preventDefault();

      var url = $("url-input").value.trim();
      if (!url) {
        showError(0, { detail: "Enter a URL to scan." });
        return;
      }

      runScan("/scan/url", { url: url, authorized: true }, "URL scan");
    });

    syncButtons();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
