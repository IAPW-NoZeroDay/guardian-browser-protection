import logger from "../utils/logger.js";

export class WebhookManager {
  constructor(configManager) {
    this.configManager = configManager;
    this.webhookTypes = {
      DETECTION_ALERT: "detection_alert",
      FALSE_POSITIVE: "false_positive_report",
      PAGE_BLOCKED: "page_blocked",
      ROGUE_APP: "rogue_app_detected",
      THREAT_DETECTED: "threat_detected",
      VALIDATION_EVENT: "validation_event",
      USER_REPORT: "user_report", // Fork: block-page "where did this link come from?"
    };
  }

  async getWebhookConfig(webhookType) {
    const config = await this.configManager.getConfig();

    if (!config) {
      return [];
    }

    const webhooks = [];

    // Check CIPP webhook
    if (
      webhookType === this.webhookTypes.DETECTION_ALERT &&
      config.enableCippReporting
    ) {
      webhooks.push({
        url: config.cippServerUrl
          ? config.cippServerUrl.replace(/\/+$/, "") +
            "/api/PublicPhishingCheck"
          : null,
        enabled: config.enableCippReporting,
        type: "cipp",
        tenantId: config.cippTenantId || null,
      });
    }

    // Check generic webhook
    const genericWebhook = config.genericWebhook;
    if (genericWebhook && genericWebhook.enabled && genericWebhook.url) {
      const events = genericWebhook.events || [];
      if (events.includes(webhookType)) {
        webhooks.push({
          url: genericWebhook.url,
          enabled: true,
          type: "generic",
          // Fork: optional managed auth headers and static fields (e.g. device, client)
          headers: this.safeHeaders(genericWebhook.headers),
          staticFields: this.safeObject(genericWebhook.staticFields),
        });
      }
    }

    return webhooks.length > 0 ? webhooks : [];
  }

  // Fork: the user's answer from the warning banner or the block page. Only known fields, length-capped.
  buildUserReportPayload(data = {}) {
    const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
    const oneOf = (v, list, fallback) => (list.includes(v) ? v : fallback);
    const src = data.source && typeof data.source === "object" ? data.source : {};
    return {
      reportedFrom: oneOf(data.reportedFrom, ["warning_banner", "block_page"], "unknown"),
      url: str(data.url, 2048),
      blockedReason: str(data.blockedReason, 500),
      rule: str(data.rule, 200),
      referrer: str(data.referrer, 2048),
      source: {
        type: oneOf(src.type, ["email", "sharedfile", "teams", "sms", "web", "unknown"], "unknown"),
        label: str(src.label, 80),
        sender: str(src.sender, 320),
        senderAddress: str(src.senderAddress, 320),
        subject: str(src.subject, 300),
        receivedAround: str(src.receivedAround, 60),
        sharedBy: str(src.sharedBy, 200),
        site: str(src.site, 2048),
        note: str(src.note, 1000),
      },
      enteredPassword: oneOf(data.enteredPassword, ["yes", "no", "unsure"], "unknown"),
      timestamp: str(data.timestamp, 40) || new Date().toISOString(),
    };
  }

  // Fork: only plain key/values from managed policy (at most 32 keys, 512 characters each).
  safeObject(obj) {
    const out = {};
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return out;
    for (const [k, v] of Object.entries(obj)) {
      if (Object.keys(out).length >= 32) break;
      if (/^[A-Za-z0-9_.-]{1,64}$/.test(k) && ["string", "number", "boolean"].includes(typeof v)) {
        out[k] = String(v).slice(0, 512);
      }
    }
    return out;
  }

  // Fork: header names must be tokens and values printable ASCII (no CR/LF or other control characters),
  // and protocol headers (Content-Type, User-Agent, X-Webhook-*, ...) can't be overridden.
  safeHeaders(obj) {
    const reserved = new Set(["content-type", "content-length", "host", "user-agent", "cookie", "origin", "referer", "connection", "transfer-encoding"]);
    const out = {};
    for (const [k, v] of Object.entries(this.safeObject(obj))) {
      const name = k.toLowerCase();
      if (/^[A-Za-z0-9-]+$/.test(k) && !reserved.has(name) && !name.startsWith("x-webhook-") && /^[\x20-\x7e]*$/.test(v)) {
        out[k] = v;
      }
    }
    return out;
  }

  // Fork: for logs. The query string can carry the webhook's shared key (?k=), so log the origin and path only.
  redactUrl(url) {
    try {
      const u = new URL(url);
      return u.origin + u.pathname;
    } catch (_) {
      return "(invalid URL)";
    }
  }

  buildPayload(webhookType, data, metadata = {}) {
    const basePayload = {
      version: "1.0",
      type: webhookType,
      timestamp: new Date().toISOString(),
      source: "Check Extension",
      extensionVersion:
        metadata.extensionVersion || chrome.runtime.getManifest().version,
      data: {},
    };

    switch (webhookType) {
      case this.webhookTypes.DETECTION_ALERT:
        basePayload.data = this.buildDetectionAlertPayload(data);
        break;
      case this.webhookTypes.FALSE_POSITIVE:
        basePayload.data = this.buildFalsePositivePayload(data);
        break;
      case this.webhookTypes.PAGE_BLOCKED:
        basePayload.data = this.buildPageBlockedPayload(data);
        break;
      case this.webhookTypes.ROGUE_APP:
        basePayload.data = this.buildRogueAppPayload(data);
        break;
      case this.webhookTypes.THREAT_DETECTED:
        basePayload.data = this.buildThreatDetectedPayload(data);
        break;
      case this.webhookTypes.VALIDATION_EVENT:
        basePayload.data = this.buildValidationEventPayload(data);
        break;
      case this.webhookTypes.USER_REPORT:
        basePayload.data = this.buildUserReportPayload(data);
        break;
      default:
        basePayload.data = data;
    }

    if (metadata.userProfile) {
      basePayload.user = this.sanitizeUserProfile(metadata.userProfile);
    }

    if (metadata.browserContext) {
      basePayload.browser = metadata.browserContext;
    }

    if (metadata.tenantId) {
      basePayload.tenantId = metadata.tenantId;
    }

    return basePayload;
  }

  buildDetectionAlertPayload(data) {
    // Extract rule information from various possible locations
    const rule = data.rule || data.ruleId || data.event?.rule || null;
    const reason =
      data.reason ||
      data.blockReason ||
      data.event?.reason ||
      "Threat detected";

    // Build matched rules array
    let matchedRules =
      data.rules || data.matchedRules || data.event?.matchedRules || [];

    // If no matchedRules but we have phishingIndicators, convert them to matched rules
    if (
      matchedRules.length === 0 &&
      data.phishingIndicators &&
      Array.isArray(data.phishingIndicators)
    ) {
      matchedRules = data.phishingIndicators.map((indicatorId) => ({
        id: indicatorId,
        description: indicatorId,
        severity: data.severity || data.threatLevel || "medium",
      }));
    }

    // If we have a single rule but no matchedRules array, create one
    if (matchedRules.length === 0 && rule) {
      matchedRules = [
        {
          id: rule,
          description: data.ruleDescription || reason,
          severity:
            data.severity ||
            data.threatLevel ||
            data.event?.severity ||
            "medium",
        },
      ];
    }

    return {
      url: data.url || data.targetUrl || data.event?.url,
      severity:
        data.severity || data.threatLevel || data.event?.severity || "medium",
      score: data.score || data.threatScore || 0,
      threshold: data.threshold || 85,
      reason: reason,
      detectionMethod: data.detectionMethod || "rules_engine",
      rule: rule,
      ruleDescription: data.ruleDescription || reason || null,
      category: data.category || "phishing",
      confidence: data.confidence || 0.8,
      matchedRules: matchedRules,
      context: {
        referrer: data.referrer || data.event?.referrer || null,
        pageTitle: data.pageTitle || data.event?.pageTitle || null,
        domain: data.domain || data.event?.domain || null,
        redirectTo: data.redirectTo || data.event?.redirectTo || null,
      },
    };
  }

  buildFalsePositivePayload(data) {
    return {
      url: data.blockedUrl || data.url,
      severity: "info",
      reason: data.blockReason || data.reason || "User reported false positive",
      reportTimestamp: data.timestamp || new Date().toISOString(),
      userAgent: data.userAgent || null,
      browserInfo: data.browserInfo || {},
      screenResolution: data.screenResolution || {},
      detectionDetails: data.detectionDetails || {},
      userComments: data.comments || null,
      context: {
        referrer: null,
        pageTitle: null,
        domain: null,
      },
    };
  }

  buildPageBlockedPayload(data) {
    // Extract rule information from various possible locations
    const rule = data.rule || data.ruleId || null;
    const reason = data.reason || data.blockReason || "Page blocked";

    // Build matched rules array
    let matchedRules = data.matchedRules || [];

    // If we have a single rule but no matchedRules array, create one
    if (matchedRules.length === 0 && rule) {
      matchedRules = [
        {
          id: rule,
          description: data.ruleDescription || reason,
          severity: data.severity || data.threatLevel || "high",
        },
      ];
    }

    return {
      url: data.url || data.blockedUrl,
      severity: data.severity || data.threatLevel || "high",
      score: data.score || 0,
      threshold: data.threshold || 85,
      reason: reason,
      detectionMethod: data.detectionMethod || "rules_engine",
      rule: rule,
      ruleDescription: data.ruleDescription || reason || null,
      category: data.category || "phishing",
      action: "blocked",
      matchedRules: matchedRules,
      context: {
        referrer: data.referrer || null,
        pageTitle: data.pageTitle || null,
        domain: data.domain || null,
        redirectTo: data.redirectTo || null,
      },
    };
  }

  buildRogueAppPayload(data) {
    return {
      url: data.url,
      severity: data.severity || data.risk || "critical",
      reason: data.reason || "Rogue OAuth application detected",
      detectionMethod: "rogue_app_detection",
      category: "oauth_threat",
      clientId: data.clientId,
      appName: data.appName || "Unknown",
      appInfo: {
        description: data.description || null,
        tags: data.tags || [],
        references: data.references || [],
        risk: data.risk || "high",
      },
      context: {
        referrer: null,
        pageTitle: null,
        domain: null,
        redirectTo: data.redirectTo || null,
        isLocalhost: data.redirectTo?.includes("localhost") || false,
        isPrivateIP: data.isPrivateIP || false,
      },
    };
  }

  buildThreatDetectedPayload(data) {
    return {
      url: data.url,
      severity: data.severity || "medium",
      score: data.score || 0,
      threshold: data.threshold || 85,
      reason: data.reason || "Threat detected",
      detectionMethod: data.detectionMethod || "content_analysis",
      rule: data.rule || null,
      category: data.category || data.type || data.threatType || "threat",
      confidence: data.confidence || 0.7,
      indicators: data.indicators || [],
      matchedRules: data.matchedRules || [],
      context: {
        referrer: data.referrer || null,
        pageTitle: data.pageTitle || null,
        domain: data.domain || null,
        redirectTo: data.redirectTo || null,
        ...(data.context || {}),
      },
    };
  }

  buildValidationEventPayload(data) {
    return {
      url: data.url,
      severity: "info",
      reason: data.reason || "Legitimate domain validated",
      detectionMethod: data.validationType || "domain_validation",
      category: "validation",
      result: data.result || "legitimate",
      confidence: data.confidence || 1.0,
      context: {
        referrer: null,
        pageTitle: null,
        domain: data.domain || null,
        redirectTo: null,
      },
    };
  }

  sanitizeUserProfile(profile) {
    if (!profile) return null;

    return {
      email: profile.userInfo?.email || null,
      id: profile.userInfo?.id || null,
      accountType: profile.userInfo?.accountType || "unknown",
      provider: profile.userInfo?.provider || "unknown",
      isManaged: profile.isManaged || false,
      profileId: profile.profileId || null,
    };
  }

  async sendWebhook(webhookType, data, metadata = {}) {
    const webhookConfigs = await this.getWebhookConfig(webhookType);

    if (!webhookConfigs || webhookConfigs.length === 0) {
      return {
        success: false,
        error: "Webhook not configured",
        skipped: true,
      };
    }

    // Send to all configured webhooks
    const results = await Promise.allSettled(
      webhookConfigs.map((webhookConfig) =>
        this.sendSingleWebhook(webhookType, data, metadata, webhookConfig)
      )
    );

    // Aggregate results
    const successfulSends = results.filter(
      (r) => r.status === "fulfilled" && r.value.success
    );
    const failedSends = results.filter(
      (r) =>
        r.status === "rejected" ||
        (r.status === "fulfilled" && !r.value.success)
    );

    if (successfulSends.length === 0) {
      return {
        success: false,
        error: "All webhook sends failed",
        webhookType: webhookType,
        results: results.map((r) =>
          r.status === "fulfilled"
            ? r.value
            : { success: false, error: r.reason }
        ),
      };
    }

    return {
      success: true,
      webhookType: webhookType,
      results: results.map((r) =>
        r.status === "fulfilled"
          ? r.value
          : { success: false, error: r.reason?.message || "Unknown error" }
      ),
      totalSent: successfulSends.length,
      totalFailed: failedSends.length,
    };
  }

  async sendSingleWebhook(webhookType, data, metadata, webhookConfig) {
    if (!webhookConfig.url) {
      return {
        success: false,
        error: "Webhook URL not configured",
        type: webhookConfig.type,
      };
    }

    const payload =
      webhookConfig.type === "cipp"
        ? this.buildCippPayload(data, metadata)
        : this.buildPayload(webhookType, data, metadata);
    if (webhookConfig.staticFields && Object.keys(webhookConfig.staticFields).length) {
      payload.fields = { ...webhookConfig.staticFields };
    }

    try {
      const response = await fetch(webhookConfig.url, {
        method: "POST",
        // Fork: no cookies or referrer, give up after 15 s, and never follow a redirect with the auth headers.
        credentials: "omit",
        referrerPolicy: "no-referrer",
        redirect: webhookConfig.type === "generic" ? "error" : "follow",
        signal: AbortSignal.timeout(15000),
        headers: {
          "Content-Type": "application/json",
          "User-Agent": `Check/${
            metadata.extensionVersion || chrome.runtime.getManifest().version
          }`,
          "X-Webhook-Type": webhookType,
          "X-Webhook-Version": "1.0",
          ...(webhookConfig.headers || {}),
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      logger.log(
        `Webhook sent to ${this.redactUrl(webhookConfig.url)} successfully: ${webhookType} (${webhookConfig.type})`
      );
      return {
        success: true,
        status: response.status,
        webhookType: webhookType,
        type: webhookConfig.type,
      };
    } catch (error) {
      logger.error(
        `Failed to send webhook ${webhookType} to ${webhookConfig.type}:`,
        error.message
      );
      return {
        success: false,
        error: error.message,
        webhookType: webhookType,
        type: webhookConfig.type,
      };
    }
  }

  buildCippPayload(data, metadata) {
    const config = metadata.config || {};
    const userProfile = metadata.userProfile;

    const userEmail = userProfile?.userInfo?.email || null;
    const userDisplayName =
      userProfile?.userInfo?.displayName ||
      userProfile?.userInfo?.name ||
      (userEmail ? userEmail.split("@")[0] : null);

    const browserContext = {
      browserType: userProfile?.browserInfo?.browserType || "unknown",
      browserVersion: userProfile?.browserInfo?.browserVersion || "unknown",
      platform: userProfile?.browserInfo?.platform || "unknown",
      language: userProfile?.browserInfo?.language || "unknown",
      extensionVersion:
        userProfile?.browserInfo?.version ||
        chrome.runtime.getManifest().version,
      installType: userProfile?.browserInfo?.installType || "unknown",
    };

    return {
      ...data,
      tenantId: config.cippTenantId || metadata.tenantId || null,
      userEmail: userEmail,
      userDisplayName: userDisplayName,
      accountType: userProfile?.userInfo?.accountType || "unknown",
      isManaged: userProfile?.isManaged || false,
      profileId: userProfile?.profileId || null,
      browserContext: browserContext,
      alertSeverity: this.mapSeverityLevel(data.severity || data.threatLevel),
      alertCategory: this.categorizeSecurityEvent(data),
      detectionMethod: "chrome_extension",
      extensionId: chrome.runtime.id,
      reportVersion: "2.0",
      ...(data.redirectTo && {
        redirectContext: {
          redirectHost: data.redirectTo,
          isLocalhost: data.redirectTo?.includes("localhost"),
          isPrivateIP: metadata.isPrivateIP || false,
        },
      }),
      ...(data.clientId && {
        oauthContext: {
          clientId: data.clientId,
          appName: data.appName || "Unknown",
          ...(data.reason && { threatReason: data.reason }),
        },
      }),
    };
  }

  mapSeverityLevel(severity) {
    const severityMap = {
      critical: "CRITICAL",
      high: "HIGH",
      medium: "MEDIUM",
      low: "LOW",
      info: "INFORMATIONAL",
    };
    return severityMap[severity?.toLowerCase()] || "MEDIUM";
  }

  categorizeSecurityEvent(payload) {
    const type = payload.type?.toLowerCase() || "";

    if (
      type.includes("rogue_app") ||
      payload.ruleType === "rogue_app_detection"
    ) {
      return "OAUTH_THREAT";
    }
    if (type.includes("phishing") || type.includes("blocked")) {
      return "PHISHING_ATTEMPT";
    }
    if (type.includes("validation")) {
      return "VALIDATION_EVENT";
    }
    return "SECURITY_EVENT";
  }

  isPrivateIP(host) {
    if (!host) return false;
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^localhost$/i,
    ];
    return privateRanges.some((range) => range.test(host));
  }
}
