// abuseProtection.js

import { checkRateLimit, getRateLimitStatus, clearAllRateLimits } from './rateLimiter.js';
import { logger } from './logger.js';

const DEFAULT_PROTECTION_POLICY = Object.freeze({
  maxAttempts: 2,
  windowMs: 30_000
});

const DEFAULT_ANOMALY_POLICY = Object.freeze({
  threshold: 3,
  windowMs: 5 * 60_000
});

const RISKY_COMMAND_CATEGORIES = new Set([
  'moderation',
  'ticket',
  'config',
  'verification'
]);

const RISKY_COMMAND_NAMES = new Set([
  'wipedata',
  'massban',
  'masskick',
  'ban',
  'kick',
  'timeout',
  'untimeout',
  'purge',
  'warn',
  'unban',
  'lock',
  'unlock',
  'ticket',
  'reactroles'
]);

const blockedAttemptStore = new Map();

function normalizeCommandCategory(command) {
  return String(command?.category || '').trim().toLowerCase();
}

function normalizeCommandName(commandName) {
  return String(commandName || '').trim().toLowerCase();
}

function getCommandPolicy(command) {
  const protection = command?.abuseProtection || {};
  const maxAttempts = Number.isInteger(protection.maxAttempts) && protection.maxAttempts > 0
    ? protection.maxAttempts
    : DEFAULT_PROTECTION_POLICY.maxAttempts;
  const windowMs = Number.isInteger(protection.windowMs) && protection.windowMs > 0
    ? protection.windowMs
    : DEFAULT_PROTECTION_POLICY.windowMs;

  return { maxAttempts, windowMs };
}

function getAnomalyPolicy(command) {
  const anomaly = command?.abuseProtection?.anomaly || {};
  const threshold = Number.isInteger(anomaly.threshold) && anomaly.threshold > 0
    ? anomaly.threshold
    : DEFAULT_ANOMALY_POLICY.threshold;
  const windowMs = Number.isInteger(anomaly.windowMs) && anomaly.windowMs > 0
    ? anomaly.windowMs
    : DEFAULT_ANOMALY_POLICY.windowMs;

  return { threshold, windowMs };
}

function getProtectionKey(interaction, commandName) {
  const guildScope = interaction.guildId || 'dm';
  const userId = interaction.user?.id || 'unknown_user';
  return `${guildScope}:${userId}:${normalizeCommandName(commandName)}`;
}

function recordBlockedAttempt(key, commandName, interaction, command, remainingMs) {
  const now = Date.now();
  const anomalyPolicy = getAnomalyPolicy(command);
  const current = blockedAttemptStore.get(key);

  if (!current || now - current.windowStart > anomalyPolicy.windowMs) {
    blockedAttemptStore.set(key, {
      count: 1,
      windowStart: now,
      thresholdReachedAt: null
    });
    return;
  }

  current.count += 1;

  if (current.count >= anomalyPolicy.threshold && !current.thresholdReachedAt) {
    current.thresholdReachedAt = now;
    logger.warn('Abuse anomaly detected for risky command cooldown breaches', {
      event: 'interaction.command.abuse_anomaly',
      guildId: interaction.guildId,
      userId: interaction.user?.id,
      command: normalizeCommandName(commandName),
      anomalyCount: current.count,
      anomalyWindowMs: anomalyPolicy.windowMs,
      cooldownRemainingMs: remainingMs
    });
  }
}

export function formatCooldownDuration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) {
    return 'a moment';
  }

  const totalSeconds = Math.ceil(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;

  if (minutes > 0 && seconds > 0) {
    return `${minutes}m ${seconds}s`;
  }

  if (minutes > 0) {
    return `${minutes}m`;
  }

  return `${seconds}s`;
}

export function isRiskyCommand(command, commandName) {
  const protectionEnabled = command?.abuseProtection?.enabled;
  if (protectionEnabled === false) {
    return false;
  }

  if (protectionEnabled === true) {
    return true;
  }

  const normalizedName = normalizeCommandName(commandName);
  if (RISKY_COMMAND_NAMES.has(normalizedName)) {
    return true;
  }

  const normalizedCategory = normalizeCommandCategory(command);
  return RISKY_COMMAND_CATEGORIES.has(normalizedCategory);
}

export async function enforceAbuseProtection(interaction, command, commandName) {
  return {
    allowed: true,
    risky: false,
    remainingMs: 0,
    policy: null
  };
}

export function resetAbuseProtectionState() {
  blockedAttemptStore.clear();
  clearAllRateLimits();
}
