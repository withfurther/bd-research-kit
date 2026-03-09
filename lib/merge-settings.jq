# Merge bd-research-kit settings into existing settings.json
# Usage: jq -s -f merge-settings.jq existing.json kit.json
#
# Strategy:
#   permissions.deny    -> UNION (add kit rules, keep existing)
#   permissions.allow   -> UNION (add kit rules, keep existing)
#   ignorePatterns      -> UNION (add kit patterns, keep existing)
#   hooks               -> MERGE by event name (add new, keep existing)
#   enabledPlugins      -> MERGE (add new plugins, don't change existing)
#   scalar values       -> SET if missing, SKIP if already set

.[0] as $existing | .[1] as $kit |

# Merge permissions
($existing.permissions // {}) as $ep |
($kit.permissions // {}) as $kp |

# Union arrays (deduplicate)
(($ep.deny // []) + ($kp.deny // []) | unique) as $deny |
(($ep.allow // []) + ($kp.allow // []) | unique) as $allow |

# Merge hooks (keep existing events, add new)
(($existing.hooks // {}) * ($kit.hooks // {})) as $hooks |

# Merge enabledPlugins (keep existing states, add new kit-only plugins)
(($kit.enabledPlugins // {}) | to_entries |
  [.[] | select(.key as $k | ($existing.enabledPlugins // {}) | has($k) | not)] |
  from_entries) as $new_plugins |
(($existing.enabledPlugins // {}) + $new_plugins) as $plugins |

# Merge ignorePatterns
(($existing.ignorePatterns // []) + ($kit.ignorePatterns // []) | unique) as $ignores |

# Build merged result: existing scalars take precedence (right side wins in jq *)
($kit | del(.permissions, .hooks, .enabledPlugins, .ignorePatterns)) *
$existing |
# Overwrite with our properly merged arrays/objects
.permissions.deny = $deny |
.permissions.allow = $allow |
.hooks = $hooks |
.enabledPlugins = $plugins |
.ignorePatterns = $ignores
