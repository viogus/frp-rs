//! Config-reload application: the `request_reload`/`try_reload`/`reload_from_sources`
//! entry points, the wire-name helper `reload_from_sources` uses, and the two
//! `start`/`enabled` list filters they share with the rest of the client.
//!
//! Split out of `frp-client/src/service.rs` by the P2 S1 seam as a pure move
//! (every line byte-identical). This module is a *child* of `service`, which is
//! what lets the `impl Service` blocks below reach the parent's private fields
//! and methods; it is deployed as a child module rather than a flat sibling for
//! exactly that reason (see the P2 layout note in
//! `docs/refactor-large-modules.md`).
//!
//! Ordering that must not change: `reload_from_sources` performs only
//! reversible side effects (plugin starts held in a local map, vnet TUN
//! open/register) before it sends the CloseProxy/NewProxy batch through
//! `writer`; the in-memory `proxy_info_map`/`health_proxy_configs`/`cfg`
//! commits happen only after that send succeeds, so a mid-way write failure
//! cannot leave the process half-applied.

use super::*;

impl Service {
    /// Request a config reload. Safe to call from signal handler.
    /// Returns immediately; actual reload happens asynchronously in run().
    /// Logs a warning if the reload channel is full or closed — the reload
    /// will be retried on the next try_send (periodic or on next event).
    pub fn request_reload(&self) {
        match self.reload_tx.try_send(ReloadRequest {
            strict: false,
            reply: {
                let (tx, _) = tokio::sync::oneshot::channel();
                tx
            },
        }) {
            Ok(()) => tracing::info!("Config reload requested (SIGUSR1)"),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("Config reload channel full (capacity 64) — reload queued; will be processed when prior reload completes");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!("Config reload channel closed — reload not possible (service may be shutting down)");
            }
        }
    }
}

impl Service {
    /// CloseProxy must use the ORIGINAL registered wire name (old user
    /// prefix). After a `user` config change, rebuilding the name from the
    /// new user misses the server-side proxy and leaves it orphaned (its
    /// port/domains stay allocated). Look up the registered key from
    /// proxy_info_map: when old/new users differ, do_reload's strip_prefix
    /// fails and the delta name IS the full registered key.
    async fn close_wire_name_for_reload(&self, name: &str, user: &str) -> String {
        let map = self.proxy_info_map.read().await;
        if map.contains_key(name) {
            name.to_string()
        } else {
            wire_proxy_name(user, name)
        }
    }

    /// Reload configuration from file. Used by admin API and SIGUSR1.
    ///
    /// Diffs old vs new proxy configs, restarts affected plugins, sends
    /// CloseProxy/NewProxy messages with correct plugin bound addresses,
    /// and updates the shared proxy_info_map.
    pub(crate) async fn try_reload(
        &self,
        config_path: &str,
        strict: bool,
        writer: &Arc<ControlWriter>,
    ) -> Result<String, String> {
        self.reload_from_sources(config_path, strict, writer).await
    }

    /// Reload the config file, merge the optional store overlay, and apply the
    /// resulting proxy/visitor changes to the running service.
    ///
    /// Also refreshes the in-memory config/proxy snapshots so the next session
    /// and admin API see the merged result.
    pub(crate) async fn reload_from_sources(
        &self,
        config_path: &str,
        strict: bool,
        writer: &Arc<ControlWriter>,
    ) -> Result<String, String> {
        // `load_client_config_with_presence` (not the plain wrapper) so the
        // `[web_server.tls] enable` diagnostic still reaches the log on a
        // reload: the loader itself is silent — on the startup `-c` path it
        // would run before `init_logging` and reach no subscriber — so every
        // in-process load site that *does* have a sink emits it here. Measured
        // on the base binary: a SIGUSR1 reload of a config with the key logged
        // `web_server.tls.enable has no effect: …` from the loader, and the
        // admin section has no field for it, so that record was the only signal
        // the reload gave about it.
        let (mut new_cfg, presence) =
            frp_core::config::load_client_config_with_presence(config_path, strict)
                .map_err(|e| format!("failed to load config: {e}"))?;
        presence.warn_inert_web_server_tls_enable(crate::web_server_tls_enable_reader());
        if let Some(ref store) = self.store_source {
            if let Err(e) = store.reload() {
                tracing::warn!(error = %e, "store reload failed, using in-memory state");
            }
            new_cfg = merge_client_config(&new_cfg, Some(store));
        }
        // `Self::cfg` has not been written yet at this point, so its `auth`
        // section is the one this process started with — `reload::auth_reload_
        // refusal` depends on that (see its docs). The check runs before any
        // proxy/plugin/visitor work so a refused reload has no side effects on
        // the running session.
        //
        // Why refuse instead of re-derive, and what this does *not* cover: see
        // `reload::auth_reload_refusal`. Scope note: the store merge **cannot**
        // contribute an `[auth]` section at all — `store::merge_client_config`
        // clones the config and overlays only proxies and visitors
        // (`frp-client/src/store.rs:231-254`) — so the config file is the only
        // source this comparison ever sees. The `store.reload()` a few lines
        // above *has* already run when the check refuses, so re-reading the
        // store file is one side effect a refused reload can still have;
        // nothing from the new config is applied.
        if let Some(reason) = crate::reload::auth_reload_refusal(
            self.cfg.read().await.auth.as_ref(),
            new_cfg.auth.as_ref(),
        ) {
            return Err(reason);
        }
        // Source-local enabled filtering, then apply the start allowlist so the
        // reload diff never registers store/config proxies outside `start`.
        new_cfg.proxies.retain(|p| p.enabled);
        new_cfg.visitors.retain(|v| v.enabled);
        let active_proxies = filter_active_proxies(&new_cfg, &new_cfg.proxies);
        new_cfg.proxies = active_proxies;
        new_cfg.visitors = filter_active_visitors(&new_cfg, &new_cfg.visitors);

        let user = new_cfg.user.clone();
        let old_visitors = self.cfg.read().await.visitors.clone();
        #[cfg(feature = "vnet")]
        let mut delta =
            crate::reload::do_reload(&self.proxy_info_map, &old_visitors, new_cfg, &user).await?;
        #[cfg(not(feature = "vnet"))]
        let delta =
            crate::reload::do_reload(&self.proxy_info_map, &old_visitors, new_cfg, &user).await?;

        // reload::config_snapshot omits vnet-only fields; extend the delta so
        // a subnet/IP/mask change still rebuilds the TUN during reload.
        #[cfg(feature = "vnet")]
        {
            let old_cfg = self.cfg.read().await.clone();
            let old_proxies = Arc::clone(&*self.proxies.read().await);
            for p in &delta.new_config.proxies {
                let old = old_proxies.iter().find(|old| old.name == p.name);
                let vnet_field_changed =
                    old.is_some_and(|old| vnet_proxy_snapshot(old) != vnet_proxy_snapshot(p));
                let global_changed = old_cfg.virtual_net.address
                    != delta.new_config.virtual_net.address
                    && p.plugin
                        .as_ref()
                        .is_some_and(|pl| pl.plugin_type == "virtual_net");
                if (vnet_field_changed || global_changed) && !delta.changed.contains(&p.name) {
                    delta.changed.push(p.name.clone());
                }
            }
        }

        if delta.removed.is_empty()
            && delta.added.is_empty()
            && delta.changed.is_empty()
            && delta.visitor_removed.is_empty()
            && delta.visitor_added.is_empty()
            && delta.visitor_changed.is_empty()
        {
            let merged = delta.new_config;
            *self.cfg.write().await = merged;
            *self.proxies.write().await = Arc::new(self.cfg.read().await.proxies.clone());
            return Ok(delta.summary);
        }

        // Visitor listeners are session-scoped; a visitor change requires a
        // clean session restart so the new visitor set is fully rebuilt
        // (Go frp's visitor_manager stop/start equivalent).
        let visitor_changed = !delta.visitor_removed.is_empty()
            || !delta.visitor_added.is_empty()
            || !delta.visitor_changed.is_empty();

        let v2 = delta.new_config.v2;

        // Phase A — perform only reversible side effects, then send the protocol
        // messages. A write failure mid-way must not leave the process half-applied
        // (old plugins killed / new plugin addresses not yet in proxy_info_map would
        // register dead addresses on the next reconnect). The plugin kills/starts are
        // therefore deferred until AFTER the send succeeds; the only pre-send side
        // effect besides the messages is starting the new plugins, whose handles are
        // held locally and dropped on failure (vnet TUN state is refreshed on reconnect).

        // Drop TUN state for removed and changed proxies before recreating it.
        // Changed proxies must get a fresh TUN and a fresh delivery channel.
        // The vnet comes from the pre-reload config (removed proxies are still
        // present there; self.cfg is refreshed at the end of the reload).
        #[cfg(feature = "vnet")]
        for name in delta.removed.iter().chain(delta.changed.iter()) {
            let vnet = self
                .cfg
                .read()
                .await
                .proxies
                .iter()
                .find(|p| &p.name == name)
                .map(|p| p.virtual_net.clone())
                .unwrap_or_default();
            remove_vnet_tun(
                &self.vnet_tuns,
                &self.vnet_tun_tx,
                &self.vnet_tun_cancels,
                &self.vnet_tun_names,
                &self.vnet_tun_subnets,
                &self.vnet_controller.route_table(),
                &self.vnet_peer_routes,
                writer,
                v2,
                name,
                &vnet,
            )
            .await;
        }

        // Start new plugins for added and changed proxies that have plugin config.
        // Collect actual bound addresses for use in NewProxy messages and map updates.
        // Handles are kept in a local map (not yet committed to self.plugin_handles)
        // so a failed send below can drop them and leave the old plugin set running
        // untouched.
        let mut new_plugin_handles: HashMap<String, PluginHandle> = HashMap::new();
        let mut plugin_addrs: HashMap<String, String> = HashMap::new();
        for name in delta.added.iter().chain(delta.changed.iter()) {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                if let Some(ref plugin_cfg) = p.plugin {
                    // virtual_net is not a local-listener plugin (startup
                    // skip at plugin/mod.rs start_plugin): start_plugin
                    // returns None for it, which the changed-arm below would
                    // misread as a restart FAILURE and abort the ENTIRE
                    // reload (dropping every other changed proxy). Skip it
                    // here — vnet proxies are handled by the TUN
                    // open/register section below.
                    if plugin_cfg.plugin_type == "virtual_net" {
                        continue;
                    }
                    if let Some(handle) = self
                        .start_plugin(name, plugin_cfg, p.use_encryption, p.use_compression)
                        .await
                    {
                        let addr = handle.local_addr.to_string();
                        plugin_addrs.insert(name.clone(), addr);
                        new_plugin_handles.insert(name.clone(), handle);
                    } else if delta.changed.contains(name) {
                        // A CHANGED proxy whose plugin failed to restart must
                        // not silently fall back to local_ip:local_port — the
                        // commit phase would then kill the OLD plugin and leave
                        // the proxy pointing at a dead address while reload
                        // reports success. Abort the whole reload: drop the
                        // freshly started plugins (if any), keep the old
                        // plugin set and the server-side old proxy untouched.
                        for (_, h) in new_plugin_handles.drain() {
                            drop(h);
                        }
                        return Err(format!(
                            "plugin '{}' failed to restart for changed proxy '{}'; reload aborted, old plugin kept running",
                            plugin_cfg.plugin_type, name
                        ));
                    }
                    // Added proxy: a plugin start failure falls back to
                    // local_ip:local_port with an error recorded on the proxy
                    // (see the proxy_info_map err field below).
                }
            }
        }

        // Open/register TUN devices and spawn controllers for added and
        // changed vnet proxies before NewProxy is sent, so a work conn that
        // arrives immediately can find the fresh delivery channel.
        #[cfg(feature = "vnet")]
        for name in delta.added.iter().chain(delta.changed.iter()) {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                if vnet_tun_params(p, &delta.new_config.virtual_net.address).is_none() {
                    continue;
                }
                if let Err(e) = self.open_vnet_tun_for_proxy(p, &delta.new_config).await {
                    warn!(proxy_name = %name, error = %e, "reload TUN open/register failed");
                    continue;
                }
                spawn_vnet_tun_controller(
                    &self.vnet_tuns,
                    &self.vnet_tun_tx,
                    &self.vnet_tun_cancels,
                    &self.vnet_controller,
                    name,
                    &p.virtual_net,
                    writer,
                    v2,
                )
                .await;
            }
        }

        // Collect all messages, then send them atomically while holding the
        // writer lock (no other .await work between writes).
        // NOTICE: Do NOT hold the writer lock across any non-write .await.
        let mut changes: Vec<String> = Vec::new();

        struct ReloadMsg {
            label: String,
            msg: FrpMessage,
        }
        let mut msgs: Vec<ReloadMsg> = Vec::new();

        // CloseProxy for removed proxies
        let user = delta.new_config.user.clone();
        for name in &delta.removed {
            let wn = self.close_wire_name_for_reload(name, &user).await;
            msgs.push(ReloadMsg {
                label: format!("send CloseProxy for '{name}'"),
                msg: FrpMessage::CloseProxy(msg::CloseProxy { proxy_name: wn }),
            });
            changes.push(format!("proxy '{name}' removed"));
        }

        // CloseProxy + NewProxy for changed proxies
        for name in &delta.changed {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                let wn = self.close_wire_name_for_reload(name, &user).await;
                let local_addr = plugin_addrs
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                msgs.push(ReloadMsg {
                    label: format!("send CloseProxy for changed '{name}'"),
                    msg: FrpMessage::CloseProxy(msg::CloseProxy { proxy_name: wn }),
                });
                msgs.push(ReloadMsg {
                    label: format!("send NewProxy for changed '{name}'"),
                    msg: crate::proxy::create_new_proxy_msg(p, &local_addr, &user),
                });
                changes.push(format!("proxy '{name}' updated"));
            }
        }

        // NewProxy for added proxies
        for name in &delta.added {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                let local_addr = plugin_addrs
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                msgs.push(ReloadMsg {
                    label: format!("send NewProxy for added '{name}'"),
                    msg: crate::proxy::create_new_proxy_msg(p, &local_addr, &user),
                });
                changes.push(format!("proxy '{name}' added"));
            }
        }

        // Enqueue all reload messages to the control writer in order. The
        // writer task owns the raw write half; `send` never blocks and fails
        // fast when the channel is full or the writer has died. On failure
        // the reload is aborted before any commit: drop the not-yet-committed
        // plugin handles (killing the fresh plugins) so the old plugin set,
        // health checks, proxy_info_map, and cfg all remain untouched and
        // consistent.
        {
            for rm in &msgs {
                if let Err(e) = writer.send(rm.msg.clone(), v2) {
                    drop(new_plugin_handles);
                    return Err(format!("{}: {e}", rm.label));
                }
            }
        }

        // Resolve the wire keys for removed/changed proxies while
        // proxy_info_map still holds the pre-reload entries (Step 4 removes
        // them below). When the reload changes `user`, do_reload's
        // strip_prefix fails against the NEW user and delta.removed holds the
        // full OLD wire names (old_user.name); rebuilding them with
        // wire_proxy_name(&user, name) double-prefixes and misses every keyed
        // lookup (health_cancels, proxy_info_map, health_proxy_configs),
        // leaving stale entries and surviving health tasks.
        let mut wire_keys: HashMap<String, String> = HashMap::new();
        for name in delta.removed.iter().chain(delta.changed.iter()) {
            wire_keys.insert(
                name.clone(),
                self.close_wire_name_for_reload(name, &user).await,
            );
        }

        // Commit point — every remaining operation is infallible, so the reload
        // can no longer fail part-way. Apply the plugin lifecycle changes that
        // were deferred until the server accepted the new proxy set.

        // Cancel health checks and drop old PluginHandles for removed
        // and changed proxies. Health check tasks hold Arc<AtomicBool> cancel
        // flags — setting them to true stops the health check loop. PluginHandle::Drop
        // sends a oneshot shutdown signal to the plugin task.
        {
            let mut cancels = self.health_cancels.lock().await;
            for name in delta.removed.iter().chain(delta.changed.iter()) {
                // health_cancels is keyed by the wire proxy name ({user}.{name}),
                // matching spawn_health_checks and the CloseProxy handler. Keying
                // by the bare name would leave the health task running forever.
                // The resolved key (wire_keys) uses the registered wire name —
                // for a `user` change in this reload, delta names are already
                // full wire names and rebuilding them with the new user misses.
                let Some(wn) = wire_keys.get(name) else {
                    continue;
                };
                if let Some(cancel) = cancels.get(wn) {
                    cancel.store(true, Ordering::Relaxed);
                }
                cancels.remove(wn);
            }
        }
        {
            // Same removal path for XTCP P2P bridge tokens: reload-removed or
            // changed proxies must not leak active P2P bridges/UDP sockets.
            let mut tokens = self.p2p_bridge_tokens.lock().await;
            for name in delta.removed.iter().chain(delta.changed.iter()) {
                let Some(wn) = wire_keys.get(name) else {
                    continue;
                };
                if let Some(token) = tokens.remove(wn) {
                    token.cancel();
                }
            }
        }
        {
            let mut handles = self
                .plugin_handles
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for name in delta.removed.iter().chain(delta.changed.iter()) {
                if handles.remove(name).is_some() {
                    debug!(proxy_name = %name, "Dropped old plugin handle for '{}'", name);
                }
            }
            // Commit the freshly started plugin handles for added/changed proxies
            // now that the server accepted the new proxy set. For a changed proxy
            // this replaces the handle removed just above.
            for (name, handle) in new_plugin_handles {
                handles.insert(name, handle);
            }
        }

        // Log summary (no longer interleaved with sends, but functionally identical).
        for name in &delta.removed {
            tracing::info!(name = %name, "Reload: sent CloseProxy for removed '{}'", name);
        }
        for name in &delta.changed {
            tracing::info!(name = %name, "Reload: sent CloseProxy+NewProxy for changed '{}'", name);
        }
        for name in &delta.added {
            tracing::info!(name = %name, "Reload: sent NewProxy for added '{}'", name);
        }

        // Advertise vnet subnets only after the corresponding NewProxy has
        // been sent, so the server has a proxy to associate the route with.
        #[cfg(feature = "vnet")]
        for name in delta.added.iter().chain(delta.changed.iter()) {
            if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                send_vnet_route_advertise(writer, v2, p).await;
            }
        }

        // Step 4: Update proxy_info_map so admin API and work conn lookups
        // reflect the new proxy set with correct plugin bound addresses.
        {
            let mut map = self.proxy_info_map.write().await;
            for name in &delta.removed {
                // Registered wire key (see wire_keys above): with a `user`
                // change the delta name IS the old registered key, and
                // rebuilding it with the new user would leave the stale entry
                // in place.
                if let Some(wn) = wire_keys.get(name) {
                    map.remove(wn);
                }
            }
            for name in delta.changed.iter().chain(delta.added.iter()) {
                if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                    let bw_limit =
                        frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
                    let local_addr = plugin_addrs
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                    let plugin_type = p
                        .plugin
                        .as_ref()
                        .map(|pl| pl.plugin_type.clone())
                        .unwrap_or_default();
                    let snapshot = crate::reload::config_snapshot(p);
                    let mut err = String::new();
                    // If this proxy has a plugin but plugin_addrs doesn't have it,
                    // the plugin failed to start — record the error. virtual_net
                    // is not a local-listener plugin (start_plugin skips it, see
                    // the plugin-restart loop above), so its name never lands in
                    // plugin_addrs — stamping the err here would report a false
                    // "failed to start" after every vnet-touching reload
                    // (transient until NewProxyResp clears it).
                    if p.plugin.is_some()
                        && plugin_type != "virtual_net"
                        && !plugin_addrs.contains_key(name)
                    {
                        err = format!("plugin '{}' failed to start", plugin_type);
                    }
                    map.insert(
                        wire_proxy_name(&user, name),
                        ProxyRuntimeInfo {
                            local_addr,
                            proxy_type: p.proxy_type.clone(),
                            use_encryption: p.use_encryption,
                            use_compression: p.use_compression,
                            sk: p.sk.clone(),
                            bandwidth_limit: bw_limit,
                            bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
                            bandwidth_limiter: frp_core::bandwidth::client_side_limiter(
                                bw_limit,
                                &p.bandwidth_limit_mode,
                            ),
                            proxy_protocol_version: p.proxy_protocol_version.clone(),
                            plugin: plugin_type,
                            remote_addr: String::new(),
                            err,
                            config_snapshot: snapshot,
                            // NewProxy for this proxy is already in flight at
                            // the commit point, so the proxy is waiting for
                            // the server's response — WaitStart, not New.
                            // The run_message_loop NewProxyResp arm then
                            // transitions WaitStart → Running (or StartErr
                            // on failure). `New` here would strand the proxy
                            // forever: the message-loop arm only handles
                            // WaitStart | StartErr, and the work-conn phase
                            // gate (Go proxy_wrapper.go InWorkConn parity)
                            // closes work conns unless phase == Running.
                            phase: ProxyPhase::WaitStart,
                        },
                    );
                }
            }
        }

        // Step 5: Spawn health checks for added and changed proxies that
        // have health_check configured. The health_cancels entries for
        // changed proxies were removed in step 1 — re-add them here.
        if !delta.added.is_empty() || !delta.changed.is_empty() {
            let hc_proxies: Vec<frp_core::config::ProxyConfig> = delta
                .new_config
                .proxies
                .iter()
                .filter(|p| delta.added.contains(&p.name) || delta.changed.contains(&p.name))
                .cloned()
                .collect();
            if !hc_proxies.is_empty() {
                // Pass the NEW user explicitly: self.cfg still holds the
                // pre-reload user at this point (refreshed in Step 7 below).
                // Keying the health tasks with the old user would desync them
                // from the wire names registered above.
                self.spawn_health_checks(
                    &user,
                    &hc_proxies,
                    &self.health_tx,
                    &self.health_cancels,
                    &self.health_session_gen,
                )
                .await;
            }
        }

        // Step 6: Update health_proxy_configs to match the new proxy set.
        // This ensures that on HealthEvent::Recover, the correct config is
        // used to re-register the proxy after reload.
        {
            let mut configs = self.health_proxy_configs.lock().await;
            for name in &delta.removed {
                // health_proxy_configs is keyed by the wire proxy name
                // ({user}.{name}), matching the initial population in
                // Service::new and the Recover handler. A stale bare-name
                // entry would let a removed proxy resurrect on recovery. Use
                // the registered wire key (see wire_keys above) so a `user`
                // change in this reload still removes the old-user entry.
                if let Some(wn) = wire_keys.get(name) {
                    configs.remove(wn);
                }
            }
            for name in delta.changed.iter().chain(delta.added.iter()) {
                if let Some(p) = delta.new_config.proxies.iter().find(|p| &p.name == name) {
                    let wn = wire_proxy_name(&user, name);
                    if health_check_monitored(p) {
                        configs.insert(wn, p.clone());
                    } else {
                        configs.remove(&wn);
                    }
                }
            }
        }

        // Step 7: Refresh the in-memory config/proxy snapshots so the next
        // session, reconnect, and admin status endpoint use the merged config.
        *self.cfg.write().await = delta.new_config;
        *self.proxies.write().await = Arc::new(self.cfg.read().await.proxies.clone());

        if visitor_changed {
            // Signal the session loop to restart so visitors are rebuilt.
            self.visitor_reload_needed.store(true, Ordering::Release);
            tracing::info!("Reload changed visitors — requesting session restart");
        }

        let summary = changes.join("; ");
        tracing::info!(summary = %summary, "Config reload summary: {}", summary);
        Ok(format!("reload success: {summary}"))
    }
}

/// Apply the client `start` allowlist and `enabled` flag to a proxy list.
/// Store-backed proxies go through the same filter as config-file proxies.
pub(crate) fn filter_active_proxies(
    cfg: &frp_core::config::ClientConfig,
    proxies: &[frp_core::config::ProxyConfig],
) -> Vec<frp_core::config::ProxyConfig> {
    let mut active: Vec<frp_core::config::ProxyConfig> = if cfg.start.is_empty() {
        proxies.to_vec()
    } else {
        let start_set: std::collections::HashSet<&str> =
            cfg.start.iter().map(|s| s.as_str()).collect();
        let filtered: Vec<_> = proxies
            .iter()
            .filter(|p| start_set.contains(p.name.as_str()))
            .cloned()
            .collect();
        info!(
            active = %filtered.len(), total = %proxies.len(), start = ?cfg.start,
            "Selective proxy start: {} of {} proxies active (start={:?})",
            filtered.len(),
            proxies.len(),
            cfg.start,
        );
        filtered
    };
    active.retain(|p| p.enabled);
    active
}

/// Apply the client `start` allowlist and `enabled` flag to a visitor list.
/// Mirrors Go frp v0.70.1 `FilterClientConfigurers`, which filters visitors by
/// the same `start` set as proxies.
pub(crate) fn filter_active_visitors(
    cfg: &frp_core::config::ClientConfig,
    visitors: &[frp_core::config::VisitorConfig],
) -> Vec<frp_core::config::VisitorConfig> {
    let mut active: Vec<frp_core::config::VisitorConfig> = if cfg.start.is_empty() {
        visitors.to_vec()
    } else {
        let start_set: std::collections::HashSet<&str> =
            cfg.start.iter().map(|s| s.as_str()).collect();
        let filtered: Vec<_> = visitors
            .iter()
            .filter(|v| start_set.contains(v.name.as_str()))
            .cloned()
            .collect();
        info!(
            active = %filtered.len(), total = %visitors.len(), start = ?cfg.start,
            "Selective visitor start: {} of {} visitors active (start={:?})",
            filtered.len(),
            visitors.len(),
            cfg.start,
        );
        filtered
    };
    active.retain(|v| v.enabled);
    active
}
