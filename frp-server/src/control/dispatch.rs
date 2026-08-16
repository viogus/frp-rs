//! Control message dispatch — pure routing from message variants to handlers.
//!
//! These functions contain NO business logic. They match on message type
//! and delegate to the appropriate handler in `pool`, `nathole`, or `proxy`.

use std::future::Future;
use std::pin::Pin;
use tokio::io::AsyncWriteExt;

use frp_core::msg::{self, FrpMessage};

use crate::service::InternalMsg;

use super::{ControlContext, ControlState};

// ── InternalMsg dispatch ─────────────────────────────────────────────

/// Non-async match that returns a boxed future for the matched handler.
#[inline(never)]
fn match_internal_dispatch<'a, W: AsyncWriteExt + Unpin + Send + 'a>(
    ctx: &'a mut ControlContext,
    ctl: &'a mut ControlState,
    writer: &'a mut W,
    msg: InternalMsg,
) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
    match msg {
        InternalMsg::NewWorkConn(s) => {
            Box::pin(super::pool::handle_new_work_conn(ctx, ctl, writer, s))
        }
        InternalMsg::VisitorConn {
            proxy_name,
            visitor_conn,
            visitor_use_encryption,
            visitor_use_compression,
            visitor_v2,
            visitor_udp_packet_codec,
        } => Box::pin(super::pool::handle_visitor_conn(
            ctx,
            ctl,
            writer,
            proxy_name,
            visitor_conn,
            visitor_use_encryption,
            visitor_use_compression,
            visitor_v2,
            visitor_udp_packet_codec,
        )),
        InternalMsg::ProxyUserConn {
            proxy_name,
            user_conn,
            pre_read,
            user_conn_permit,
            group_selected,
        } => Box::pin(super::pool::handle_proxy_user_conn(
            ctx,
            ctl,
            writer,
            proxy_name,
            user_conn,
            pre_read,
            user_conn_permit,
            group_selected,
        )),
        InternalMsg::UdpNeedsWorkConn { proxy_name } => Box::pin(
            super::pool::handle_udp_work_conn(ctx, ctl, writer, proxy_name),
        ),
        InternalMsg::NatHoleSidOnWorkConn { sid, proxy_name } => Box::pin(
            super::nathole::handle_sid_on_work_conn(ctx, ctl, writer, sid, proxy_name),
        ),
        InternalMsg::WriteNatHoleSid { sid } => Box::pin(async move {
            super::nathole::handle_write_sid(ctx, ctl, writer, sid).await;
            Ok(())
        }),
        InternalMsg::WriteNatHoleResp {
            transaction_id,
            error,
            sid,
            protocol,
            candidate_addrs,
            assisted_addrs,
            detect_behavior,
        } => Box::pin(async move {
            super::nathole::handle_write_resp(
                ctx,
                ctl,
                writer,
                msg::NatHoleResp {
                    transaction_id,
                    error,
                    sid,
                    protocol,
                    candidate_addrs,
                    assisted_addrs,
                    detect_behavior,
                },
            )
            .await;
            Ok(())
        }),
        InternalMsg::WriteNatHoleReport { sid } => Box::pin(async move {
            super::nathole::handle_write_report(ctx, ctl, writer, sid).await;
            Ok(())
        }),
        #[cfg(feature = "vnet")]
        InternalMsg::VnetPacketForward { proxy_name, data } => Box::pin(async move {
            super::nathole::handle_vnet_packet_forward(ctx, ctl, writer, proxy_name, data).await;
            Ok(())
        }),
        #[cfg(feature = "vnet")]
        InternalMsg::VnetRouteAdvertiseForward { msg } => Box::pin(async move {
            super::nathole::handle_vnet_route_advertise_forward(ctx, ctl, writer, msg).await;
            Ok(())
        }),
        #[cfg(feature = "vnet")]
        InternalMsg::VnetRouteRemoveForward { msg } => Box::pin(async move {
            super::nathole::handle_vnet_route_remove_forward(ctx, ctl, writer, msg).await;
            Ok(())
        }),
        InternalMsg::WriteCloseProxy { proxy_name } => Box::pin(async move {
            super::proxy::handle_write_close_proxy(ctx, ctl, writer, proxy_name).await;
            Ok(())
        }),
        InternalMsg::Shutdown { done } => Box::pin(async move {
            tracing::warn!(
                run_id = %ctx.run_id,
                "Shutdown received for run_id {} (replaced by new control connection)",
                ctx.run_id
            );
            ctl.shutting_down = true;
            ctl.shutdown_done = Some(done);
            Err(())
        }),
    }
}

/// Async wrapper around `match_internal_dispatch`.
pub(crate) async fn dispatch_internal<W: AsyncWriteExt + Unpin + Send>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    msg: InternalMsg,
) -> Result<(), ()> {
    match_internal_dispatch(ctx, ctl, writer, msg).await
}

// ── FrpMessage dispatch ─────────────────────────────────────────────

/// Non-async match that returns a boxed future for the matched handler.
/// This avoids having the 16-arm dispatch inside the async state machine
/// of `dispatch_frp_message`, reducing its closure size.
#[inline(never)]
fn match_dispatch<'a, W: AsyncWriteExt + Unpin + Send + 'a>(
    ctx: &'a mut ControlContext,
    ctl: &'a mut ControlState,
    writer: &'a mut W,
    msg: FrpMessage,
    login_user: &'a str,
) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
    match msg {
        FrpMessage::NewProxy(m) => Box::pin(super::proxy::handle_new_proxy(ctx, ctl, writer, *m)),
        FrpMessage::CloseProxy(m) => {
            Box::pin(super::proxy::handle_close_proxy(ctx, ctl, writer, m))
        }
        FrpMessage::Ping(m) => Box::pin(super::proxy::handle_ping(ctx, ctl, writer, m)),
        FrpMessage::NatHoleClient(m) => Box::pin(async move {
            super::nathole::handle_nat_hole_client(ctx, ctl, writer, *m).await;
            Ok(())
        }),
        FrpMessage::NatHoleSid(m) => Box::pin(async move {
            super::nathole::handle_nat_hole_sid(ctx, ctl, writer, m).await;
            Ok(())
        }),
        FrpMessage::NatHoleResp(m) => Box::pin(async move {
            super::nathole::handle_nat_hole_resp(ctx, ctl, writer, *m).await;
            Ok(())
        }),
        FrpMessage::NatHoleReport(m) => Box::pin(async move {
            super::nathole::handle_nat_hole_report(ctx, ctl, writer, m).await;
            Ok(())
        }),
        FrpMessage::NatHoleVisitor(m) => Box::pin(super::nathole::handle_nat_hole_visitor_on_ctl(
            ctx, ctl, writer, m, login_user,
        )),
        FrpMessage::NewVisitorConn(m) => Box::pin(async move {
            super::nathole::handle_new_visitor_conn(ctx, ctl, writer, m, login_user).await;
            Ok(())
        }),
        #[cfg(feature = "vnet")]
        FrpMessage::VnetRouteAdvertise(m) => Box::pin(async move {
            super::nathole::handle_vnet_route_advertise(ctx, ctl, writer, m).await;
            Ok(())
        }),
        #[cfg(feature = "vnet")]
        FrpMessage::VnetPacket(m) => Box::pin(async move {
            super::nathole::handle_vnet_packet(ctx, ctl, writer, m).await;
            Ok(())
        }),
        #[cfg(feature = "vnet")]
        FrpMessage::VnetRouteRemove(m) => Box::pin(async move {
            super::nathole::handle_vnet_route_remove(ctx, ctl, writer, m).await;
            Ok(())
        }),
        other => Box::pin(async move {
            tracing::debug!("unhandled control msg: {:?}", other.v1_type_byte());
            Ok(())
        }),
    }
}

/// Async wrapper around `match_dispatch`. The state machine has only
/// two variants (start + await boxed future), shrinking from the
/// original 16-arm inline match.
pub(crate) async fn dispatch_frp_message<W: AsyncWriteExt + Unpin + Send>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    msg: FrpMessage,
    login_user: &str,
) -> Result<(), ()> {
    match_dispatch(ctx, ctl, writer, msg, login_user).await
}
