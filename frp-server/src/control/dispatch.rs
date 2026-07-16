//! Control message dispatch — pure routing from message variants to handlers.
//!
//! These functions contain NO business logic. They match on message type
//! and delegate to the appropriate handler in `pool`, `nathole`, or `proxy`.

use tokio::io::AsyncWriteExt;

use frp_core::msg::FrpMessage;

use crate::service::InternalMsg;

use super::{ControlContext, ControlState};

// ── InternalMsg dispatch ─────────────────────────────────────────────

pub(crate) async fn dispatch_internal<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    msg: InternalMsg,
) -> Result<(), ()> {
    match msg {
        InternalMsg::NewWorkConn(s) => super::pool::handle_new_work_conn(ctx, ctl, writer, s).await,
        InternalMsg::VisitorConn {
            proxy_name,
            visitor_conn,
        } => super::pool::handle_visitor_conn(ctx, ctl, writer, proxy_name, visitor_conn).await,
        InternalMsg::ProxyUserConn {
            proxy_name,
            user_conn,
            pre_read,
        } => {
            super::pool::handle_proxy_user_conn(ctx, ctl, writer, proxy_name, user_conn, pre_read)
                .await
        }
        InternalMsg::UdpNeedsWorkConn { proxy_name } => {
            super::pool::handle_udp_work_conn(ctx, ctl, writer, proxy_name).await
        }
        InternalMsg::NatHoleSidOnWorkConn { sid, proxy_name } => {
            super::nathole::handle_sid_on_work_conn(ctx, ctl, writer, sid, proxy_name).await
        }
        InternalMsg::WriteNatHoleSid { sid, provider_addr } => {
            super::nathole::handle_write_sid(ctx, ctl, writer, sid, provider_addr).await;
            Ok(())
        }
        InternalMsg::WriteNatHoleResp {
            transaction_id,
            error,
            sid,
            protocol,
            candidate_addrs,
            assisted_addrs,
        } => {
            super::nathole::handle_write_resp(
                ctx,
                ctl,
                writer,
                transaction_id,
                error,
                sid,
                protocol,
                candidate_addrs,
                assisted_addrs,
            )
            .await;
            Ok(())
        }
        InternalMsg::WriteNatHoleReport { sid } => {
            super::nathole::handle_write_report(ctx, ctl, writer, sid).await;
            Ok(())
        }
        #[cfg(feature = "vnet")]
        InternalMsg::VnetPacketForward { proxy_name, data } => {
            super::nathole::handle_vnet_packet_forward(ctx, ctl, writer, proxy_name, data).await;
            Ok(())
        }
        InternalMsg::Shutdown => {
            tracing::warn!(
                run_id = %ctx.run_id,
                "Shutdown received for run_id {} (replaced by new control connection)",
                ctx.run_id
            );
            ctl.shutting_down = true;
            // Return Err to trigger loop break via is_err() in mod.rs,
            // so that cleanup runs after the select! loop exits.
            Err(())
        }
    }
}

// ── FrpMessage dispatch ─────────────────────────────────────────────

pub(crate) async fn dispatch_frp_message<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    msg: FrpMessage,
    login_user: &str,
) -> Result<(), ()> {
    match msg {
        FrpMessage::NewProxy(m) => super::proxy::handle_new_proxy(ctx, ctl, writer, m).await,
        FrpMessage::CloseProxy(m) => super::proxy::handle_close_proxy(ctx, ctl, writer, m).await,
        FrpMessage::Ping(m) => super::proxy::handle_ping(ctx, ctl, writer, m).await,
        FrpMessage::UDPPacket(m) => super::proxy::handle_udp_packet(ctx, ctl, writer, m).await,
        FrpMessage::NatHoleClient(m) => {
            super::nathole::handle_nat_hole_client(ctx, ctl, writer, m).await;
            Ok(())
        }
        FrpMessage::NatHoleSid(m) => {
            super::nathole::handle_nat_hole_sid(ctx, ctl, writer, m).await;
            Ok(())
        }
        FrpMessage::NatHoleResp(m) => {
            super::nathole::handle_nat_hole_resp(ctx, ctl, writer, m).await;
            Ok(())
        }
        FrpMessage::NatHoleReport(m) => {
            super::nathole::handle_nat_hole_report(ctx, ctl, writer, m).await;
            Ok(())
        }
        FrpMessage::NatHoleVisitor(m) => {
            super::nathole::handle_nat_hole_visitor_on_ctl(ctx, ctl, writer, m, login_user).await
        }
        FrpMessage::NewVisitorConn(m) => {
            super::nathole::handle_new_visitor_conn(ctx, ctl, writer, m, login_user).await;
            Ok(())
        }
        #[cfg(feature = "vnet")]
        FrpMessage::VnetRouteAdvertise(m) => {
            super::nathole::handle_vnet_route_advertise(ctx, ctl, writer, m).await;
            Ok(())
        }
        #[cfg(feature = "vnet")]
        FrpMessage::VnetPacket(m) => {
            super::nathole::handle_vnet_packet(ctx, ctl, writer, m).await;
            Ok(())
        }
        #[cfg(feature = "vnet")]
        FrpMessage::VnetRouteRemove(m) => {
            super::nathole::handle_vnet_route_remove(ctx, ctl, writer, m).await;
            Ok(())
        }
        other => {
            tracing::debug!("unhandled control msg: {:?}", other.v1_type_byte());
            Ok(())
        }
    }
}
