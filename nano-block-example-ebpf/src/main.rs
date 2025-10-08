#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{error, info};
use nano_block_ebpf::{check_packet, utils::ptr_at};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};
#[xdp]
pub fn nano_block_example(ctx: XdpContext) -> u32 {
    match try_nano_block_example(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_nano_block_example(ctx: XdpContext) -> Result<u32, ()> {
    let transport_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let des_port = if let Ok(port_ptr) = ptr_at::<u16>(&ctx, transport_offset + 2) {
        u16::from_be(unsafe { *port_ptr })
    } else {
        return Ok(xdp_action::XDP_PASS);
    };

    if des_port == 22 {
        return Ok(xdp_action::XDP_PASS);
    }

    if des_port == 3000 {
        info!(&ctx, "packet at 3000");
    }

    if let Err(_) = check_packet(&ctx) {
        error!(&ctx, "Firewall Error");
        return Ok(xdp_action::XDP_PASS);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
