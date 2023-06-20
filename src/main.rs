const SSID: &str = env!("MICRO_RDK_WIFI_SSID");
const PASS: &str = env!("MICRO_RDK_WIFI_PASSWORD");

// Generated robot config during build process
include!(concat!(env!("OUT_DIR"), "/robot_secret.rs"));

#[cfg(feature = "staticconf")]
use micro_rdk::common::config::RobotConfigStatic;
#[cfg(feature = "staticconf")]
include!(concat!(env!("OUT_DIR"), "/robot_config.rs"));
use anyhow::bail;
use esp_idf_hal::prelude::Peripherals;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::netif::{EspNetif, EspNetifWait};
use esp_idf_svc::wifi::EspWifi;
use esp_idf_sys as _; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported
use esp_idf_sys::esp_wifi_set_ps;
use log::*;
use micro_rdk::common::app_client::AppClientConfig;
#[cfg(feature = "staticconf")]
use micro_rdk::common::config::{Kind, StaticComponentConfig};
use micro_rdk::esp32::certificate::WebRtcCertificate;
use micro_rdk::esp32::entry::serve_web;
use micro_rdk::esp32::tls::Esp32TlsServerConfig;

use std::time::Duration;

fn main() -> anyhow::Result<()> {
    esp_idf_sys::link_patches();

    esp_idf_svc::log::EspLogger::initialize_default();
    let sys_loop_stack = EspSystemEventLoop::take().unwrap();
    {
        esp_idf_sys::esp!(unsafe {
            esp_idf_sys::esp_vfs_eventfd_register(&esp_idf_sys::esp_vfs_eventfd_config_t {
                max_fds: 5,
            })
        })?;
    }

    let periph = Peripherals::take().unwrap();

    #[cfg(not(feature = "staticconf"))]
    let robot = None;

    #[cfg(feature = "staticconf")]
    let robot = {
        use micro_rdk::common::robot::LocalRobot;
        let robot = LocalRobot::new_from_static(&STATIC_ROBOT_CONFIG.unwrap());
        if robot.is_err() {
            log::info!(
                "failure to build robot with {:?}",
                robot.as_ref().err().unwrap()
            );
        }
        Some(robot.unwrap())
    };

    let (ip, _wifi) = {
        let wifi = start_wifi(periph.modem, sys_loop_stack)?;
        (wifi.sta_netif().get_ip_info()?.ip, wifi)
    };
    let cfg = AppClientConfig::new(
        ROBOT_SECRET.to_owned(),
        ROBOT_ID.to_owned(),
        ip,
        "".to_owned(),
    );
    let webrtc_certificate =
        WebRtcCertificate::new(ROBOT_DTLS_CERT, ROBOT_DTLS_KEY_PAIR, ROBOT_DTLS_CERT_FP);

    let tls_cfg = {
        let cert = include_bytes!(concat!(env!("OUT_DIR"), "/ca.crt"));
        let key = include_bytes!(concat!(env!("OUT_DIR"), "/key.key"));
        Esp32TlsServerConfig::new(
            cert.as_ptr(),
            cert.len() as u32,
            key.as_ptr(),
            key.len() as u32,
        )
    };

    serve_web(cfg, tls_cfg, robot, ip, webrtc_certificate);
    Ok(())
}

fn start_wifi(
    modem: impl esp_idf_hal::peripheral::Peripheral<P = esp_idf_hal::modem::Modem> + 'static,
    sl_stack: EspSystemEventLoop,
) -> anyhow::Result<Box<EspWifi<'static>>> {
    use embedded_svc::wifi::{ClientConfiguration, Wifi};
    use esp_idf_svc::wifi::WifiWait;
    use std::net::Ipv4Addr;

    let mut wifi = Box::new(EspWifi::new(modem, sl_stack.clone(), None)?);

    info!("scanning");
    let aps = wifi.scan()?;
    let foundap = aps.into_iter().find(|x| x.ssid == SSID);

    let channel = if let Some(foundap) = foundap {
        info!("{} channel is {}", "Viam", foundap.channel);
        Some(foundap.channel)
    } else {
        None
    };
    let client_config = ClientConfiguration {
        ssid: SSID.into(),
        password: PASS.into(),
        channel,
        ..Default::default()
    };
    wifi.set_configuration(&embedded_svc::wifi::Configuration::Client(client_config))?; //&Configuration::Client(client_config)

    wifi.start()?;

    if !WifiWait::new(&sl_stack)?
        .wait_with_timeout(Duration::from_secs(20), || wifi.is_started().unwrap())
    {
        bail!("couldn't start wifi")
    }

    wifi.connect()?;

    if !EspNetifWait::new::<EspNetif>(wifi.sta_netif(), &sl_stack)?.wait_with_timeout(
        Duration::from_secs(20),
        || {
            wifi.is_connected().unwrap()
                && wifi.sta_netif().get_ip_info().unwrap().ip != Ipv4Addr::new(0, 0, 0, 0)
        },
    ) {
        bail!("wifi couldn't connect")
    }

    let ip_info = wifi.sta_netif().get_ip_info()?;

    info!("Wifi DHCP info: {:?}", ip_info);

    esp_idf_sys::esp!(unsafe { esp_wifi_set_ps(esp_idf_sys::wifi_ps_type_t_WIFI_PS_NONE) })?;

    Ok(wifi)
}
