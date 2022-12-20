const SSID: &str = env!("MINI_RDK_WIFI_SSID");
const PASS: &str = env!("MINI_RDK_WIFI_PASSWORD");

// Generated robot config during build process
include!(concat!(env!("OUT_DIR"), "/robot_secret.rs"));

use anyhow::bail;
use esp_idf_hal::prelude::Peripherals;
use esp_idf_hal::task::notify;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::mdns::EspMdns;
use esp_idf_svc::netif::{EspNetif, EspNetifWait};
use esp_idf_svc::wifi::EspWifi;
use esp_idf_sys::esp_wifi_set_ps;
use esp_idf_sys::vTaskDelay;
use esp_idf_sys::{self as _, TaskHandle_t}; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported
use futures_lite::future::block_on;
use hyper::server::conn::Http;
use log::*;
use mini_rdk::esp32::exec::Esp32Executor;
use mini_rdk::esp32::grpc::GrpcServer;
use mini_rdk::esp32::robot::Esp32Robot;
use mini_rdk::esp32::robot::ResourceType;
use mini_rdk::esp32::robot_client::RobotClientConfig;
use mini_rdk::esp32::tcp::Esp32Listener;
use mini_rdk::esp32::tls::{Esp32Tls, Esp32TlsServerConfig};
use mini_rdk::proto::common::v1::ResourceName;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
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

    let robot = {
        use esp_idf_hal::adc::config::Config;
        use esp_idf_hal::adc::{self, AdcChannelDriver, AdcDriver, Atten11dB};
        use esp_idf_hal::gpio::PinDriver;
        use mini_rdk::esp32::analog::Esp32AnalogReader;
        use mini_rdk::esp32::board::EspBoard;

        let pins = vec![PinDriver::output(periph.pins.gpio15)?];

        let adc1 = Rc::new(RefCell::new(AdcDriver::new(
            periph.adc1,
            &Config::new().calibration(true),
        )?));

        let adc_chan: AdcChannelDriver<_, Atten11dB<adc::ADC1>> =
            AdcChannelDriver::new(periph.pins.gpio34)?;
        let analog1 = Esp32AnalogReader::new("A1".to_string(), adc_chan, adc1.clone());

        let adc_chan: AdcChannelDriver<_, Atten11dB<adc::ADC1>> =
            AdcChannelDriver::new(periph.pins.gpio35)?;
        let analog2 = Esp32AnalogReader::new("A2".to_string(), adc_chan, adc1.clone());

        let board = EspBoard::new(
            pins,
            vec![
                Rc::new(RefCell::new(analog1)),
                Rc::new(RefCell::new(analog2)),
            ],
        );

        let board = Arc::new(Mutex::new(board));

        let mut res: mini_rdk::esp32::robot::ResourceMap = HashMap::with_capacity(1);

        res.insert(
            ResourceName {
                namespace: "rdk".to_string(),
                r#type: "component".to_string(),
                subtype: "board".to_string(),
                name: "board".to_string(),
            },
            ResourceType::Board(board),
        );

        Esp32Robot::new(res)
    };

    let (ip, _wifi) = {
        let wifi = start_wifi(periph.modem, sys_loop_stack)?;
        (wifi.sta_netif().get_ip_info()?.ip, wifi)
    };

    let client_cfg = { RobotClientConfig::new(ROBOT_SECRET.to_string(), ROBOT_ID.to_string(), ip) };

    let hnd = match mini_rdk::esp32::robot_client::start(client_cfg) {
        Err(e) => {
            log::error!("couldn't start robot client {:?} will start the server", e);
            None
        }
        Ok(hnd) => Some(hnd),
    };

    // start mdns service
    let _mdms = {
        let mut mdns = EspMdns::take()?;
        mdns.set_hostname(ROBOT_NAME)?;
        mdns.set_instance_name(ROBOT_NAME)?;
        mdns.add_service(None, "_rpc", "_tcp", 80, &[])?;
        mdns
    };

    if let Err(e) = runserver(robot, hnd) {
        log::error!("robot server failed with error {:?}", e);
        return Err(e);
    }

    Ok(())
}

fn runserver(robot: Esp32Robot, client_handle: Option<TaskHandle_t>) -> anyhow::Result<()> {
    let cfg = {
        let cert = include_bytes!(concat!(env!("OUT_DIR"), "/ca.crt"));
        let key = include_bytes!(concat!(env!("OUT_DIR"), "/key.key"));
        Esp32TlsServerConfig::new(
            cert.as_ptr(),
            cert.len() as u32,
            key.as_ptr(),
            key.len() as u32,
        )
    };
    let tls = Box::new(Esp32Tls::new_server(&cfg));
    let address: SocketAddr = "0.0.0.0:80".parse().unwrap();
    let mut listener = Esp32Listener::new(address.into(), Some(tls))?;
    let exec = Esp32Executor::new();
    let srv = GrpcServer::new(Arc::new(Mutex::new(robot)));
    if let Some(hnd) = client_handle {
        if unsafe { notify(hnd, 1) } {
            log::info!("successfully notified client task");
            unsafe {
                vTaskDelay(1000);
            };
        } else {
            log::error!("failed to notity client task had handle {:?}", hnd);
        }
    } else {
        log::error!("no handle")
    }
    loop {
        let stream = listener.accept()?;
        block_on(exec.run(async {
            let err = Http::new()
                .with_executor(exec.clone())
                .http2_max_concurrent_streams(1)
                .serve_connection(stream, srv.clone())
                .await;
            if err.is_err() {
                log::error!("server error {}", err.err().unwrap());
            }
        }));
    }
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
