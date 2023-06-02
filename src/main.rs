const SSID: &str = env!("MICRO_RDK_WIFI_SSID");
const PASS: &str = env!("MICRO_RDK_WIFI_PASSWORD");

// Generated robot config during build process
include!(concat!(env!("OUT_DIR"), "/robot_secret.rs"));

#[cfg(feature = "staticconf")]
use micro_rdk::common::config::RobotConfigStatic;
#[cfg(feature = "staticconf")]
include!(concat!(env!("OUT_DIR"), "/robot_config.rs"));
#[cfg(feature = "staticconf")]
use micro_rdk::common::config::{Kind, StaticComponentConfig};

use anyhow::bail;
use esp_idf_hal::prelude::Peripherals;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::netif::{EspNetif, EspNetifWait};
use esp_idf_svc::wifi::EspWifi;
use esp_idf_sys as _; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported
use esp_idf_sys::esp_wifi_set_ps;
use log::*;
use micro_rdk::common::robot::LocalRobot;
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
    let robot = {
        use esp_idf_hal::adc::config::Config;
        use esp_idf_hal::adc::{self, AdcChannelDriver, AdcDriver, Atten11dB};
        use esp_idf_hal::gpio::IOPin;
        use esp_idf_hal::gpio::PinDriver;
        use micro_rdk::common::analog::AnalogReader;
        use micro_rdk::common::robot::ResourceType;
        use micro_rdk::esp32::analog::Esp32AnalogReader;
        use micro_rdk::esp32::board::EspBoard;
        use micro_rdk::proto::common::v1::ResourceName;
        use std::cell::RefCell;
        use std::collections::HashMap;
        use std::rc::Rc;
        use std::sync::Arc;
        use std::sync::Mutex;

        let pins = vec![
            PinDriver::input_output(periph.pins.gpio18.downgrade())?,
        ];

        let adc1 = Rc::new(RefCell::new(AdcDriver::new(
            periph.adc1,
            &Config::new().calibration(true),
        )?));

        let adc_chan: AdcChannelDriver<_, Atten11dB<adc::ADC1>> =
            AdcChannelDriver::new(periph.pins.gpio34)?;
        let analog1 = Esp32AnalogReader::new("A1".to_string(), adc_chan, adc1.clone());

        let analog_readers: Vec<
            Rc<RefCell<(dyn AnalogReader<u16, Error = anyhow::Error> + 'static)>>,
        > = vec![Rc::new(RefCell::new(analog1))];

        let board = EspBoard::new(pins, analog_readers, HashMap::new());

        let board = Arc::new(Mutex::new(board));

        let mut res: micro_rdk::common::robot::ResourceMap = HashMap::with_capacity(1);

        res.insert(
            ResourceName {
                namespace: "rdk".to_string(),
                r#type: "component".to_string(),
                subtype: "board".to_string(),
                name: "board".to_string(),
            },
            ResourceType::Board(board),
        );

        LocalRobot::new(res)
    };

    #[cfg(feature = "staticconf")]
    let robot = {
        let robot = LocalRobot::new_from_static(&STATIC_ROBOT_CONFIG.unwrap());
        if robot.is_err() {
            log::info!(
                "failure to build robot with {:?}",
                robot.as_ref().err().unwrap()
            );
        }
        robot.unwrap()
    };

    let (ip, _wifi) = {
        let wifi = start_wifi(periph.modem, sys_loop_stack)?;
        (wifi.sta_netif().get_ip_info()?.ip, wifi)
    };
    #[cfg(not(feature = "webrtc"))]
    {
        use micro_rdk::esp32::server::{CloudConfig, Esp32Server};
        use micro_rdk::esp32::tls::Esp32TlsServerConfig;
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

        let mut cloud_cfg = CloudConfig::new(ROBOT_NAME, LOCAL_FQDN, FQDN, ROBOT_ID, ROBOT_SECRET);
        cloud_cfg.set_tls_config(cfg);
        let esp32_srv = Esp32Server::new(robot, cloud_cfg);
        esp32_srv.start(ip)?;
        Ok(())
    }

    #[cfg(feature = "webrtc")]
    {
        use futures_lite::future::block_on;
        use micro_rdk::common::app_client::{AppClientBuilder, AppClientConfig};
        use micro_rdk::common::grpc::GrpcServer;
        use micro_rdk::common::grpc_client::GrpcClient;
        use micro_rdk::common::webrtc::grpc::{WebRtcGrpcBody, WebRtcGrpcServer};
        use micro_rdk::esp32::certificate::WebRtcCertificate;
        use micro_rdk::esp32::dtls::Esp32Dtls;
        use micro_rdk::esp32::exec::Esp32Executor;
        use micro_rdk::esp32::tcp::Esp32Stream;
        use micro_rdk::esp32::tls::Esp32Tls;
        use std::rc::Rc;
        use std::sync::Arc;
        use std::sync::Mutex;
        log::info!("Starting WebRtc ");
        let cfg = AppClientConfig::new(ROBOT_SECRET.to_owned(), ROBOT_ID.to_owned(), ip);
        let executor = Esp32Executor::new();
        let mut webrtc = {
            let mut tls = Box::new(Esp32Tls::new_client());
            let conn = tls.open_ssl_context(None).unwrap();
            let conn = Esp32Stream::TLSStream(Box::new(conn));

            let grpc_client =
                GrpcClient::new(conn, executor.clone(), "https://app.viam.com:443").unwrap();
            let mut app_client = AppClientBuilder::new(grpc_client, cfg).build().unwrap();

            let webrtc_certificate = Rc::new(WebRtcCertificate::new(
                ROBOT_DTLS_CERT,
                ROBOT_DTLS_KEY_PAIR,
                ROBOT_DTLS_CERT_FP,
            ));

            let dtls = Esp32Dtls::new(webrtc_certificate.clone()).unwrap();

            let webrtc = app_client
                .connect_webrtc(webrtc_certificate, executor.clone(), dtls)
                .unwrap();

            drop(app_client);
            webrtc
        };
        let channel = block_on(executor.run(async { webrtc.open_data_channel().await })).unwrap();
        log::info!("channel opened {:?}", channel);

        let mut webrtc_grpc = WebRtcGrpcServer::new(
            channel,
            GrpcServer::new(Arc::new(Mutex::new(robot)), WebRtcGrpcBody::default()),
        );

        loop {
            block_on(executor.run(async { webrtc_grpc.next_request().await })).unwrap();
        }
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
