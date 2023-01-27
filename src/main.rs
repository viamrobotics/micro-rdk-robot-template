const SSID: &str = env!("MICRO_RDK_WIFI_SSID");
const PASS: &str = env!("MICRO_RDK_WIFI_PASSWORD");

// Generated robot config during build process
include!(concat!(env!("OUT_DIR"), "/robot_secret.rs"));

use anyhow::bail;
use esp_idf_hal::prelude::Peripherals;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::netif::{EspNetif, EspNetifWait};
use esp_idf_svc::wifi::EspWifi;
use esp_idf_sys as _; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported
use esp_idf_sys::esp_wifi_set_ps;
use log::*;
use micro_rdk::common::robot::LocalRobot;
use micro_rdk::common::robot::ResourceType;
use micro_rdk::esp32::server::{CloudConfig, Esp32Server};
use micro_rdk::esp32::tls::Esp32TlsServerConfig;
use micro_rdk::proto::common::v1::ResourceName;
use std::cell::RefCell;
use std::collections::HashMap;
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
        use esp_idf_hal::gpio::OutputPin;
        use esp_idf_hal::gpio::PinDriver;
        use micro_rdk::common::analog::AnalogReader;
        use micro_rdk::esp32::analog::Esp32AnalogReader;
        use micro_rdk::esp32::board::EspBoard;

        let pins = vec![PinDriver::output(periph.pins.gpio18.downgrade_output())?];

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

        let board = EspBoard::new(pins, analog_readers);

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

    let (ip, _wifi) = {
        let wifi = start_wifi(periph.modem, sys_loop_stack)?;
        (wifi.sta_netif().get_ip_info()?.ip, wifi)
    };
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
