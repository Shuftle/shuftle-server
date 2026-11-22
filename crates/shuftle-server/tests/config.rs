//! Reading the configuration file.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::ensure;
use proptest::{
    option, prop_assert, prop_oneof, proptest, sample,
    strategy::{Just, Strategy},
};
use shuftle_server::config::{AllowedOrigin, Config, Cors};

#[test]
fn reads_the_listen_address() -> anyhow::Result<()> {
    let actual: Config = r#"
        listen = "0.0.0.0:50051"

        [cors]
        allowed_origins = []
    "#
    .parse()?;

    let expected = Config {
        listen: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 50051)),
        cors: Cors {
            allowed_origins: Vec::new(),
        },
    };
    ensure!(actual == expected, "got {actual:?}, expected {expected:?}");
    Ok(())
}

/// The parts of an origin as browsers send it: a scheme with its default port, a lowercase host
/// and a port only when it is not the scheme's default.
fn origin_parts() -> impl Strategy<Value = (&'static str, u16, String, Option<u16>)> {
    let scheme = prop_oneof![(Just("http"), Just(80_u16)), (Just("https"), Just(443_u16))];
    let host = "[a-z][a-z0-9]{0,10}(\\.[a-z][a-z0-9]{0,10}){0,3}";
    (scheme, host, option::of(1_u16..))
        .prop_filter("default port", |((_, default_port), _, port)| {
            *port != Some(*default_port)
        })
        .prop_map(|((scheme, default_port), host, port)| (scheme, default_port, host, port))
}

/// Origins written as browsers send them.
fn canonical_origin() -> impl Strategy<Value = String> {
    origin_parts().prop_map(|(scheme, _, host, port)| match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

/// An origin as browsers send it, and the same origin written in a way browsers never send.
fn damaged_origin() -> impl Strategy<Value = (String, String)> {
    origin_parts().prop_flat_map(|(scheme, default_port, host, port)| {
        let origin = match port {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        };
        let mut damaged = vec![
            format!("{origin}/"),
            format!("{origin}/x"),
            format!("{origin}?x"),
            format!("{origin}#x"),
            format!("{scheme}://user@{}", &origin[scheme.len() + "://".len()..]),
            origin.to_uppercase(),
        ];
        if port.is_none() {
            damaged.push(format!("{origin}:{default_port}"));
        }
        (Just(origin), sample::select(damaged))
    })
}

/// URLs whose scheme is neither http nor https, with and without a host.
fn other_scheme_url() -> impl Strategy<Value = String> {
    let scheme = "[a-z][a-z0-9+.-]{0,8}".prop_filter("http or https", |scheme| {
        scheme != "http" && scheme != "https"
    });
    let host = "[a-z][a-z0-9]{0,10}";
    (scheme, host).prop_flat_map(|(scheme, host)| {
        sample::select(vec![
            format!("{scheme}://{host}"),
            format!("{scheme}:///{host}"),
            format!("{scheme}:{host}"),
        ])
    })
}

/// Text that is not a URL, and why the URL parser refuses it.
fn unparsable_url() -> impl Strategy<Value = (String, &'static str)> {
    let host = "[a-z][a-z0-9]{0,10}";
    prop_oneof![
        host.prop_map(|host| (host, "relative URL without a base")),
        prop_oneof![Just("http"), Just("https")]
            .prop_map(|scheme| (format!("{scheme}://"), "empty host")),
        (host, 65536_u32..)
            .prop_map(|(host, port)| (format!("http://{host}:{port}"), "invalid port number")),
    ]
}

proptest! {
    #[test]
    fn accepts_canonical_origins(origin in canonical_origin()) {
        let result = AllowedOrigin::try_from(origin.clone());
        prop_assert!(result.is_ok(), "`{origin}` refused: {result:?}");
    }

    #[test]
    fn refuses_other_spellings_suggesting_the_origin((origin, damaged) in damaged_origin()) {
        let result = AllowedOrigin::try_from(damaged.clone());
        let expected = format!("`{damaged}` is not an origin: did you mean `{origin}`?");
        prop_assert!(
            result.as_ref().is_err_and(|error| error.to_string() == expected),
            "got {result:?}, expected {expected}"
        );
    }

    #[test]
    fn refuses_other_schemes(url in other_scheme_url()) {
        let result = AllowedOrigin::try_from(url.clone());
        let expected = format!("`{url}` is not an origin: the scheme must be http or https");
        prop_assert!(
            result.as_ref().is_err_and(|error| error.to_string() == expected),
            "got {result:?}, expected {expected}"
        );
    }

    #[test]
    fn refuses_text_that_is_not_a_url((text, reason) in unparsable_url()) {
        let result = AllowedOrigin::try_from(text.clone());
        let expected = format!("`{text}` is not an origin: {reason}");
        prop_assert!(
            result.as_ref().is_err_and(|error| error.to_string() == expected),
            "got {result:?}, expected {expected}"
        );
    }
}
