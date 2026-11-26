// SPDX-License-Identifier: LGPL-2.1-or-later
//! Which network `GetNetwork` names, a pure function of Connman's `GetServices` answer.

use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// Connman's `GetServices` answer: services in Connman's order, the default route first.
pub type Services = Vec<(OwnedObjectPath, HashMap<String, OwnedValue>)>;

/// No connected service.
pub const NONE: &str = "none";
/// Connman cannot be asked.
pub const UNKNOWN: &str = "unknown";

fn text(props: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    props.get(key).and_then(|v| String::try_from(v.clone()).ok())
}

/// The name of a service type.
#[must_use]
pub fn kind_of(service_type: &str) -> &'static str {
    match service_type {
        "wifi" => "wifi",
        "ethernet" => "ethernet",
        "cellular" => "mobile",
        _ => "other",
    }
}

/// The kind of the first connected service (`ready` or `online`), else [`NONE`].
#[must_use]
pub fn network(services: &Services) -> &'static str {
    services
        .iter()
        .map(|(_, props)| props)
        .find(|props| matches!(text(props, "State").as_deref(), Some("ready" | "online")))
        .map_or(NONE, |props| kind_of(&text(props, "Type").unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Value;

    fn service(path: &str, kind: &str, state: &str) -> (OwnedObjectPath, HashMap<String, OwnedValue>) {
        let props = HashMap::from([
            ("Type".to_owned(), OwnedValue::try_from(Value::from(kind)).unwrap()),
            ("State".to_owned(), OwnedValue::try_from(Value::from(state)).unwrap()),
        ]);
        (OwnedObjectPath::try_from(path).unwrap(), props)
    }

    #[test]
    fn the_first_connected_service_names_the_network() {
        let services = vec![
            service("/net/connman/service/wifi_a", "wifi", "idle"),
            service("/net/connman/service/cellular_b", "cellular", "online"),
            service("/net/connman/service/wifi_c", "wifi", "ready"),
        ];
        assert_eq!(network(&services), "mobile");
        let services = vec![
            service("/net/connman/service/wifi_c", "wifi", "ready"),
            service("/net/connman/service/cellular_b", "cellular", "online"),
        ];
        assert_eq!(network(&services), "wifi");
    }

    #[test]
    fn without_a_connected_service_there_is_none() {
        assert_eq!(network(&Vec::new()), NONE);
        let services = vec![
            service("/net/connman/service/wifi_a", "wifi", "failure"),
            service("/net/connman/service/wifi_b", "wifi", "association"),
            service("/net/connman/service/wifi_c", "wifi", "configuration"),
            service("/net/connman/service/wifi_d", "wifi", "disconnect"),
        ];
        assert_eq!(network(&services), NONE);
        let (path, mut props) = service("/net/connman/service/x", "wifi", "online");
        props.remove("State");
        assert_eq!(network(&vec![(path, props)]), NONE, "a service without a state is not connected");
    }

    #[test]
    fn service_types_map_to_the_protocol_words() {
        assert_eq!(
            ["wifi", "ethernet", "cellular", "bluetooth", "gadget", "vpn", ""].map(kind_of),
            ["wifi", "ethernet", "mobile", "other", "other", "other", "other"]
        );
        let (path, mut props) = service("/net/connman/service/x", "wifi", "online");
        props.insert("Type".to_owned(), OwnedValue::from(7u32));
        assert_eq!(network(&vec![(path, props)]), "other", "a type that is no string");
    }
}
