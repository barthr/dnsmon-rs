use pnet::datalink;

#[derive(Debug)]
pub struct NetInterface {
    pub index: u32,
    pub name: String,
}

impl NetInterface {
    pub fn from_name(name: &str) -> Option<Self> {
        datalink::interfaces()
            .iter()
            .find(|iface| iface.name == name)
            .map(|iface| NetInterface {
                index: iface.index,
                name: iface.name.to_string(),
            })
    }
}
